//! The ondisk corpus stores unused testcases to disk.

use alloc::vec::Vec;
use core::{cell::RefCell, time::Duration};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};



#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write};

use crate::{
    bolts::serdeany::SerdeAnyMap, corpus::Corpus, corpus::Testcase, inputs::Input,
    bolts::rands::{Rand, StdRand},
    state::HasMetadata, Error,
};

use hashbrown::{HashSet, HashMap};

/// Options for the the format of the on-disk metadata
#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnDiskMetadataFormat {
    /// A binary-encoded postcard
    Postcard,
    /// JSON
    Json,
    /// JSON formatted for readability
    JsonPretty,
}

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Debug, Serialize)]
pub struct OnDiskMetadata<'a> {
    metadata: &'a SerdeAnyMap,
    exec_time: &'a Option<Duration>,
    executions: &'a usize,
}

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OnDiskCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
    current: Option<usize>,
    dir_path: PathBuf,
    meta_format: Option<OnDiskMetadataFormat>,

    rand: StdRand,
    hotest: usize,
    redirect: HashMap<usize, usize>,
}

impl<I> Corpus<I> for OnDiskCorpus<I>
where
    I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, mut testcase: Testcase<I>) -> Result<usize, Error> {
        if testcase.filename().is_none() {
            // TODO walk entry metadata to ask for pieces of filename (e.g. :havoc in AFL)
            let file_orig = testcase
                .input()
                .as_ref()
                .unwrap()
                .generate_name(self.entries.len());
            let mut file = file_orig.clone();

            let mut ctr = 2;
            let filename = loop {
                let lockfile = format!("{}.lafl_lock", file);
                // try to create lockfile.

                if OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.dir_path.join(lockfile))
                    .is_ok()
                {
                    break self.dir_path.join(file);
                }

                file = format!("{}-{}", &file_orig, ctr);
                ctr += 1;
            };

            let filename_str = filename.to_str().expect("Invalid Path");
            testcase.set_filename(filename_str.into());
        };
        if self.meta_format.is_some() {
            let mut filename = PathBuf::from(testcase.filename().as_ref().unwrap());
            filename.set_file_name(format!(
                ".{}.metadata",
                filename.file_name().unwrap().to_string_lossy()
            ));
            let mut tmpfile_name = PathBuf::from(&filename);
            tmpfile_name.set_file_name(format!(
                ".{}.tmp",
                tmpfile_name.file_name().unwrap().to_string_lossy()
            ));

            let ondisk_meta = OnDiskMetadata {
                metadata: testcase.metadata(),
                exec_time: testcase.exec_time(),
                executions: testcase.executions(),
            };

            let mut tmpfile = File::create(&tmpfile_name)?;

            let serialized = match self.meta_format.as_ref().unwrap() {
                OnDiskMetadataFormat::Postcard => postcard::to_allocvec(&ondisk_meta)?,
                OnDiskMetadataFormat::Json => serde_json::to_vec(&ondisk_meta)?,
                OnDiskMetadataFormat::JsonPretty => serde_json::to_vec_pretty(&ondisk_meta)?,
            };
            tmpfile.write_all(&serialized)?;
            fs::rename(&tmpfile_name, &filename)?;
        }
        testcase
            .store_input()
            .expect("Could not save testcase to disk");

        self.hotest = self.place_to_list(testcase);
        Ok(self.hotest)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        if idx >= self.entries.len() {
            return Err(Error::KeyNotFound(format!("Index {} out of bounds", idx)));
        }

        //this hacked version will replace, if needed, entries[idx] with
        //its real input, so redirect[idx] = 0
        let dest = self.dest(idx);

        if testcase.input().is_some() {
            // seems somebody wants to do really replace, OK go for it
            self.entries[dest].replace(testcase);
            // though we will keep the hotest
        } else {
            // ok request to just update at idx position with original
            self.update_head_at(idx, dest, testcase)
        }
        self.hotest = idx;
        return Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        if idx >= self.entries.len() {
            return Ok(None)
        }

        let testcase = Testcase::<I>::default();
        self.prepare_drop(idx);
        self.update_hotest(idx);

        self.redirect.insert(idx, self.hotest);
        let entry = self.entries[idx].replace(testcase);
        if let Some(ref path) = entry.filename() {
            fs::remove_file(path)?;
            fs::remove_file(format!("{}.lafl_lock", path))?;
        }
        Ok(Some(entry))
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        Ok(&self.entries[self.dest(idx % self.entries.len())])
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<usize> {
        &self.current
    }

    /// Current testcase scheduled (mut)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        &mut self.current
    }
}

impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`OnDiskCorpus`].
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        fn new<I: Input>(dir_path: PathBuf) -> Result<OnDiskCorpus<I>, Error> {
            fs::create_dir_all(&dir_path)?;
            Ok(OnDiskCorpus {
                entries: vec![],
                current: None,
                dir_path,
                meta_format: None,
                rand: StdRand::with_seed(0x42),
                hotest: 0,
                redirect: HashMap::new(),
            })
        }
        new(dir_path.as_ref().to_path_buf())
    }

    /// Creates the [`OnDiskCorpus`] specifying the type of `Metadata` to be saved to disk.
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new_save_meta(
        dir_path: PathBuf,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error> {
        fs::create_dir_all(&dir_path)?;
        Ok(Self {
            entries: vec![],
            current: None,
            dir_path,
            meta_format,
            rand: StdRand::with_seed(66),
            hotest: 0,
            redirect: HashMap::new(),
        })
    }

    fn dest(&self, idx: usize) -> usize {
        if self.redirect.contains_key(&idx) {
            return self.dest(self.redirect[&idx])
        }
        idx
    }

    fn update_head_at(
        &mut self, 
        idx: usize, 
        dest: usize, 
        testcase: Testcase<I>) 
    {
        if dest == idx {
            return
        }

        self.redirect.insert(dest, idx);
        let entry = self.entries[dest].replace(testcase);

        self.redirect.remove(&idx);
        self.entries[idx].replace(entry);
    }

    fn update_hotest(&mut self, idx: usize) {
        if idx != self.hotest // its not itself as we are removing
            && !self.redirect.contains_key(&self.hotest) // need to be real stuff
        { return }
// if no original entry insde we have bigger problem than choose assertion
// and we want to boils up panic! here
        self.hotest = self.rand.choose(
            (0..self.entries.len())
                .filter(|i| !self.redirect.contains_key(&i))
                .filter(|&i| idx != i)
                .collect::<Vec<usize>>());
    }

    fn prepare_drop(&mut self, dest: usize) {
        if self.dest(dest) != dest {
            return
        }
        let nodes = (0..self.entries.len())
            .filter(|i| self.redirect.contains_key(i))//only refs
            .filter(|&i| self.dest(i) == dest)//pointing to dest
            .collect::<Vec<usize>>();
        if 0 == nodes.len() { // nobody using it as reference
            return // therefore removing original is OK
        }
// make sure that we delete final node at very end!!
        let idx = self.rand.choose(nodes);//choose

        assert!(idx != dest);// should be clear as the sky

        self.update_head_at(
            idx, dest, Testcase::<I>::default());
    }

    fn place_to_list(&mut self, testcase: Testcase<I>) -> usize {
        if self.redirect.is_empty() {
            self.append(testcase)
        } else {
            self.zombiefy(testcase)
        }
    }

    fn append(&mut self, testcase: Testcase<I>) -> usize {
        self.entries.push(RefCell::new(testcase));
        self.entries.len() - 1
    }

    fn zombiefy(&mut self, testcase: Testcase<I>) -> usize {
        let values = self.redirect
            .values()
            .copied()
            .collect::<HashSet<usize>>();
// ok we will need to choose leaf node, from reversed tree
        let idx = self.rand.choose(
            self.redirect
                .keys()
                .copied()
                .collect::<HashSet<usize>>()
                .difference(&values)
                .collect::<Vec<&usize>>()).clone();
            /*
        let idx = loop {
            let idx = *self.rand.choose(self.redirect.keys());
            if !self.redirect.values().contains(idx) {
                break idx
            }
        }
        assert!(!self.redirect.values().copied().collect::<Vec<usize>>().contains(&idx));
            */
        self.redirect.remove(&idx);
        self.entries[idx].replace(testcase);
        idx
    }
}
