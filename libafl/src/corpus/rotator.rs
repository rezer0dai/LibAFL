//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
// with testcases only from a subset of the total corpus.

use crate::{
    bolts::{rands::Rand, serdeany::SerdeAny, AsSlice, HasRefCnt},
    corpus::{Corpus, CorpusScheduler, Testcase, IsFavoredMetadata},
    feedbacks::MapIndexesMetadata,
    inputs::{HasBytesVec, Input},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

use core::marker::PhantomData;

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// Default probability to skip the non-favored values
pub const DEFAULT_SKIP_NON_FAVORED_PROB: u64 = 95;

crate::impl_serdeany!(DropoutsMetadata);

/// integral structure for rotating of inputs
#[derive(Debug, Serialize, Deserialize)]
pub struct DropoutsMetadata {
    /// ...
    pub list: Vec<(usize, usize)>,
}

/// integral structure for rotating of inputs
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationMeta {
    idx: usize,
    counter: usize,
}

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
pub struct TopRatedsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, RotationMeta>,
}

crate::impl_serdeany!(TopRatedsMetadata);

impl TopRatedsMetadata {
    /// Creates a new [`struct@TopRatedsMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

impl Default for TopRatedsMetadata {
    fn default() -> Self {
        Self::new()
    }
}


/// The [`RotatingCorpusScheduler`] employs a genetic algorithm to compute a subset of the
/// corpus that exercise all the requested features (e.g. all the coverage seen so far)
/// prioritizing [`Testcase`]`s` using [`FavFactor`]
#[derive(Debug, Clone)]
pub struct RotatingCorpusScheduler<CS, I, M, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata,
{
    base: CS,
    skip_non_favored_prob: u64,
    phantom: PhantomData<(I, M, S)>,
}

impl<CS, I, M, S> CorpusScheduler<I, S> for RotatingCorpusScheduler<CS, I, M, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input + HasBytesVec,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        self.update_score(state, idx)?;
        self.base.on_add(state, idx)
    }

    /// Replaces the testcase at the given idx
    fn on_replace(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error> {
        self.base.on_replace(state, idx, testcase)
    }

    /// Removes an entry from the corpus, returning M if M was present.
    fn on_remove(
        &self,
        state: &mut S,
        idx: usize,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, idx, testcase)
    }

    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        self.cull(state)?;
        let mut idx = self.base.next(state)?;
        while {
            let has = !state
                .corpus()
                .get(idx)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>();
            has
        } && state.rand_mut().below(100) < self.skip_non_favored_prob
        {
            idx = self.base.next(state)?;
        }
        Ok(idx)
    }
}

impl<CS, I, M, S> RotatingCorpusScheduler<CS, I, M, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input + HasBytesVec,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Update the `Corpus` score using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        if state.metadata().get::<DropoutsMetadata>().is_none() {
            state.add_metadata(DropoutsMetadata { list : vec![] });
        }

        // ok lets query metadata aka coverage edge indicies
        let meta = state
            .corpus()
            .get(idx)?
            .borrow()
            .metadata()
            .get::<M>().ok_or_else(|| {
                Error::KeyNotFound(format!(
                    "Metadata needed for RotatingCorpusScheduler not found in testcase #{}",
                    idx
                ))
            })?
            .as_slice()
            .to_vec();


        let cid = get_cid(state, idx);

        let mut visited = HashSet::new();

        let mut new_favoreds = vec![];

        let to_drop = meta
            .iter()
            .filter(|&elem| if let Some(ref mut info) = state
                    .metadata_mut()
                    .get_mut::<TopRatedsMetadata>()
                    .unwrap()
                    .map
                    .get_mut(elem) 
                {
                    if !visited.contains(&info.idx) {
                        info.counter += 1
                    }
                    visited.insert(info.idx);
                    info.counter > 0x42
                } else { 
                    new_favoreds.push(*elem);
                    false 
                })
// we need to to chain it like this, as at first we want to update TopRatedsMetadata
// by info.counters...
            .map(|elem| *elem)
            .collect::<Vec<usize>>()
            .iter()
//now we are back ... to continue to work with updated TopRatedsMetadata
            .map(|&elem| (elem, state
                    .metadata()
                    .get::<TopRatedsMetadata>()
                    .unwrap()
                    .map
                    .get(&elem)
                    .unwrap()
                    .idx))
            .filter(|&(_, old_idx)| get_cid(state, old_idx) != cid) // avoid self pointers
            .filter(|&(elem, old_idx)| {
                assert!(idx != old_idx);
                new_favoreds.push(elem); // ok here we collect ones which is ok to ROTATE
                0 == state // and collect all whose are fully expandalble 
                    .corpus()
                    .get(old_idx).unwrap()
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<M>().unwrap()
                    .refcnt_mut()
                    .checked_sub(1)
                    .unwrap() // we want panic here if below 0!
                //drop(old.metadata_mut().remove::<M>());
                //println!("DROP: {elem}::{:?} + REPLACE", old.filename());
            })
            .map(|(_, old_idx)| (old_idx, idx))
            .collect::<Vec<(usize, usize)>>();

        if new_favoreds.is_empty() {
            println!("DROPING INPUT!! -> we got better : {:?}", meta.len());
            return Err(Error::KeyNotFound(format!("droping un-interesting input")))
        }

        state
            .corpus()
            .get(idx).unwrap()
            .borrow_mut()
            .metadata_mut()
            .get_mut::<M>().unwrap()
            .refcnt_mut()
            .checked_add(new_favoreds.len() as isize)
            .ok_or_else(|| 
                Error::KeyNotFound(format!("droping T00 MUCHO interesting input"))
            )?;

        state // every new stuff will get time to shine
            .corpus()
            .get(idx).unwrap()
            .borrow_mut()
            .add_metadata(IsFavoredMetadata {});

        for elem in new_favoreds {
            state
                .metadata_mut()
                .get_mut::<TopRatedsMetadata>()
                .unwrap()
                .map
                .insert(elem, RotationMeta{ idx: idx, counter: 0 });
        }

        state
            .metadata_mut()
            .get_mut::<DropoutsMetadata>()
            .unwrap()
            .list
            .extend_from_slice(&to_drop);

        return Ok(())
    }

    /// Cull the `Corpus` using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let top_rated = if let Some(tops) = state.metadata().get::<TopRatedsMetadata>() 
            { tops } else { return Ok(()) };

        for &idx in top_rated.map
            .values()
            .filter(|&info| info.counter > 66)
            .map(|ref info| (get_cid(state, info.idx), info.idx))
            .collect::<HashMap<u64, usize>>()
            .values()
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();

            assert!(entry.metadata().get::<M>().is_some(),
                //by definition meta is there until last reference is droped
                //otherwise any reference to some original which must have meta!!
                //also we dont drop meta manually!! - but should not matter anyway
                "ENTRY MUST HAVE EDGE INFO, as those should be droped only at dtor");

            if !entry.has_metadata::<IsFavoredMetadata>() {
                continue
            }
            
            drop(// ok here i just follow pattern, not sure why need do explicitelly drop ?
                entry.metadata_mut().remove::<IsFavoredMetadata>()
            );
        }

        Ok(())
    }

    /// Creates a new [`RotatingCorpusScheduler`] that wraps a `base` [`CorpusScheduler`]
    /// and has a default probability to skip non-faved [`Testcase`]s of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    pub fn new(base: CS) -> Self {
        Self {
            base,
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`RotatingCorpusScheduler`] that wraps a `base` [`CorpusScheduler`]
    /// and has a non-default probability to skip non-faved [`Testcase`]s using (`skip_non_favored_prob`).
    pub fn with_skip_prob(base: CS, skip_non_favored_prob: u64) -> Self {
        Self {
            base,
            skip_non_favored_prob,
            phantom: PhantomData,
        }
    }
}

/// lets try to use it
pub type IndexesRotatingCorpusScheduler<CS, I, S> =
    RotatingCorpusScheduler<CS, I, MapIndexesMetadata, S>;

use ahash::AHasher;
use core::hash::Hasher;
fn hash(bytes: &[u8]) -> u64 {
    let mut hasher = AHasher::new_with_keys(0, 0);
    hasher.write(bytes);
    hasher.finish()
}
fn get_cid<I, S>(state: &S, idx: usize) -> u64 
where
    I: Input + HasBytesVec,
    S: HasCorpus<I>,
{
    if let Some(input) = state
        .corpus()
        .get(idx).unwrap()
        .borrow()
        .input() 
    { hash(input.bytes()) } else { 0 }
}
