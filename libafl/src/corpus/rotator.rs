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

/// unique information per input drop
#[derive(Debug, Serialize, Deserialize)]
pub struct DropoutInfo {
    /// corpus idx of input do drop
    pub idx: usize,
    /// corpus idx of input to replace with
    pub tgt: usize,
    /// corpus id based on hash of input data for input to drop
    pub cid: u64,
}
/// integral structure for rotating of inputs
#[derive(Debug, Serialize, Deserialize)]
pub struct DropoutsMetadata {
    /// ...
    pub list: Vec<DropoutInfo>,
}
crate::impl_serdeany!(DropoutsMetadata);

/// integral structure for rotating of inputs
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationMeta {
    idx: usize,
    counter: usize,
    cid: u64,
    elem: usize,
}

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
pub struct RotatorsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, RotationMeta>,
}
crate::impl_serdeany!(RotatorsMetadata);

impl RotatorsMetadata {
    /// Creates a new [`struct@RotatorsMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

impl Default for RotatorsMetadata {
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
        self.base.on_add(state, idx)?;
        self.update_score(state, idx)
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
        if state.metadata().get::<RotatorsMetadata>().is_none() {
            state.add_metadata(RotatorsMetadata::new());
        }
        if state.metadata().get::<DropoutsMetadata>().is_none() {
            state.add_metadata(DropoutsMetadata { list : vec![] });
        }
// idx is not unique identifier once we remove from ondisk, but hash should be
        let cid = get_cid(state, idx);
// avoid favorizing replaying input which was deemed to drop but was not droped yet
        if state
            .metadata()
            .get::<DropoutsMetadata>()
            .unwrap()
            .list
            .iter()
            .filter(|&info| cid == info.cid)
            .nth(0) 
            .is_some()
        { // keep it from sadman's parade - spamming disk of doubles inputs
            return Err(
                Error::KeyNotFound(format!("Input waiting to drop")))
        }

// ok lets query metadata aka coverage edge indicies
        let meta = state 
            .corpus()
            .get(idx).unwrap()
            .borrow()
            .metadata()
            .get::<M>().unwrap()
            .as_slice()
            .to_vec();

// separate novels from potential cadidates for rotation
        let (dropouts, novels): (Vec<(usize, Option<bool>)>, _) = meta
            .iter()
            .map(|elem| if let Some(ref mut info) = state
                    .metadata_mut()
                    .get_mut::<RotatorsMetadata>()
                    .unwrap()
                    .map
                    .get_mut(elem)
                {
                    info.counter += 1;
                    (elem.clone(), Some(info.counter > 0x42))
                } else { (elem.clone(), None) })
            .partition(|(_, info)| info.is_some());

        let mut new_favoreds = vec![];

        let mut dropouts = dropouts
            .iter()
            // check if fuzzed enough cycles, if so then rotate
            .filter(|&(_, fuzzed_enough)| fuzzed_enough.unwrap())
            // adding corpus-idx of fuzzed enough target
            .map(|(elem, _)| state
                    .metadata()
                    .get::<RotatorsMetadata>().unwrap()
                    .map
                    .get(&elem).unwrap())
            // avoid self pointers
            .filter(|info| info.cid != cid)
            // just in case input was cleared and we are not able to get hash anymore
            .inspect(|info| assert!(info.idx != idx))//.filter(|info| info.idx != idx)//
            // ok here we collect unique-ones which are ok to ROTATE
            .inspect(|info| new_favoreds.push((info.elem, None)))
            // and collect all whose are fully expandalble by now
            .filter(|info| if let Some(ref mut old_meta) = state 
                    .corpus()
                    .get(info.idx).unwrap()
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<M>() 
                {
                    *old_meta.refcnt_mut() -= 1;
                    assert!(old_meta.refcnt() >= 0);
                    0 == old_meta.refcnt()
                } else { false })
            .map(|info| DropoutInfo{ idx:info.idx, tgt:idx, cid:info.cid })
            .collect::<Vec<DropoutInfo>>();

// if nothing to contribute ( nove, or exchange in rotation ) then signal to remove from corpus
        if new_favoreds.is_empty() && novels.is_empty() {
            println!("DROPING INPUT!! -> we got better : {:?} <{:?}>", meta.len(),
                state.corpus().get(idx).unwrap().borrow().filename().as_ref().unwrap());
            return Err(
                Error::KeyNotFound(format!("DROPING: non-( or way T00 MUCHO) interesting input ({})",
                    state.corpus().get(idx).unwrap().borrow().filename().as_ref().unwrap())));
        }

// keep count of inputs relevancy in fuzzing rotation
        *state
            .corpus()
            .get(idx).unwrap()
            .borrow_mut()
            .metadata_mut()
            .get_mut::<M>().unwrap()
            .refcnt_mut() += (new_favoreds.len() + novels.len()) as isize;
// if novel we want to favor it until given enough time
        if 0 != novels.len() {
            state // every new stuff will get time to shine
                .corpus()
                .get(idx).unwrap()
                .borrow_mut()
                .add_metadata(IsFavoredMetadata {});
        }
// register our top_rateds
        novels.iter().chain(new_favoreds.iter())
            .for_each(|&(elem, _)| {
                state
                    .metadata_mut()
                    .get_mut::<RotatorsMetadata>().unwrap()
                    .map
                    .insert(elem, RotationMeta{ idx: idx, counter: 0, cid: cid, elem: elem });
            });
// register what to drop
        state
            .metadata_mut()
            .get_mut::<DropoutsMetadata>()
            .unwrap()
            .list
            .append(&mut dropouts);

        return Ok(())
    }

    /// Cull the `Corpus` using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let top_rated = if let Some(tops) = state.metadata().get::<RotatorsMetadata>() 
            { tops } else { return Ok(()) };

        let need_more = top_rated.map
            .values()
            .filter(|&info| info.counter < 66)
            .map(|ref info| info.cid)
            .collect::<HashSet<u64>>();

        for info in top_rated.map
            .values()
            .filter(|&info| !need_more.contains(&info.cid))
        {
            let mut entry = state.corpus().get(info.idx)?.borrow_mut();

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
    let mut testcase = state
        .corpus()
        .get(idx).unwrap()
        .borrow_mut();
    let (in_mem, bytes) = match testcase.load_input() {
        Ok(input) => (true, input.bytes().as_ref()),
        _ => (false, testcase // if in disk then banana modifications have been too
                .load_input().unwrap()
                .bytes().as_ref())
    };
    let hash = hash(bytes);
// NOTE :   i am not sure what is criterion on storing memory to file in LibAFL
//          therefore likely we dont need to store it, as once modified by BFL
//          it will be stored by default to disk
    if in_mem { // we want bananized input to store to file
        testcase.store_input().unwrap();
    }
    hash
}
