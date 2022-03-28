//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
// with testcases only from a subset of the total corpus.

use crate::{
    bolts::{rands::Rand, serdeany::SerdeAny, AsSlice, HasRefCnt},
    corpus::{Corpus, CorpusScheduler, Testcase, IsFavoredMetadata},
    feedbacks::MapIndexesMetadata,
    inputs::{HasBytesVec, Input},
    state::{HasCorpus, HasMetadata, HasRand, HasMaxSize},
    Error,
};

use core::marker::PhantomData;

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

/// Default probability to skip the non-favored values
pub const DEFAULT_SKIP_NON_FAVORED_PROB: u64 = 95;

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
    /// ...
    pub hit: BTreeMap<usize, usize>,
    /// parent for depth estimation
    parent: usize,
}
crate::impl_serdeany!(RotatorsMetadata);

impl RotatorsMetadata {
    /// Creates a new [`struct@RotatorsMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
            hit: BTreeMap::default(),
            parent : 0,
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
    S: HasCorpus<I> + HasMetadata + HasMaxSize,
{
    base: CS,
    // hitcount is ok to have per fuzzing instance, no need to share
    skip_non_favored_prob: u64,
    phantom: PhantomData<(I, M, S)>,
}

impl<CS, I, M, S> CorpusScheduler<I, S> for RotatingCorpusScheduler<CS, I, M, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input + HasBytesVec,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand + HasMaxSize,
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

        let idx = loop {
            let idx = self.base.next(state)?;

            if state // keep corpus minimal w.r.t to active coverage set
                .metadata()
                .get::<RotatorsMetadata>().unwrap()
                .map
                .values()
                .find(|&info| idx == info.idx)
                .is_none() 
            { 
                state.corpus_mut().remove(idx).unwrap_or_default(); 
                continue
            }
            
            if state
                .corpus()
                .get(idx)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>()
            { break idx }

            if state.rand_mut().below(100) > self.skip_non_favored_prob {
                break idx
            }
        };

        state
            .metadata_mut()
            .get_mut::<RotatorsMetadata>().unwrap()
            .parent = idx; // keep corpus minimal w.r.t to active coverage set
println!("--------------> choosen one : #{idx} priority ? {:?}", 
   state.corpus().get(idx)?.borrow().has_metadata::<IsFavoredMetadata>());
        Ok(idx)
    }
}

impl<CS, I, M, S> RotatingCorpusScheduler<CS, I, M, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input + HasBytesVec,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand + HasMaxSize,
{
    /// Update the `Corpus` score using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata().get::<RotatorsMetadata>().is_none() {
            state.add_metadata(RotatorsMetadata::new());
        }
// idx is not unique identifier once we remove from ondisk, but hash should be
        let cid = get_cid(state, idx);
// ok lets query metadata aka coverage edge indicies
        let meta = state 
            .corpus()
            .get(idx).unwrap()
            .borrow()
            .metadata()
            .get::<M>().unwrap()
            .as_slice()
            .to_vec();

        let mut none_or_overfuzzed: Option<bool> = None;

        let (parent, (dropouts, novels)): (usize, (Vec<(usize, Option<bool>)>, _)) = {
            let rotator = &mut state
                    .metadata_mut()
                    .get_mut::<RotatorsMetadata>().unwrap();
            (rotator.parent, meta
                .iter()
// for base hitcounts
                .inspect(|&elem| {
                    if !rotator.hit.contains_key(elem) {
                        rotator.hit.insert(elem.clone(), 0);
                    }
                    // count *global* edge hitcount
                    *rotator.hit.get_mut(elem).unwrap() += 1
                })
// separate novels from potential cadidates for rotation
                .map(|elem| if let Some(ref mut info) = rotator
                        .map
                        .get_mut(elem)
                    {
                        info.counter += 1; // count *current input* edge hitcount
                        if idx == info.idx && !none_or_overfuzzed.unwrap_or(false) {
                            none_or_overfuzzed.replace(info.counter > 66);
                        } // prohibit to self-remmove
                        (elem.clone(), Some(info.counter > 0x42))
                    } else { (elem.clone(), None) })
                .partition(|(_, info)| info.is_some()))
        };

        let mut new_favoreds = vec![];

        dropouts
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
                    assert!(old_meta.refcnt() >= 1);
                    *old_meta.refcnt_mut() -= 1;
                    0 == old_meta.refcnt()
                } else { false })
            .map(|info| info.idx)
            // avoid removing parent at recursive banana stacked fuzzing
            .filter(|&idx| idx != parent)
            .collect::<Vec<usize>>()
            .iter()
            .for_each(|&old_idx| {
                state.corpus_mut().replace(idx, Testcase::<I>::default()).unwrap();
                state.corpus_mut().remove(old_idx).unwrap();
            });
// one problem with depth + powersched + bananafzz :
//   - it will not count depth when stacking inputs
//   - as depth is calculated from parent
//   - but actually, stacked fuzzing imply that new input this way is no hard to get
//     + aka without little change without feeedback needed
//   - more like siblings / cousins, not like offsprings
//   - therefore depth to stay still in recursive stacking of input, w/o feedback, is ..
//     very OKish .. i think :)

// if nothing to contribute ( nove, or exchange in rotation ) then signal to remove from corpus
        if none_or_overfuzzed.unwrap_or(true) && new_favoreds.is_empty() && novels.is_empty() {
            return state.corpus_mut().remove(idx).map(|_| ())
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
                let counter = self.base_hitcount(state, elem);
                state
                    .metadata_mut()
                    .get_mut::<RotatorsMetadata>().unwrap()
                    .map
                    .insert(elem, RotationMeta{
                        idx: idx, 
                        counter: counter,
                        cid: cid, 
                        elem: elem });
            });
        return Ok(())
    }

    /// Cull the `Corpus` using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let max = state.max_size() as u64;
        let seed = state.rand_mut().below(max) as usize;

        let top_rated = if let Some(tops) = state.metadata().get::<RotatorsMetadata>() 
            { tops } else { return Ok(()) };

        let hit = &state
            .metadata()
            .get::<RotatorsMetadata>().unwrap()
            .hit;
        let avg = hit.values().sum::<usize>() / hit.len();

        if avg < 0x42 {
            return Ok(())
        }

        let mut n_favored = 0;
        let low_fuzzing_temperature = top_rated.map
            .values()
            .inspect(|&info| if state
                .corpus()
                .get(info.idx).unwrap()
                .borrow_mut()
                .has_metadata::<IsFavoredMetadata>() 
            { n_favored += 1 })
            .filter(|&info| hit[&info.elem] < avg)
            .map(|ref info| info.cid)
            .collect::<HashSet<u64>>();
        // keep it balanced
        let (cold, hot) = top_rated.map
            .values()
            .partition::<Vec<&RotationMeta>, _>(
                |&info| low_fuzzing_temperature.contains(&info.cid));

        for info in hot {
            let mut entry = state.corpus().get(info.idx)?.borrow_mut();
            if !entry.has_metadata::<IsFavoredMetadata>() {
                continue
            }
            entry.metadata_mut().remove::<IsFavoredMetadata>().unwrap();
            assert!(!entry.has_metadata::<IsFavoredMetadata>());
        }

        let total = cold.len();
        if 0 == total {
            return Ok(())
        }

        const FACTOR: usize = 2;
        // here we choosing ratio in one fuzzing round ( loop over fuzzing queue ) : 
        //                    |FACTOR * favored| : |others|
        // as (100 - skip_non_favored_prob) will do it 1:1 ( even if favored are 1000x less )
        let spearhead_weight = FACTOR * (100 - self.skip_non_favored_prob as usize);
        let n_hotest = 1 + total * spearhead_weight / 100;
        if n_favored > n_hotest {
            return Ok(())
        }

        // spearhead to go breaktrough, avoid too much wide search
        for info in cold
            .iter()
            .cycle()
            .skip(seed % total)
            .step_by(1 + total / n_hotest)
            .enumerate()
            .take_while(|&(i, _)| i < n_hotest)
            .map(|(_, &info)| info)
        {
            let mut entry = state.corpus().get(info.idx)?.borrow_mut();
            if entry.has_metadata::<IsFavoredMetadata>() {
                continue
            }
            entry.add_metadata(IsFavoredMetadata {});
        }

        Ok(())
    }

    /// hitcount based probability
    #[allow(clippy::unused_self)]
    pub fn base_hitcount(&self, state: &mut S, ind: usize) -> usize {
        let hit = &state
            .metadata()
            .get::<RotatorsMetadata>().unwrap()
            .hit;

        if hit[&ind] < 66 {
            return 0x42
        }

        let max = hit.values().max().unwrap().clone() as f64;
        let sum = hit.values().sum::<usize>() as f64;

        let max_prob = max * 100.0 / sum;
        let ind_prob = hit[&ind] as f64 * 100.0 / sum;

        let prob = 1.0 - ind_prob / max_prob;

        66 - (24 + state.rand_mut().below((prob * (0x42 - 24) as f64) as u64) as usize)
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
