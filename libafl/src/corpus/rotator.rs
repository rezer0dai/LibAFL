//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer

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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RotationMeta {
    idx: usize,
    counter: usize,
    cid: u64,
    elem: usize,
    hitcount: usize,
}

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
pub struct RotatorsMetadata {
    /// map index -> corpus index
    map: HashMap<usize, RotationMeta>,
    /// ...
    hit: BTreeMap<usize, usize>,
    /// avoid situation that we place to map input and it will never repro again that edge
    cache: HashMap<usize, RotationMeta>,
    /// avoid situation that we place to map input and it will never repro again that edge
    minmax: HashMap<usize, RotationMeta>,
    /// parent for depth estimation
    parent: usize,
    /// how many next was called
    round: usize,
}
crate::impl_serdeany!(RotatorsMetadata);

impl RotatorsMetadata {
    /// Creates a new [`struct@RotatorsMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
            hit: BTreeMap::default(),
            cache: HashMap::default(),
            minmax: HashMap::default(),
            parent : 0,
            round : 0,
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
        self.update_score(state, idx);
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
        self.fix_map(state);
        self.cull(state);

        let round = state.metadata() // once a while do heat map focus
            .get::<RotatorsMetadata>().unwrap()
            .round; // we do equal fuzzing most of the time
        let ignore_favorites = 1 == round % (3 * 2 + 1); // TODO : (magic3 * 2 + 1) to the config
        if 0 != round % 3 { // TODO : magic3 to the config
            self.finish_selection(state) 
        }

        println!("\t\t =====> CURRENT ROUND#{round} minmax|{:?}|", 
                state.metadata()
                    .get::<RotatorsMetadata>().unwrap()
                    .minmax.len()
            );

        self.reset_counters(state);

        let idx = loop {
            let idx = self.base.next(state)?;

            if 0 == idx {
                state.metadata_mut()
                    .get_mut::<RotatorsMetadata>().unwrap()
                    .round += 1;
            }

            if ignore_favorites
                && state.metadata()
                    .get::<RotatorsMetadata>().unwrap()
                    .minmax
                    .values()
                    .find(|&minmax| minmax.idx == idx)
                    .is_some() 
            { break idx }

            if self.safe_remove(state, idx).is_ok() {
                continue
            }

            if state.corpus()
                .get(idx)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>()
            { break idx }

            if state.rand_mut().below(100) > self.skip_non_favored_prob {
                break idx 
            }
        };

        state.metadata_mut()
            .get_mut::<RotatorsMetadata>().unwrap()
            .parent = idx; // keep corpus minimal w.r.t to active coverage set

//        println!("--------------> choosen one : #{idx} priority ? {:?}", 
//           state.corpus().get(idx)?.borrow().has_metadata::<IsFavoredMetadata>());

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
    pub fn update_score(&self, state: &mut S, idx: usize) {
        // Create a new top rated meta if not existing
        if state.metadata().get::<RotatorsMetadata>().is_none() {
            state.add_metadata(RotatorsMetadata::new());
        }
// idx is not unique identifier once we remove from ondisk, but hash should be
        let cid = get_cid(state, idx);
// ok lets query metadata aka coverage edge indicies
        let meta = state.corpus()
            .get(idx).unwrap()
            .borrow()
            .metadata()
            .get::<M>().unwrap()
            .as_slice()
            .to_vec();

        let mut none_or_overfuzzed: Option<bool> = None;

        let (parent, (dropouts, novels)): (usize, (Vec<(usize, Option<bool>)>, _)) = {
            let rotator = &mut state.metadata_mut()
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
                .map(|elem| if let Some(ref mut info) = rotator.map
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

        let dropouts = dropouts
            .iter()
            // check if fuzzed enough cycles, if so then rotate
            .filter(|&(_, fuzzed_enough)| fuzzed_enough.unwrap())
            // adding corpus-idx of fuzzed enough target
            .map(|(elem, _)| state.metadata()
                    .get::<RotatorsMetadata>().unwrap()
                    .map
                    .get(&elem).unwrap())
            // avoid self pointers
            .filter(|info| info.cid != cid)
            // ok here we collect unique-ones which are ok to ROTATE
            .inspect(|info| new_favoreds.push((info.elem, None)))
            // and collect all whose are fully expandalble by now
            .filter(|info| if let Some(ref mut old_meta) = state.corpus()
                    .get(info.idx).unwrap().borrow_mut()
                    .metadata_mut().get_mut::<M>() 
                {
                    assert!(old_meta.refcnt() >= 1);
                    *old_meta.refcnt_mut() -= 1;
                    0 == old_meta.refcnt()
                } else { false })
            // avoid removing parent at recursive banana stacked fuzzing
            .filter(|info| info.idx != parent)
            .copied()
            .collect::<Vec<RotationMeta>>();

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
            return state.corpus_mut().remove(idx).map(|_| ()).unwrap()
        }

// keep count of inputs relevancy in fuzzing rotation
        *state.corpus()
            .get(idx).unwrap()
            .borrow_mut()
            .metadata_mut()
            .get_mut::<M>().unwrap()
            .refcnt_mut() += (new_favoreds.len() + novels.len()) as isize;
// if novel we want to favor it until given enough time
        if 0 != novels.len() {
            state.corpus() // every new stuff will get time to shine
                .get(idx).unwrap()
                .borrow_mut()
                .add_metadata(IsFavoredMetadata {});
        }
// register our top_rateds
        novels.iter().chain(new_favoreds.iter())
            .for_each(|&(elem, _)| {
                let (hitcount, counter) = self.base_hitcount(state, elem);
                state.metadata_mut()
                    .get_mut::<RotatorsMetadata>().unwrap()
                    .map
                    .insert(elem, RotationMeta {
                        idx: idx, 
                        counter: counter,
                        cid: cid, 
                        elem: elem,
                        hitcount : hitcount
                    });
            });

        // remove replaced ones
        for info in dropouts {
            let (old, old_info) = if let Some(old_info) = state.metadata_mut()
                .get_mut::<RotatorsMetadata>().unwrap()
                .cache
                .insert(info.elem, info)
            { // ok saved to cache, removing from corpus
                (self.safe_remove(state, old_info.idx), old_info)
            } else { continue }; // ola seems used by map still ?

            let mut testcase = if let Ok(Some(testcase)) = old {
                testcase // extracting corpus released data
            } else { continue }; // nope, data keeped still in corpus (refed by cache[other_idx] or minmax )

            if state.metadata()
                .get::<RotatorsMetadata>().unwrap()
                .minmax
                .values()
                .find(|&minmax| minmax.cid == old_info.cid)
                .is_some() 
            { continue } // need to have unique cid, we build minmax queue

            // put to corpus, without feedback to anybody
            *testcase.filename_mut() = None;
            let new_idx = if let Ok(new_idx) = state.corpus_mut().add(testcase) {
                 new_idx
            } else { continue }; // uh, not added inside corpus, good as dead this input

            state.metadata_mut()
                .get_mut::<RotatorsMetadata>().unwrap()
                .minmax // its ok to replace itself, but only for unique cid !!
                .insert(old_info.elem, RotationMeta {
                    idx: new_idx,
                    counter: old_info.counter,
                    cid: old_info.cid, 
                    elem: old_info.elem,
                    hitcount : old_info.hitcount
                });
        }
        // ok lets set idx to be choosen at most if taken reference-idx from corpora
        state.corpus_mut().replace(idx, Testcase::<I>::default()).unwrap();
    }

    /// Cull the `Corpus` using the `RotatingCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut S) {
        // no need to return error, as we require buffer store all of the past idx, just crossref
        // them, those must not errored at get anyway!
        let count = state.corpus().count() as u64;
        let seed = state.rand_mut().below(count) as usize;

        let top_rated = if let Some(tops) = state.metadata().get::<RotatorsMetadata>() 
            { tops } else { return };

        let hit = &state.metadata()
            .get::<RotatorsMetadata>().unwrap()
            .hit;
        let avg = hit.values().sum::<usize>() / hit.len();

        if avg < 0x42 {
            return
        }

        let mut n_favored = 0;
        let low_fuzzing_temperature = top_rated.map
            .values()
            .inspect(|&info| if state.corpus()
                .get(info.idx).unwrap()
                .borrow_mut()
                .has_metadata::<IsFavoredMetadata>() 
            { n_favored += 1 })
//            .inspect(|&info| assert!(info.cid == get_cid(state, info.idx)))
.inspect(|&info| println!("STATS : avg#{avg} |{info:?}| heat : {:?}", hit[&info.elem]))
            .filter(|&info| hit[&info.elem] < avg)
            .map(|ref info| info.cid)
            .collect::<HashSet<u64>>();
        // keep it balanced
        let (cold, hot) = top_rated.map
            .values()
            .partition::<Vec<&RotationMeta>, _>(
                |&info| low_fuzzing_temperature.contains(&info.cid));

println!("\t\t @@@@@@@@@@@@@ (favored#{n_favored} >>> colds#{:?} vs hots#{:?}", cold.len(), hot.len());
println!("\n *** uniques : {:?}\n", top_rated.map.values().map(|ref info| info.cid).collect::<HashSet<u64>>());

        for info in hot.iter() {
            let mut entry = state.corpus().get(info.idx).unwrap().borrow_mut();
            if !entry.has_metadata::<IsFavoredMetadata>() {
                continue
            }
            entry.metadata_mut().remove::<IsFavoredMetadata>().unwrap();
            assert!(!entry.has_metadata::<IsFavoredMetadata>());
        }

        const FACTOR: usize = 2; // TODO : magic2 to the config
        // here we choosing ratio in one fuzzing round ( loop over fuzzing queue ) : 
        //                    |FACTOR * favored| : |others|
        // as (100 - skip_non_favored_prob) will do it 1:1 ( even if favored are 1000x less )

        if 0 == cold.len() || cold.len() > FACTOR * hot.len() { // its too cold to choose fav
            return
        } // ok we can fuzz without prio as seems good ratio anyway


        // spearhead to go breaktrough, avoid too much wide search
        let spearhead_weight = FACTOR * (100 - self.skip_non_favored_prob as usize);
        let n_hotest = 1 + hot.len() * spearhead_weight / 100;
        let mut favored = HashSet::new();
        for info in cold
            .iter()
            .cycle()
            .skip(seed % cold.len())
            .take(n_hotest)
        {
            if favored.contains(&info.cid) {
// ok we counting only new stuffs
// otherwise is possible we only get 1 input favored
// as that input may prevails most of the cold queue ...
                continue
            }
            favored.insert(info.cid);
            let mut entry = state.corpus().get(info.idx).unwrap().borrow_mut();
            if entry.has_metadata::<IsFavoredMetadata>() {
                continue
            }
            entry.add_metadata(IsFavoredMetadata {});
        }
println!("\t\t======>> OK need few more hot #{n_hotest} to the party!! and we got #{:?}", favored.len());
    }

    /// hitcount based probability
    #[allow(clippy::unused_self)]
    fn base_hitcount(&self, state: &mut S, ind: usize) -> (usize, usize) {
        let hit = &state
            .metadata()
            .get::<RotatorsMetadata>().unwrap()
            .hit;

        if hit[&ind] < 66 {
            return (hit[&ind], 0x42)
        }

        let max = hit.values().max().unwrap().clone() as f64;
        let sum = hit.values().sum::<usize>() as f64;

        let max_prob = max * 100.0 / sum;
        let ind_prob = hit[&ind] as f64 * 100.0 / sum;

        let prob = 1.0 - ind_prob / max_prob;

        (
            hit[&ind], 
            66 - (24 + state.rand_mut().below((prob * (0x42 - 24) as f64) as u64) as usize)
        )
    }

    fn safe_remove(&self, state: &mut S, idx: usize) -> Result<Option<Testcase<I>>, ()> {
        let meta = if let Some(meta) = state.metadata().get::<RotatorsMetadata>() 
            { meta } else { return Err(()) };
// keep corpus minimal w.r.t to active coverage set
        if meta.map
            .values() // though these should be covered by metadata().refcnt() !+ 0
            .find(|&info| idx == info.idx)
            .is_some() 
        { return Err(()) }

        if meta.cache
            .values()
            .find(|&info| idx == info.idx)
            .is_some() 
        { return Ok(None) } // ok pretend to be remove but keep it ( skip in next )

        if meta.minmax
            .values()
            .find(|&info| idx == info.idx)
            .is_some() 
        { return Ok(None) } // ok pretend to be remove but keep it ( skip in next )

        Ok(state.corpus_mut().remove(idx).unwrap())
    }
    /// checking cache for failing of map replacement
    #[allow(clippy::unused_self)]
    fn fix_map(&self, state: &mut S) {
        for (old_idx, idx) in self.revived_edges(state) {
            if idx == old_idx {
                continue
            }

            *state.corpus()
                .get(idx).unwrap().borrow_mut()
                .metadata_mut().get_mut::<M>().unwrap()
                .refcnt_mut() += 1;
/*
// make it here to add as favorite, will it widen spearhead maybe too much to be effective ?
            state // as is questionable if we want to do it here
                .corpus() // or leave it fpr cull
                .get(idx).unwrap() // problem with cull is when too cold env
                .borrow_mut() // aka nothing going to be favored
                .add_metadata(IsFavoredMetadata {}); // so this can take quite time to uptake
*/
            let remove = if let Some(old_meta) = state.corpus()
                .get(old_idx).unwrap().borrow_mut()
                .metadata_mut().get_mut::<M>()
            {
                *old_meta.refcnt_mut() -= 1;
                0 == old_meta.refcnt()
            } else { panic!("not possible to dref metadata of latest entry ??") };

            if !remove {
                continue
            }

            state.corpus_mut().replace(idx, Testcase::<I>::default()).unwrap();
            drop( // ok seems nice way to handle unused warning
                self.safe_remove(state, old_idx).unwrap_or(None)
            );
        }
    }
    fn revived_edges(&self, state: &mut S) -> Vec<(usize, usize)> {
        let meta = if let Some(meta) = state.metadata_mut().get_mut::<RotatorsMetadata>() 
            { meta } else { return vec![] };

        let avg = meta.hit.values().sum::<usize>() / meta.hit.len();

        meta.map
            .values()
            .filter(|&info| meta.hit[&info.elem] > 66) // only those once replaced
            .filter(|&info| meta.hit[&info.elem] < avg / 2) // way below average
            .filter(|&info| meta.hit[&info.elem] < info.hitcount * 110 / 100) // seems frozen
            .filter(|&info| meta.cache.get(&info.elem).is_some())
            .copied() 
            .collect::<Vec<RotationMeta>>()
            .iter()
            .map(|&info| { let old_info = meta.cache.get(&info.elem).unwrap().clone();// load it back

                let info = meta
                    .map
                    .insert(info.elem, RotationMeta{
                        idx: old_info.idx,
                        counter: 1,
                        cid: old_info.cid, 
                        elem: old_info.elem,
                        hitcount : meta.hit[&info.elem],
                    }).unwrap();

println!("BACK TO THE FUTURE from #{info:?} instead of {:?}", old_info.idx);

                (info.idx, old_info.idx)
            })
            .collect()
    }

    /// Do finish selection tro cover full edge map
    #[allow(clippy::unused_self)]
    pub fn finish_selection(&self, state: &mut S) {
        let count = state.corpus().count();
        let seed = state.rand_mut().below(count as u64 - 1) as usize;

        let meta_map = if let Some(meta) = state.metadata().get::<RotatorsMetadata>() 
            { &meta.map } else { return };

        let acc = &mut meta_map
            .keys()
            .filter(|&elem| state.corpus()
                .get(elem.clone()).unwrap().borrow()
                .has_metadata::<IsFavoredMetadata>())
            .flat_map(|&elem| state.corpus()
                    .get(elem).unwrap().borrow()
                    .metadata()
                    .get::<M>().unwrap()
                    .as_slice()
                    .to_vec()
                )
            .collect::<HashSet<usize>>();

        for (key, info) in meta_map
            .iter()
            .cycle()
            .skip(seed % count)
            .take(count)
        {
            if acc.contains(key) {
                continue
            }

            let mut entry = state.corpus()
                .get(info.idx).unwrap().borrow_mut();

            entry.metadata()
                .get::<M>().unwrap()
                .as_slice()
                .iter()
                .for_each(|elem| { acc.insert(elem.clone()); });

            entry.add_metadata(IsFavoredMetadata {});
        }
println!("\n\t\t--> FAVORING : {:?}\n", acc.len());
    }

    /// reset hitcounts to not reflect past too muuch, to not overdo with new samples
    #[allow(clippy::unused_self)]
    pub fn reset_counters(&self, state: &mut S) {
        let meta = if let Some(meta) = state.metadata_mut().get_mut::<RotatorsMetadata>() 
            { meta } else { return };

        let avg = meta.hit.values().sum::<usize>() / meta.hit.len();

        if avg < 1000 {
            return
        }

        meta.map
            .iter_mut()
            .filter(|&(_, &mut info)| info.hitcount > 66)
            .for_each(|(_, mut info)| info.hitcount = 1 + 0x42);
        meta.hit
            .iter_mut()
            .filter(|&(_, &mut hitcount)| hitcount > 0x42)
            .for_each(|(_, hitcount)| *hitcount = 1 + 66);
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
