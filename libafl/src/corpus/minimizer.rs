//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
// with testcases only from a subset of the total corpus.

use crate::{
    bolts::serdeany::SerdeAny,
    corpus::{Corpus, CorpusScheduler, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::{HasLen, Input},
    state::{HasCorpus, HasMetadata, HasRand},
    utils::{AsSlice, Rand},
    Error,
};

use core::marker::PhantomData;
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

pub const DEFAULT_SKIP_NOT_FAV_PROB: u64 = 95;

/// A testcase metadata saying if a testcase is favored
#[derive(Serialize, Deserialize)]
pub struct IsFavoredMetadata {}

crate::impl_serdeany!(IsFavoredMetadata);

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Serialize, Deserialize)]
pub struct TopRatedsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, usize>,
}

crate::impl_serdeany!(TopRatedsMetadata);

impl TopRatedsMetadata {
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

/// Compute the favor factor of a testcase. Lower is better.
pub trait FavFactor<I>
where
    I: Input,
{
    fn compute(testcase: &mut Testcase<I>) -> Result<u64, Error>;
}

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
pub struct LenTimeMulFavFactor<I>
where
    I: Input + HasLen,
{
    phantom: PhantomData<I>,
}

impl<I> FavFactor<I> for LenTimeMulFavFactor<I>
where
    I: Input + HasLen,
{
    fn compute(entry: &mut Testcase<I>) -> Result<u64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as u64 * entry.cached_len()? as u64)
    }
}

/// The Minimizer scheduler employs a genetic algorithm to compute a subset of the
/// corpus that exercise all the requested features (e.g. all the coverage seen so far)
/// prioritizing testcases using FavFactor
pub struct MinimizerCorpusScheduler<C, CS, F, I, M, R, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    M: AsSlice<usize> + SerdeAny,
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
{
    base: CS,
    skip_not_fav_prob: u64,
    phantom: PhantomData<(C, F, I, M, R, S)>,
}

impl<C, CS, F, I, M, R, S> CorpusScheduler<I, S> for MinimizerCorpusScheduler<C, CS, F, I, M, R, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    M: AsSlice<usize> + SerdeAny,
    S: HasCorpus<C, I> + HasMetadata + HasRand<R>,
    C: Corpus<I>,
    R: Rand,
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
        } && state.rand_mut().below(100) < self.skip_not_fav_prob
        {
            idx = self.base.next(state)?;
        }
        Ok(idx)
    }
}

impl<C, CS, F, I, M, R, S> MinimizerCorpusScheduler<C, CS, F, I, M, R, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    M: AsSlice<usize> + SerdeAny,
    S: HasCorpus<C, I> + HasMetadata + HasRand<R>,
    C: Corpus<I>,
    R: Rand,
{
    /// Update the `Corpus` score using the `MinimizerCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();
            let factor = F::compute(&mut *entry)?;
            let meta = entry.metadata().get::<M>().ok_or_else(|| {
                Error::KeyNotFound(format!(
                    "Metadata needed for MinimizerCorpusScheduler not found in testcase #{}",
                    idx
                ))
            })?;
            for elem in meta.as_slice() {
                if let Some(old_idx) = state
                    .metadata()
                    .get::<TopRatedsMetadata>()
                    .unwrap()
                    .map
                    .get(elem)
                {
                    if factor > F::compute(&mut *state.corpus().get(*old_idx)?.borrow_mut())? {
                        continue;
                    }
                }

                new_favoreds.push((*elem, idx));
            }
        }

        for pair in new_favoreds {
            state
                .metadata_mut()
                .get_mut::<TopRatedsMetadata>()
                .unwrap()
                .map
                .insert(pair.0, pair.1);
        }
        Ok(())
    }

    /// Cull the `Corpus` using the `MinimizerCorpusScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let top_rated = match state.metadata().get::<TopRatedsMetadata>() {
            None => return Ok(()),
            Some(val) => val,
        };

        let mut acc = HashSet::new();

        for (key, idx) in &top_rated.map {
            if !acc.contains(key) {
                let mut entry = state.corpus().get(*idx)?.borrow_mut();
                let meta = entry.metadata().get::<M>().ok_or_else(|| {
                    Error::KeyNotFound(format!(
                        "Metadata needed for MinimizerCorpusScheduler not found in testcase #{}",
                        idx
                    ))
                })?;
                for elem in meta.as_slice() {
                    acc.insert(*elem);
                }

                entry.add_metadata(IsFavoredMetadata {});
            }
        }

        Ok(())
    }

    pub fn new(base: CS) -> Self {
        Self {
            base,
            skip_not_fav_prob: DEFAULT_SKIP_NOT_FAV_PROB,
            phantom: PhantomData,
        }
    }

    pub fn with_skip_prob(base: CS, skip_not_fav_prob: u64) -> Self {
        Self {
            base,
            skip_not_fav_prob,
            phantom: PhantomData,
        }
    }
}

/// A MinimizerCorpusScheduler with LenTimeMulFavFactor to prioritize quick and small testcases
pub type LenTimeMinimizerCorpusScheduler<C, CS, I, M, R, S> =
    MinimizerCorpusScheduler<C, CS, LenTimeMulFavFactor<I>, I, M, R, S>;

/// A MinimizerCorpusScheduler with LenTimeMulFavFactor to prioritize quick and small testcases
/// that exercise all the entries registered in the MapIndexesMetadata
pub type IndexesLenTimeMinimizerCorpusScheduler<C, CS, I, R, S> =
    MinimizerCorpusScheduler<C, CS, LenTimeMulFavFactor<I>, I, MapIndexesMetadata, R, S>;
