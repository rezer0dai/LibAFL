/// bananizing AFL data format to be able to fuzz effectively generative api based args

use crate::{
    bolts::{rands::Rand, tuples::Named},
    inputs::{HasBytesVec, Input},
    mutators::{MutationResult, Mutator, banana::BananaState, bananizer::get_calls_count},
    corpus::Corpus,
    state::{HasCorpus, HasRand},
    Error,
    libbfl::info::PocDataHeader,
};

use std::{rc::Rc, sync::RwLock};

use core::{
    mem::size_of,
    fmt::Debug,
};

/// Splice mutation for two diff banana inputs
/// - we skip banana cross-over, Splice could do that job
/// - also adding InsertBananasMutator
#[derive(Debug, Default)]
pub struct CrossoverBananasMutator {
    state: Rc<RwLock<BananaState>>,
}


impl<I, S> Mutator<I, S> for CrossoverBananasMutator
where
    I: Input + HasBytesVec,
    S: HasRand + HasCorpus<I>,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if size_of::<PocDataHeader>() == input.bytes().len() {
            return Ok(MutationResult::Skipped)
        }

        let poc_header = unsafe { 
            &::std::slice::from_raw_parts(
                input.bytes().as_ptr() as *const PocDataHeader, 1)[0] 
        }.clone();

        if !0 != poc_header.split_at {
            return Ok(MutationResult::Skipped)
        }

        if !self.state.read().unwrap().generate() {
            return Ok(MutationResult::Skipped)
        }
        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_bytes = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input()?;
            other.bytes().to_vec()
        };

        let mut banana_state = self.state.write().unwrap();
        let ind_a = banana_state.select_input_ind(stage_idx, state, input);

        let cc_b = get_calls_count(&other_bytes);
        if 1 == cc_b {
            return Ok(MutationResult::Skipped);
        }
        let ind_b = state.rand_mut().choose(0..cc_b - 1);

        unsafe { 
            let mut poc_a = &mut ::std::slice::from_raw_parts_mut(
                input.bytes_mut().as_ptr() as *mut PocDataHeader, 1)[0];

            poc_a.split_at = ind_a;
            let limit = if cc_b - ind_b > 10 { 10 } else { cc_b - ind_b - 1 };
            poc_a.split_cnt = state.rand_mut().choose(0..limit);

        }
        unsafe { 
            &mut ::std::slice::from_raw_parts_mut(
                other_bytes.as_ptr() as *mut PocDataHeader, 1)[0]
        }.split_at = ind_b;


//        let call_c = crossover::do_bananized_crossover(
//            input.bytes(), ind_a,
//            &other_bytes, ind_b,
//            state.rand_mut().choose(ind_b..cc_b));

        input
            .bytes_mut()
            .extend(other_bytes);

        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverBananasMutator {
    fn name(&self) -> &str {
        "CrossoverBananasMutator"
    }
}

impl CrossoverBananasMutator {
    /// Creates a new [`CrossoverBananasMutator`].
    #[must_use]
    pub fn new(state: Rc<RwLock<BananaState>>) -> Self {
        CrossoverBananasMutator {
            state: state,
        }
    }
}

#[derive(Debug, Default)]
pub struct SpliceBananasMutator {
    state: Rc<RwLock<BananaState>>,
}

impl<I, S> Mutator<I, S> for SpliceBananasMutator
where
    I: Input + HasBytesVec,
    S: HasRand + HasCorpus<I>,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if size_of::<PocDataHeader>() == input.bytes().len() {
            return Ok(MutationResult::Skipped)
        }
        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_bytes = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input()?;
            other.bytes().to_vec()
        };
        if size_of::<PocDataHeader>() == other_bytes.len() {
            return Ok(MutationResult::Skipped)
        }

        let mut banana_state = self.state.write().unwrap();

        let call_a = banana_state.select_input_call(stage_idx, state, input);
        if 0 == call_a.kin { // non-mutable call selected
            return Ok(MutationResult::Skipped);
        }

        let call_b = banana_state.select_kin_call(state, input, call_a.kin, &other_bytes);
        if call_a.kin != call_b.kin { // not-compatible call was selected
            return Ok(MutationResult::Skipped);
        }
        if call_a.size != call_b.size {
            return Ok(MutationResult::Skipped);
//            panic!("[BFL] in-compatible calls meet at splice, with same kin!! {:?} vs {:?}", call_a, call_b)
        }

        let split_at = state.rand_mut().choose(0..call_a.size);
        input
            .bytes_mut()[call_a.offset..][split_at..call_a.size]
            .clone_from_slice(
                &other_bytes[call_b.offset..][split_at..call_a.size]);

        Ok(MutationResult::Mutated)
    }
}

impl Named for SpliceBananasMutator {
    fn name(&self) -> &str {
        "SpliceBananasMutator"
    }
}

impl SpliceBananasMutator {
    /// Creates a new [`SpliceBananasMutator`].
    #[must_use]
    pub fn new(state: Rc<RwLock<BananaState>>) -> Self {
        SpliceBananasMutator {
            state: state,
        }
    }
}

#[derive(Debug, Default)]
pub struct InsertBanana {
    state: Rc<RwLock<BananaState>>,
}

impl<I, S> Mutator<I, S> for InsertBanana
where
    I: Input + HasBytesVec,
    S: HasRand + HasCorpus<I>,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // lets select where we will place call, preferably connected to calls mutated by AFL logic
/*
// TESTING performance of bananafzz repro only
        if 66 == unsafe { 
            &::std::slice::from_raw_parts(
                input.bytes().as_ptr() as *const PocDataHeader, 1)[0] 
        }.magic { return Ok(MutationResult::Mutated) }
*/

        let poc_header = unsafe { 
            &mut ::std::slice::from_raw_parts_mut(
                input.bytes_mut().as_ptr() as *mut PocDataHeader, 1)[0] };

        if !0 != poc_header.insert_ind {
            return Ok(MutationResult::Skipped)
        }

        if !self.state.read().unwrap().generate() {
            return Ok(MutationResult::Skipped)
        }

        let mut banana_state = self.state.write().unwrap();

        let ind = banana_state.select_input_ind(stage_idx, state, input);
        
        poc_header.insert_ind = ind;

        Ok(MutationResult::Mutated)
//        poc_header.insert_ind = !0;
//        Ok(MutationResult::Skipped)
    }
}

impl Named for InsertBanana {
    fn name(&self) -> &str {
        "InsertBanana"
    }
}

impl InsertBanana {
    /// Creates a new [`InsertBanana`].
    #[must_use]
    pub fn new(state: Rc<RwLock<BananaState>>) -> Self {
        InsertBanana {
            state: state,
        }
    }
}
