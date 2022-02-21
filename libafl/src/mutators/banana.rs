use crate::{
    bolts::rands::Rand,
    inputs::{HasBytesVec, Input},
    state::HasRand,
    libbfl::info::{PocDataHeader, PocCallDescription},
    mutators::bananizer::get_calls_count,
};

use std::collections::BTreeSet;

use core::mem::size_of;

#[derive(Default, Debug)]
pub struct BananaState {
    stage_idx: i32,
    calls: BTreeSet<usize>,
    poc: Vec<u8>,
    crossdone: bool,
}
impl BananaState {
    pub fn new() -> Self {
        BananaState {
            stage_idx : 42,
            crossdone : false,
            calls : BTreeSet::new(),
            poc : vec![0u8; 0x10000],
        }
    }

    pub fn crossdone(&self) -> bool {
        self.crossdone
    }

    pub fn crossover(&mut self) {
        self.crossdone = true;
    }

    pub unsafe fn poc_mem(&self) -> *mut u8 {
        std::mem::transmute(self.poc.as_ptr())
    }

    fn new_bananas(&self, input: &[u8]) -> usize {
        let magic = unsafe { 
            &::std::slice::from_raw_parts(
                input.as_ptr() as *const PocDataHeader, 1)[0] }.magic;

        let poc_header = unsafe { 
            &::std::slice::from_raw_parts(
                self.poc.as_ptr() as *const PocDataHeader, 1)[0] };

        if magic != poc_header.magic {
            return 0
        }

        if !0 != poc_header.insert_ind {
            panic!("[BFL] bananafzz did not clear insert_ind in poc!!")
        }

        poc_header.total_size
    }
    fn register_stage<I: Input + HasBytesVec>(&mut self, stage_idx: i32, input: &mut I) {
        if self.stage_idx == stage_idx {
            return
        }
        self.crossdone = false;
        self.calls.clear();
        self.stage_idx = stage_idx;

        let nb_size = self.new_bananas(input.bytes());
        if 0 == nb_size {
            return//no banana inserted in latest AFL fuzz_one round..
        }
        input
            .bytes_mut()
            .splice(0.., self.poc[..nb_size].iter().copied());

        unsafe { 
            &mut ::std::slice::from_raw_parts_mut(
                self.poc.as_ptr() as *mut PocDataHeader, 1)[0] 
        }.magic = 0;
    }

    pub fn select_input_ind<I: Input + HasBytesVec, S: HasRand>(
        &mut self,
        stage_idx: i32,
        seed: &mut S,
        input: &mut I,
        ) -> usize 
    {
        self.register_stage(stage_idx, input);
        self.select_input_ind_impl(seed, input.bytes(), 0)
    }
    pub fn select_input_call<I: Input + HasBytesVec, S: HasRand>(
        &mut self,
        stage_idx: i32,
        seed: &mut S,
        input: &mut I,
        ) -> PocCallDescription 
    {
        self.register_stage(stage_idx, input);
        self.register_call(input, seed);
        self.select_call(seed, input.bytes(), 0)
    }
    pub fn select_kin_call<I: Input + HasBytesVec, S: HasRand>(
        &mut self,
        seed: &mut S,
        input: &I,
        kin: usize,
        other_bytes: &[u8],
        ) -> PocCallDescription 
    {
        self.register_kins(input, kin);
        self.select_call(seed, other_bytes, kin)
    }

    fn select_input_ind_impl<S: HasRand>(
        &mut self,
        seed: &mut S,
        input: &[u8],
        kin: usize
        ) -> usize
    {
        if 0 == self.calls.len() {
            return 0
        }

        let n_calls = get_calls_count(input);
        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                input[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, n_calls) };

        let selection = self.calls
            .iter()
            .filter(|&&ind| 0 == kin || kin == poc_desc[ind].kin)
            .collect::<Vec<&usize>>();//nah i dont like this collect ..

        if 0 == selection.len() {
            return 0
        }

        *seed.rand_mut().choose(selection)
    }
    fn select_call<S: HasRand>(
        &mut self,
        seed: &mut S,
        input: &[u8],
        kin: usize
        ) -> PocCallDescription 
    {
        let ind = self.select_input_ind_impl(seed, input, kin);

        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                input[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, ind + 1) };

        poc_desc[ind]
    }

    fn register_call<I: Input + HasBytesVec, S: HasRand>(&mut self, input: &I, seed: &mut S) {
        let n_calls = get_calls_count(input.bytes());
        if self.calls.len() > 1 + n_calls / 3 {
            return
        }

//here is the quesion, to replace by random choose + set insert or to force random + insert ?
/*
        if seed.rand_mut().choose(0..n_calls) < 2 * self.calls.len() {
            return
        }
*/
        let ind = seed.rand_mut().choose(0..n_calls);
/*
        while self.calls.contains(&ind) {
            ind = (ind + 1) % n_calls;
        }
*/

        self.calls.insert(ind);
    }
    fn register_kins<I: Input + HasBytesVec>(&mut self, input: &I, kin: usize) {
        let n_calls = get_calls_count(input.bytes());
        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                input
                    .bytes()[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, n_calls) };

        for ind in 0..n_calls {
            if poc_desc[ind].size < size_of::<usize>() {
                panic!("[BFL] incorrect call data size {:?}/{:?} => {:?}", ind, n_calls, poc_desc[ind])
            }
            //0 == kin, means choose random call
            if 0 == kin || kin == poc_desc[ind].kin {
                self.calls.insert(ind);
            }
        }
    }
}
