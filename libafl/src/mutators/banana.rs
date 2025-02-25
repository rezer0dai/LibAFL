use crate::{
    bolts::rands::Rand,
    inputs::{HasBytesVec, Input},
    state::HasRand,
    libbfl::info::{PocDataHeader, PocCallDescription, PocCallHeader},
    mutators::bananizer::get_calls_count,
};

use std::collections::BTreeSet;

use core::mem::size_of;

const N_ITERS: i32 = 3;//5;//how many mutations per generation ( original / crossover / insert )
const N_GENERATIONS: i32 = 20;//how many crossover / inserts to stack up

#[derive(Default, Debug)]
pub struct BananaState {
    stage_idx: i32,
    calls: BTreeSet<usize>,
    poc: Vec<u8>,
    generate: bool,
}
impl BananaState {
    pub fn new() -> Self {
        BananaState {
            stage_idx : 42,
            calls : BTreeSet::new(),
            poc : vec![0u8; 0x100000],
            generate: true,//false,
        }
    }

    pub fn generate(&self) -> bool { 
        self.generate && (0 != self.stage_idx % (N_GENERATIONS * N_ITERS)) 
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
        if !0 != poc_header.split_at {
            panic!("[BFL] bananafzz did not clear split_at in poc!!")
        }

        poc_header.total_size
    }
    fn register_stage<I: Input + HasBytesVec>(&mut self, stage_idx: i32, input: &mut I) {
        if self.stage_idx == stage_idx {
            return
        }
        self.stage_idx = stage_idx;

        self.generate = 0 == (stage_idx % N_ITERS); //every 10th - TODO : config!!
        if self.generate {
            self.calls.clear()
        }
        let nb_size = self.new_bananas(input.bytes());
        if 0 == nb_size {
if self.generate() { println!("[BFL] failing to stack up insert/crossover at {stage_idx} level") }
            return self.calls.clear()
        }//no banana inserted in latest AFL fuzz_one round..

        let generate = self.generate;
        self.generate = true;
        if self.generate() {//0 != stage_idx {//0 != stage_idx {//first input query and mutation fuzz one we want to generate
            input
                .bytes_mut()
                .splice(0.., self.poc[..nb_size].iter().copied());
        } else { self.calls.clear() }
        self.generate = generate;

        if self.generate() {
            return
        }

        unsafe { //once we do this, we must generate, otherwise with this input no insert calls / crossover
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
        if 0 == self.calls.len() {
            self.register_call(input, seed);
        } 
        if 0 == self.calls.len() {
            return get_calls_count(input.bytes()) - 1 // should not happen btw
        } 
        let ind = *seed.rand_mut().choose(&self.calls);

        if ind < get_calls_count(input.bytes()) {
            ind
        } else { 0 }
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
        self.select_call(seed, input.bytes())
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

        let n_calls = get_calls_count(other_bytes);
        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                other_bytes[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, n_calls) };

        let selection = (0..n_calls)
            .filter(|&ind| kin == poc_desc[ind].kin)
            .collect::<Vec<usize>>();//nah i dont like this collect ..

        let ind = if 0 != selection.len() {
            seed.rand_mut().choose(selection)
        } else { 0 };// poc_desc[0].kin = 0; mutation->skipped

        let ind = if ind < get_calls_count(input.bytes()) {
            ind
        } else { 0 };

        poc_desc[ind]
    }

    fn select_call<S: HasRand>(
        &mut self,
        seed: &mut S,
        input: &[u8],
        ) -> PocCallDescription 
    {
        let ind = if 0 != self.calls.len() {
            *seed.rand_mut().choose(&self.calls)
        } else { 0 };// poc_desc[0].kin = 0; mutation->skipped

        let ind = if ind < get_calls_count(input) {
            ind
        } else { 0 };

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

        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                input
                    .bytes()[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, n_calls) };

        //best if seed.rand_mut().choose_or(0, |x| ...)
        let targets = (0..n_calls)
            .filter(|&ind| 0 != unsafe { 
                    ::std::slice::from_raw_parts(
                        input.bytes()[poc_desc[ind].offset..
                            ].as_ptr() as *const PocCallHeader, 1)[0] 
                    }.dmp_size
                )
            .collect::<Vec<usize>>();
        if 0 == targets.len() {
            return
        }
        let ind = seed.rand_mut().choose(targets);

//here is the quesion, to replace by random choose + set insert or to force random + insert ?
/*
        if seed.rand_mut().choose(0..n_calls) < 2 * self.calls.len() {
            return
        }
*/
//        let ind = seed.rand_mut().choose(0..n_calls);

/*
        while self.calls.contains(&ind) {
            ind = (ind + 1) % n_calls;
        }
*/

        self.calls.insert(ind);
    }
    /// THIS IS NO GOOD ( "break" at very least ), and 
    /// overall need to rethink this kin strategy
    /// for doing crossover in banana corpora
    fn register_kins<I: Input + HasBytesVec>(&mut self, input: &I, kin: usize) {
        assert!(0 != kin, "[BFL] 0==kin; should not happen tbh ...");
        let n_calls = get_calls_count(input.bytes());
        let poc_desc = unsafe { 
            ::std::slice::from_raw_parts(
                input
                    .bytes()[size_of::<PocDataHeader>()..]
                    .as_ptr() as *const PocCallDescription, n_calls) };

        for ind in (0..n_calls)
            //0 == kin, means choose random call
            .filter(|&ind| 0 == kin || kin == poc_desc[ind].kin) 
        {
            if poc_desc[ind].size < size_of::<usize>() {
                panic!("[BFL] incorrect call data size {:?}/{:?} => {:?}", ind, n_calls, poc_desc[ind])
            }
            self.calls.insert(ind);
            break
        }
    }
}
