/// bananizing AFL data format to be able to fuzz effectively generative api based args

use crate::{
    bolts::{rands::Rand, tuples::Named},
    inputs::{bytes::BytesInput, HasBytesVec, Input},
    mutators::{MutationResult, Mutator, banana::BananaState},
    state::HasRand,
    Error,
    libbfl::info::{PocDataHeader, PocCallHeader},
};

use std::{rc::Rc, sync::RwLock};
use core::{
    mem::size_of,
    fmt::Debug,
};

//#[allow(missing_docs)]
pub trait IBananizer<I, S> : Mutator<I, S> + Named + Debug
where
        I: Input + HasBytesVec,
        S: HasRand,
{}

//#[allow(missing_docs)]
pub struct BananizedAdapt<I, S> {
    state: Rc<RwLock<BananaState>>,
    name : String,
    mutator: Box<dyn IBananizer<I, S>>,
}

impl<I, S> Debug for BananizedAdapt<I, S> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> { 
        self.mutator.fmt(fmt)
    }
}

impl<I, S> Mutator<I, S> for BananizedAdapt<I, S>
where
        I: Input + HasBytesVec + From<BytesInput>,
        S: HasRand,
{
    fn mutate(
        &mut self,
        seed: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            return Ok(MutationResult::Skipped)
        }

        let mut banana_state = self.state.write().unwrap();
        let call = banana_state.select_input_call(stage_idx, seed, input);

        let head = unsafe { 
            ::std::slice::from_raw_parts(
                input.bytes()[call.offset..].as_ptr() as *const PocCallHeader, 1)[0] };

        if 0 == head.dmp_size {
            return Ok(MutationResult::Skipped)
        }
        assert!(head.len == call.size, "incosisten header with description[# => {stage_idx:?}] {:?} vs {:?} ==> {:?}", head.len, call.size, head);
        let end = call.offset + head.len;
        let mut off = end - head.dmp_size;
        if end == off {
            return Ok(MutationResult::Skipped)
        }

        let ind = seed.rand_mut().choose(off..end);

        let size_size = size_of::<usize>();
        let size = loop {//trhough full input {<size, [u8]>, .. }
            let size: usize = unsafe { 
                ::std::slice::from_raw_parts(
                    input.bytes()[off..].as_ptr() as *const usize, 1)[0] };

            if 0 == size {
                panic!("[BFL] size desc==0;\n\t{:?}\n\t{:?}", call, head)
            }

            if off + size_size + size > ind {
                break size
            }

            off += size_size + size;
        };
        off += size_size; // skip size description

        if off + size > end {
            panic!("[BFL] parsed out of call data {:X}+{:X}>{:X}\n>>> {:?}\n", off, size, end, call)
        }

        let ind = if ind > off { 
            ind - off
        } else { 0 }; // we hit size description

        let mut banana_input: I = BytesInput::new(
            input.bytes()[off..][..size][ind..].to_vec()).into();

        let result = self.mutator.mutate(seed, &mut banana_input, stage_idx);

        assert!(size - banana_input.bytes().len() == ind);
        (&input.bytes_mut()[off..][..size][ind..])
            .clone_from(&banana_input.bytes());

        result
    }
}

impl<I, S> Named for BananizedAdapt<I, S>
{
    fn name(&self) -> &str {
        &self.name
    }
}

//#[allow(missing_docs)]
impl<I, S> BananizedAdapt<I, S>
where
        I: Input + HasBytesVec,
        S: HasRand,
{
    #[must_use]
    pub fn new(state: Rc<RwLock<BananaState>>, mutator: Box::<dyn IBananizer<I, S>>) -> Self {
        BananizedAdapt {
            name : "Bananized@".to_owned() + mutator.name(),
            mutator: mutator,
            state: state,
        }
    }
}

pub(crate) fn get_calls_count(input: &[u8]) -> usize {
    if input.len() < size_of::<PocDataHeader>() {
        panic!("[BFL] incorrect call data")
    }
    let poc_header = unsafe { 
        &::std::slice::from_raw_parts(
            input.as_ptr() as *const PocDataHeader, 1)[0] };
    if 0 == poc_header.calls_count {
        panic!("[BFL] incorrect call data count==0")
    }
    poc_header.calls_count
}
