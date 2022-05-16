use std::{rc::Rc, sync::RwLock};

#[allow(unused)]
use crate::{
    bolts::tuples::tuple_list,
    inputs::{BytesInput, HasBytesVec, Input},
    mutators::{
        banana::BananaState,
        bananizer::{BananizedAdapt, IBananizer},
        bfl::{AppendBanana, CrossoverBananasMutator, InsertBanana, SpliceBananasMutator},
        MutatorsTuple,
    },
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
};

use crate::mutators::mutations::*;

#[allow(missing_docs)]
pub fn banana_mutations<I, S>() -> (impl MutatorsTuple<I, S>, Rc<RwLock<BananaState>>)
where
    I: Input + HasBytesVec + From<BytesInput>,
    S: HasRand + HasCorpus<I> + HasMetadata + HasMaxSize,
{
    let state = Rc::new(RwLock::new(BananaState::new()));
    (
        tuple_list!(
            //BananizedAdapt::new(Rc::clone(&state), Box::new(BitFlipMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(ByteFlipMutator::new())),
            BananizedAdapt::new(Rc::clone(&state), Box::new(ByteIncMutator::new())),
            BananizedAdapt::new(Rc::clone(&state), Box::new(ByteDecMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(ByteNegMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(ByteRandMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(ByteAddMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(WordAddMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(DwordAddMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(QwordAddMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(ByteInterestingMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(WordInterestingMutator::new())),
            BananizedAdapt::new(Rc::clone(&state), Box::new(DwordInterestingMutator::new())),
            BananizedAdapt::new(Rc::clone(&state), Box::new(DwordInterestingMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(BytesSetMutator::new())),
            //BananizedAdapt::new(Rc::clone(&state), Box::new(BytesRandSetMutator::new())),
            InsertBanana::new(Rc::clone(&state)),
            InsertBanana::new(Rc::clone(&state)),
            AppendBanana::new(Rc::clone(&state)),
            //InsertBanana::new(Rc::clone(&state)),
            //AppendBanana::new(Rc::clone(&state)),
            //SpliceBananasMutator::new(Rc::clone(&state)),
            SpliceBananasMutator::new(Rc::clone(&state)),
            SpliceBananasMutator::new(Rc::clone(&state)),
            SpliceBananasMutator::new(Rc::clone(&state)),
            CrossoverBananasMutator::new(Rc::clone(&state)),
            CrossoverBananasMutator::new(Rc::clone(&state)),
            // seems addine one more mutator and compilation will take forever
            // we will skip bytes copy mutator
            //        BananizedAdapt::new(Rc::clone(&state), Box::new(BytesCopyMutator::new())),
        ),
        state,
    )
}

impl<I, S> IBananizer<I, S> for BitFlipMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteFlipMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteIncMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteDecMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteNegMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteRandMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteAddMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for WordAddMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for DwordAddMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for QwordAddMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for ByteInterestingMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for WordInterestingMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for DwordInterestingMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for BytesSetMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for BytesRandSetMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
impl<I, S> IBananizer<I, S> for BytesCopyMutator
where
    I: Input + HasBytesVec,
    S: HasRand,
{
}
