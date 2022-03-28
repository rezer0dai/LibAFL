//! The queue corpus scheduler for power schedules.

use alloc::string::{String, ToString};

use crate::{
    corpus::{Corpus, CorpusScheduler, PowerScheduleTestcaseMetaData},
    inputs::Input,
    stages::PowerScheduleMetadata,
    state::{HasCorpus, HasMetadata},
    Error,
};

/// A corpus scheduler using power schedules
#[derive(Clone, Debug)]
pub struct PowerQueueCorpusScheduler;

impl Default for PowerQueueCorpusScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> CorpusScheduler<I, S> for PowerQueueCorpusScheduler
where
    S: HasCorpus<I> + HasMetadata,
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let current_idx = *state.corpus().current();
/*
        let filename = state
                .corpus()
                .get(idx)?
                .borrow()
                .filename()
                .clone();
*/
        let mut depth = match current_idx {
            Some(parent_idx) => if let Some(data) = state
                .corpus()
                .get(parent_idx)?
                .borrow_mut()
                .metadata_mut()
                .get_mut::<PowerScheduleTestcaseMetaData>() 
/*
                .ok_or_else(|| Error::KeyNotFound(
                        format!("#1 PowerScheduleTestData not found in corpus#{idx} == {:?}",
                            if filename.is_some() { filename.unwrap().clone() } else { format!("NO NAME") }))
                )?
                .depth(),
*/
                { data.depth() } else { 0 }, //not sure if this is worth to scatter input
            None => 0,
        };

        // Attach a `PowerScheduleTestData` to the queue entry.
        depth += 1;
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(PowerScheduleTestcaseMetaData::new(depth));
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty(String::from("No entries in corpus")))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if *cur + 1 >= state.corpus().count() {
                        let psmeta = state
                            .metadata_mut()
                            .get_mut::<PowerScheduleMetadata>()
                            .ok_or_else(|| {
                                Error::KeyNotFound("PowerScheduleMetadata not found".to_string())
                            })?;
                        psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
                        0
                    } else {
                        *cur + 1
                    }
                }
                None => 0,
            };
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl PowerQueueCorpusScheduler {
    /// Create a new [`PowerQueueCorpusScheduler`]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
