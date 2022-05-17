//! The `BijonObserver` provides ability for custom black box feedback

use ahash::AHasher;
use alloc::vec::Vec;
use core::{
    fmt::Debug,
    hash::Hasher,
    slice::{from_raw_parts, Iter, IterMut},
};
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{tuples::Named, AsMutSlice, AsSlice, HasLen},
    observers::Observer,
    Error,
};

// okay we are just wip extension building up on LibAFL patterns
use super::map::*;

use hashbrown::HashMap;

use libbijon::IBananaFeedback;

use std::sync::{RwLock, RwLockWriteGuard};

// TODO redo this stuff, likely via OwnedSlice, just temporary via lazy static
lazy_static! {
    static ref BANANA_FEEDBACK: RwLock<Vec<Vec<u8>>> = RwLock::new(vec![]);
}

/// middle man
pub fn banana_feedback<'a>() -> RwLockWriteGuard<'a, Vec<Vec<u8>>> {
    BANANA_FEEDBACK.write().unwrap()
}

/// Compute the hash of a slice
fn hash_slice<T: PrimInt>(slice: &[T]) -> u64 {
    let mut hasher = AHasher::new_with_keys(0, 0);
    let ptr = slice.as_ptr() as *const u8;
    let map_size = slice.len() / core::mem::size_of::<T>();
    unsafe {
        hasher.write(from_raw_parts(ptr, map_size));
    }
    hasher.finish()
}

/// bijon for bananafuzzer
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct BijonObserver {
    map: Vec<u8>,
    edges: HashMap<usize, usize>,
    initial: u8,
    prev: usize,
    upper_limit: usize,
}

impl<I, S> Observer<I, S> for BijonObserver
where
    Self: MapObserver,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        println!("?????????? PREx BIJON");
        //        assert!(0 == BANANA_FEEDBACK.write().unwrap().clear());
        banana_feedback().clear();

        self.prev = 0;
        self.reset_map()
    }
    #[inline]
    fn post_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        println!("?????????? POSt BIJON");
        banana_feedback()
            .drain(..)
            .for_each(|ref node| self.add_node(node));
        Ok(())
    }
}

impl Named for BijonObserver {
    #[inline]
    fn name(&self) -> &str {
        "B-IJON MAP"
    }
}

impl HasLen for BijonObserver {
    #[inline]
    fn len(&self) -> usize {
        self.upper_limit
    }
}

impl<'it> IntoIterator for &'it BijonObserver {
    type Item = <Iter<'it, u8> as Iterator>::Item;
    type IntoIter = Iter<'it, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'it> IntoIterator for &'it mut BijonObserver {
    type Item = <IterMut<'it, u8> as Iterator>::Item;
    type IntoIter = IterMut<'it, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

impl MapObserver for BijonObserver {
    type Entry = u8;

    #[inline]
    fn get(&self, pos: usize) -> &u8 {
        &self.as_slice()[pos]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.as_mut_slice()[idx]
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.as_slice().len()
    }

    fn hash(&self) -> u64 {
        hash_slice(
            &self
                .map
                .iter()
                .enumerate()
                .filter(|(_, x)| &0u8 != *x)
                .flat_map(|(i, x)| [i, *x as usize])
                .collect::<Vec<usize>>(),
        )
    }

    #[inline]
    fn initial(&self) -> u8 {
        self.initial
    }

    #[inline]
    fn initial_mut(&mut self) -> &mut u8 {
        &mut self.initial
    }

    #[inline]
    fn set_initial(&mut self, initial: u8) {
        self.initial = initial;
    }

    fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl AsSlice<u8> for BijonObserver {
    #[must_use]
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.map.as_slice()
    }
}
impl AsMutSlice<u8> for BijonObserver {
    #[must_use]
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.map.as_mut_slice()
    }
}

impl BijonObserver {
    /// Creates a new [`MapObserver`]
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            map: vec![],
            edges: HashMap::new(),
            initial: 0,
            prev: 0,
            upper_limit: limit,
        }
    }
}

impl IBananaFeedback for BijonObserver {
    /// externall call from bananafzz
    #[must_use]
    fn add_node(&mut self, nodex: &[u8]) {
        println!(".........!!!!!!> ADD NEW EDGGGG : {:?}", nodex);
        let prev = self.prev;
        let node = hash_slice(nodex) as usize;
        self.prev = node >> 1;

        if 0 == prev {
            return;
        }

        let key = prev ^ node;
        if self.edges.contains_key(&key) {
            if 1 == nodex.len() {
                return self.map[self.edges[&key]] = 1;
            }
            return self.map[self.edges[&key]] += 1;
        }

        self.edges.insert(key, self.map.len());
        self.map.push(1);
    }
}
