//! Sorted iterator
//!
//! The [`SortedIter`] struct represents an iterator that produces a sorted
//! sequence of elements from two sorted input iterators, `a` and `b`. The
//! elements in the output sequence are sorted according to a comparison
//! function `cmp` that is provided as an argument to the [`sorted_iter`]
//! function, which creates an instance of [`SortedIter`].
//!
//! The resulting iteraor iterates over all unique elements from both input
//! vectors. If an element is present in both input vectors, only the element
//! from iterator `a` is returned.
//!
//! Note that the two iterators must be sorted. Using this with unsroted
//! iterators will result in an incorrect output.

use std::cmp::Ordering;
use std::iter::Peekable;

/// Iterator that produces a sorted sequence of elements from two input
/// iterators.
pub struct SortedIter<I, E, F>
where
    I: Iterator,
    E: Ord,
    F: Fn(&I::Item) -> E,
{
    a: Peekable<I>,
    b: Peekable<I>,
    cmp: F,
}

impl<I, E, F> Iterator for SortedIter<I, E, F>
where
    I: Iterator,
    E: Ord,
    F: Fn(&I::Item) -> E,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let a_next = self.a.peek();
        let b_next = self.b.peek();
        match (a_next, b_next) {
            // Both iterators have elements, compare the next elements
            (Some(a), Some(b)) => match (self.cmp)(a).cmp(&(self.cmp)(b)) {
                // Return next element from a, since it is smaller than the
                // element from b
                Ordering::Less => self.a.next(),
                // Return next element from a, since it is equal to b and drop
                // the element from b
                Ordering::Equal => {
                    self.b.next();
                    self.a.next()
                }
                // Return next element from b, since it is smaller than the
                // element from a
                Ordering::Greater => self.b.next(),
            },
            // Iterator b is empty, return next element from a
            (Some(_), None) => self.a.next(),
            // Iterator a is empty, return next element from b
            (None, Some(_)) => self.b.next(),
            // Both iterators are empty, return None
            (None, None) => None,
        }
    }
}

/// Create a new [`SortedIter`] from two input iterators.
pub fn sorted_iter<I, E, F>(a: I, b: I, cmp: F) -> SortedIter<I, E, F>
where
    I: Iterator,
    E: Ord,
    F: Fn(&I::Item) -> E,
{
    SortedIter {
        a: a.peekable(),
        b: b.peekable(),
        cmp,
    }
}

// Test the [`SortedIter`] iterator
#[test]
fn test_sorted_iter() {
    // Test empty input
    let a: Vec<i32> = Vec::new();
    let b: Vec<i32> = Vec::new();
    let cmp = |x: &i32| *x;
    let s = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<i32> = s.collect();
    assert_eq!(result, Vec::<i32>::new());

    // Test input with only one element
    let a = vec![1];
    let b: Vec<i32> = Vec::new();
    let cmp = |x: &i32| *x;
    let iter = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<i32> = iter.collect();
    assert_eq!(result, vec![1]);

    let a: Vec<i32> = Vec::new();
    let b = vec![1];
    let cmp = |x: &i32| *x;
    let iter = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<i32> = iter.collect();
    assert_eq!(result, vec![1]);

    // Test input with two elements, sorted in ascending order
    let a = vec![1, 2];
    let b = vec![3, 4];
    let cmp = |x: &i32| *x;
    let iter = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<i32> = iter.collect();
    assert_eq!(result, vec![1, 2, 3, 4]);

    // Test input with two elements, one in each iterator, sorted in ascending order
    let a = vec![1, 2, 3, 4, 5, 6];
    let b = vec![4, 5, 6, 7, 8, 9, 10];
    let cmp = |x: &i32| *x;
    let iter = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<i32> = iter.collect();
    assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // Test with tuples
    let a = vec![(1, 1), (2, 1), (3, 1)];
    let b = vec![(1, 2), (2, 2), (4, 2)];
    let cmp = |x: &(i32, i32)| x.0;
    let iter = sorted_iter(a.into_iter(), b.into_iter(), cmp);
    let result: Vec<(i32, i32)> = iter.collect();
    assert_eq!(result, vec![(1, 1), (2, 1), (3, 1), (4, 2)]);
}
