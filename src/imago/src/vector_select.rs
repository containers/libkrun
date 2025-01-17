//! Async select over future vectors.
//!
//! Allows collecting `dyn Future` objects (i.e. async function instances) in a vector, and
//! `select`ing (awaiting one) or `join`ing (awaiting all) them.

use std::future::Future;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Collect futures and await one or all of them.
pub(crate) struct FutureVector<R, E, F: Future<Output = Result<R, E>> + Unpin> {
    /// Pending futures.
    vec: Vec<F>,
}

/// Await a single future.
pub(crate) struct FutureVectorSelect<'a, R, E, F: Future<Output = Result<R, E>> + Unpin>(
    &'a mut FutureVector<R, E, F>,
);

/// Await all futures, discarding successful results.
pub(crate) struct FutureVectorDiscardingJoin<'a, R, E, F: Future<Output = Result<R, E>> + Unpin>(
    &'a mut FutureVector<R, E, F>,
);

impl<R, E, F: Future<Output = Result<R, E>> + Unpin> FutureVector<R, E, F> {
    /// Create a new `FutureVector`.
    pub fn new() -> Self {
        FutureVector { vec: Vec::new() }
    }

    /// Add a future.
    pub fn push(&mut self, future: F) {
        self.vec.push(future);
    }

    /// `true` if and only if there are no pending futures.
    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    /// Number of pending futures.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Await any one future.
    ///
    /// Return the result of the first future that becomes ready, removing it from the vector.
    ///
    /// Functionally, behaves like:
    /// ```ignore
    /// async fn select(&mut self) -> Result<R, E>;
    /// ```
    pub fn select(&mut self) -> FutureVectorSelect<'_, R, E, F> {
        FutureVectorSelect(self)
    }

    /// Join all futures, discarding successful results.
    ///
    /// If an error occurs, return it immediately.  All pending futures remain.
    ///
    /// Functionally, behaves like:
    /// ```ignore
    /// async fn discarding_join(&mut self) -> Result<(), E>;
    /// ```
    pub fn discarding_join(&mut self) -> FutureVectorDiscardingJoin<'_, R, E, F> {
        FutureVectorDiscardingJoin(self)
    }
}

impl<R, E, F: Future<Output = Result<R, E>> + Unpin> Future for FutureVectorSelect<'_, R, E, F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<F::Output> {
        assert!(!self.0.is_empty());

        for (i, fut) in self.0.vec.iter_mut().enumerate() {
            if let Poll::Ready(result) = F::poll(Pin::new(fut), ctx) {
                self.0.vec.swap_remove(i);
                return Poll::Ready(result);
            }
        }

        Poll::Pending
    }
}

impl<R, E, F: Future<Output = Result<R, E>> + Unpin> Future
    for FutureVectorDiscardingJoin<'_, R, E, F>
{
    type Output = Result<(), E>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), E>> {
        let mut i = 0;
        while i < self.0.len() {
            if let Poll::Ready(result) = F::poll(Pin::new(&mut self.0.vec[i]), ctx) {
                self.0.vec.swap_remove(i);
                if let Err(err) = result {
                    return Poll::Ready(Err(err));
                }
            } else {
                i += 1;
            }
        }

        if self.0.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
