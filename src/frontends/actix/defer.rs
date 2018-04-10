use std::cell::RefCell;
use std::mem::replace;
use std::rc::Rc;

use super::futures::{Async, Future, Poll};

/// Encapsulates messaging, storing any async wait so that it can be retrieved later.
///
/// Special to this compared to future is that the request will only be sent once, until the
/// result is retrieved.  Storing this outside a pure sync method allows the sync method to fail
/// and be retried gracefully.
pub enum DeferredResult<Pending: Future> {
    NotInitialized /* Initial state, not reachable otherwise except panics during poll */,
    Sent(Pending) /* from initialized, going to Errored or Answer */,
    Errored(Pending::Error) /* Final state*/,
    Answer(Pending::Item) /* Final state*/,
}

type SharedResult<Pending: Future> = Rc<RefCell<DeferredResult<Pending>>>;

#[derive(Debug)]
struct WasUninitialized;

#[derive(Clone)]
pub struct DeferableComputation<Pending: Future> {
    message: SharedResult<Pending>,
}

#[derive(Clone)]
pub struct StartedComputation<Pending: Future> where Pending::Error: Clone {
    message: SharedResult<Pending>,
}

impl<Pending: Future> DeferredResult<Pending> {
    fn initialize<F>(&mut self, f: F) where F: FnOnce() -> Pending {
        match *self {
            DeferredResult::NotInitialized => *self = DeferredResult::Sent(f()),
            _ => (),
        }
    }

    fn is_initialized(&self) -> bool {
        match *self {
            DeferredResult::NotInitialized => true,
            _ => false,
        }
    }

    fn make_answer(&self) -> Option<Pending::Item> where Pending::Item: Clone {
        match *self {
            DeferredResult::Answer(ref answer) => Some(answer.clone()),
            _ => None,
        }
    }

    fn make_error(&self) -> Option<Pending::Error> where Pending::Error: Clone {
        match *self {
            DeferredResult::Errored(ref err) => Some(err.clone()),
            _ => None,
        }
    }

    fn poll(&mut self) -> Poll<(), WasUninitialized> {
        let (replacement, result) = match replace(self, DeferredResult::NotInitialized) {
            DeferredResult::Sent(mut pending) => {
                match pending.poll() {
                    Ok(Async::NotReady) => (DeferredResult::Sent(pending), Ok(Async::NotReady)),
                    Ok(Async::Ready(value)) => (DeferredResult::Answer(value), Ok(Async::Ready(()))),
                    Err(error) => (DeferredResult::Errored(error), Ok(Async::Ready(()))),
                }
            },
            DeferredResult::NotInitialized => (DeferredResult::NotInitialized, Err(WasUninitialized)),
            other => (other, Ok(Async::Ready(()))),
        };

        replace(self, replacement);
        result
    }
}

impl<Pending: Future> DeferableComputation<Pending> {
    pub fn uninitialized() -> Self {
        DeferableComputation {
            message: Rc::new(RefCell::new(DeferredResult::NotInitialized)),
        }
    }

    pub fn initialize<F>(&self, f: F) where F: FnOnce() -> Pending {
        self.message.borrow_mut().initialize(f)
    }

    pub fn make_answer(&self) -> Option<Pending::Item> where Pending::Item: Clone {
        self.message.borrow().make_answer()
    }

    pub fn start(self) -> Option<StartedComputation<Pending>> where Pending::Error: Clone {
        if self.message.borrow().is_initialized() {
            Some(StartedComputation {
                message: self.message.clone(),
            })
        } else {
            None
        }
    }
}

impl<Pending: Future> Future for DeferableComputation<Pending> where Pending::Error: Clone {
    type Item = ();
    type Error = Pending::Error;

    fn poll(&mut self) -> Poll<(), Pending::Error> {
        match self.message.borrow_mut().poll() {
            Err(_) => unreachable!("This condition is secured by DeferableComputation::start"),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(())) => {
                if let Some(error) = self.message.borrow().make_error() {
                    Err(error)
                } else {
                    Ok(Async::Ready(()))
                }
            }
        }
    }
}
