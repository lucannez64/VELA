//! A panic boundary for background work.
//!
//! `cx.background_spawn(..)` has no boundary of its own: a panicking task is
//! closed without ever producing a value, so the foreground `.await` on it
//! panics in turn ("Task polled after completion") and takes the whole window
//! down. That is how a Secret Service probe on machines with biometrics
//! enrolled turned into a startup crash — the backend bug was one thread's
//! problem, the missing boundary is what made it everyone's.
//!
//! Every call into `vela_desktop_core` from a background task goes through
//! [`GuardedSpawn::background_spawn_guarded`], which yields `None` instead of
//! unwinding into the caller. Sleeps and other infallible timing work still
//! use the raw call — there is nothing there to catch.

use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures::FutureExt as _;
use gpui::{AppContext, Task};

pub trait GuardedSpawn {
    /// `background_spawn`, but a panic in the task is logged and reported as
    /// `None` rather than propagating to whoever awaits it.
    ///
    /// `what` names the work in the log line — the panic's own message and
    /// location still come from the default hook, this just says which task
    /// it was.
    fn background_spawn_guarded<R>(
        &self,
        what: &'static str,
        future: impl Future<Output = R> + Send + 'static,
    ) -> Task<Option<R>>
    where
        R: Send + 'static;
}

impl<T: AppContext> GuardedSpawn for T {
    fn background_spawn_guarded<R>(
        &self,
        what: &'static str,
        future: impl Future<Output = R> + Send + 'static,
    ) -> Task<Option<R>>
    where
        R: Send + 'static,
    {
        self.background_spawn(async move {
            match AssertUnwindSafe(future).catch_unwind().await {
                Ok(value) => Some(value),
                Err(panic) => {
                    tracing::error!("background task `{what}` panicked: {}", describe(&panic));
                    None
                }
            }
        })
    }
}

fn describe(panic: &Box<dyn std::any::Any + Send>) -> &str {
    if let Some(s) = panic.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s
    } else {
        "<non-string panic payload>"
    }
}
