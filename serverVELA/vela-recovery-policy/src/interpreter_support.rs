//! Shared declaration machinery for the handler-to-driver interpreters.
//!
//! Each interpreter names the I/O behind every non-terminal effect as one
//! trait. Declaring the trait from a single signature list keeps the proof
//! honest: under hax every method gets `requires(true)`, so the F* lemmas
//! quantify over every possible executor; ordinary builds get the same trait
//! without the attributes, so `hax-lib` stays a hax-only dependency.
//!
//! Every method returns `Option`: `Some(observation)` is the observation the
//! driver steps on, `None` means the effect's I/O failed and the request must
//! stop with the error the executor recorded (the handler renders that error
//! unchanged, exactly as it did when the effect was written inline).

/// Declares an executor trait from one list of method signatures.
macro_rules! executor_trait {
    (
        $(#[$doc:meta])*
        pub trait $name:ident {
            $(fn $method:ident(&mut self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*
        }
    ) => {
        $(#[$doc])*
        #[cfg(hax)]
        #[hax_lib::attributes]
        pub trait $name {
            $(
                #[hax_lib::requires(true)]
                fn $method(&mut self $(, $arg: $ty)*) -> $ret;
            )*
        }

        $(#[$doc])*
        #[cfg(not(hax))]
        pub trait $name {
            $(fn $method(&mut self $(, $arg: $ty)*) -> $ret;)*
        }
    };
}

pub(crate) use executor_trait;
