//! One declaration for the I/O an interpreter drives.
//!
//! Each `<name>_interpreter` module declares its executor trait from this one
//! list of method signatures. Under hax every method gets `requires(true)` (the
//! proof assumes nothing about the executor); ordinary builds get the same
//! trait without the attributes, so `hax-lib` stays a hax-only dependency.
//!
//! The macro is crate-private: modules import it with `#[macro_use]` on this
//! module's declaration in `lib.rs`. Moving it out of
//! [`crate::deletion_interpreter`] changed no expansion.

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
