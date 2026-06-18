// SPDX-License-Identifier: GPL-2.0

//! Convenience macros for constructing [`Assertion`](crate::Assertion)s.
//!
//! Two families are provided, one per [`Assertion`](crate::Assertion) variant:
//! `always_*` builds [`Assertion::Always`](crate::Assertion::Always) and
//! `sometimes_*` builds [`Assertion::Sometimes`](crate::Assertion::Sometimes).
//!
//! Every macro takes an obligatory trailing `message` (anything `Into<String>`)
//! describing the property, and captures the call-site source location via
//! [`file!`]/[`line!`]/[`column!`]. The evaluated result is recorded too. All of
//! these land in the serialized [`AssertionData`](crate::AssertionData).
//!
//! Comparison operands accept any integer value up to `u64`: they are converted
//! with [`i128::from`], which accepts every signed/unsigned integer type
//! through `u64`/`i64` and rejects anything wider (e.g. `u128`) at compile
//! time.

/// Internal: generate one comparison macro that builds an assertion of the
/// given variant for a given [`Condition`](crate::Condition).
///
/// `$d` threads a literal `$` into the generated macro so its metavariables
/// don't clash with this generator's own parser (same trick as `bedrock-log`).
macro_rules! define_cmp_macro {
    ($d:tt $(#[$doc:meta])* $name:ident => $ctor:ident, $variant:ident) => {
        $(#[$doc])*
        #[macro_export]
        macro_rules! $name {
            ($d x:expr, $d y:expr, $d msg:expr $d(,)?) => {
                $crate::Assertion::$ctor(
                    $crate::Condition::$variant {
                        x: i128::from($d x),
                        y: i128::from($d y),
                    },
                    $d msg,
                    $crate::Location::new(::core::file!(), ::core::line!(), ::core::column!()),
                )
            };
        }
    };
}

define_cmp_macro!($
    /// Build an `Always` assertion over `x < y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::always_lt;
    /// assert!(always_lt!(1u64, 2u64, "x below y").holds());
    /// ```
    always_lt => always, Lt);

define_cmp_macro!($
    /// Build a `Sometimes` assertion over `x < y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::{sometimes_lt, Condition};
    /// assert_eq!(sometimes_lt!(1u64, 2u64, "x below y").condition(), Condition::Lt { x: 1, y: 2 });
    /// ```
    sometimes_lt => sometimes, Lt);

define_cmp_macro!($
    /// Build an `Always` assertion over `x > y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::always_gt;
    /// assert!(always_gt!(2u64, 1u64, "x above y").holds());
    /// ```
    always_gt => always, Gt);

define_cmp_macro!($
    /// Build a `Sometimes` assertion over `x > y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::{sometimes_gt, Condition};
    /// assert_eq!(sometimes_gt!(2u64, 1u64, "x above y").condition(), Condition::Gt { x: 2, y: 1 });
    /// ```
    sometimes_gt => sometimes, Gt);

define_cmp_macro!($
    /// Build an `Always` assertion over `x <= y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::always_lte;
    /// assert!(always_lte!(2u64, 2u64, "x at most y").holds());
    /// ```
    always_lte => always, Lte);

define_cmp_macro!($
    /// Build a `Sometimes` assertion over `x <= y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::{sometimes_lte, Condition};
    /// assert_eq!(sometimes_lte!(2u64, 2u64, "x at most y").condition(), Condition::Lte { x: 2, y: 2 });
    /// ```
    sometimes_lte => sometimes, Lte);

define_cmp_macro!($
    /// Build an `Always` assertion over `x >= y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::always_gte;
    /// assert!(always_gte!(2u64, 2u64, "x at least y").holds());
    /// ```
    always_gte => always, Gte);

define_cmp_macro!($
    /// Build a `Sometimes` assertion over `x >= y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::{sometimes_gte, Condition};
    /// assert_eq!(sometimes_gte!(2u64, 2u64, "x at least y").condition(), Condition::Gte { x: 2, y: 2 });
    /// ```
    sometimes_gte => sometimes, Gte);

define_cmp_macro!($
    /// Build an `Always` assertion over `x == y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::always_eq;
    /// assert!(always_eq!(2u64, 2u64, "x equals y").holds());
    /// ```
    always_eq => always, Eq);

define_cmp_macro!($
    /// Build a `Sometimes` assertion over `x == y` with a message.
    ///
    /// ```
    /// use bedrock_assertions::{sometimes_eq, Condition};
    /// assert_eq!(sometimes_eq!(2u64, 2u64, "x equals y").condition(), Condition::Eq { x: 2, y: 2 });
    /// ```
    sometimes_eq => sometimes, Eq);

/// Build an `Always` assertion over a boolean condition with a message.
///
/// ```
/// use bedrock_assertions::always_bool;
/// assert!(always_bool!(2 + 2 == 4, "arithmetic holds").holds());
/// ```
#[macro_export]
macro_rules! always_bool {
    ($cond:expr, $msg:expr $(,)?) => {
        $crate::Assertion::always(
            $crate::Condition::Bool($cond),
            $msg,
            $crate::Location::new(::core::file!(), ::core::line!(), ::core::column!()),
        )
    };
}

/// Build a `Sometimes` assertion over a boolean condition with a message.
///
/// ```
/// use bedrock_assertions::{sometimes_bool, Condition};
/// assert_eq!(sometimes_bool!(true, "sometimes true").condition(), Condition::Bool(true));
/// ```
#[macro_export]
macro_rules! sometimes_bool {
    ($cond:expr, $msg:expr $(,)?) => {
        $crate::Assertion::sometimes(
            $crate::Condition::Bool($cond),
            $msg,
            $crate::Location::new(::core::file!(), ::core::line!(), ::core::column!()),
        )
    };
}
