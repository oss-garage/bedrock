// SPDX-License-Identifier: GPL-2.0

//! The [`Assertion`] type, its [`AssertionData`] payload, and source
//! [`Location`].

use serde::{Deserialize, Serialize};

use crate::Condition;

/// Source location of an assertion macro invocation, captured via
/// [`file!`]/[`line!`]/[`column!`] at the call site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Source file path, as reported by [`file!`].
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
}

impl Location {
    /// Build a [`Location`]. The macros pass [`file!`]/[`line!`]/[`column!`];
    /// taking `impl Into<String>` keeps the `&'static str` → `String`
    /// conversion inside this crate, so callers need nothing extra in scope.
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Location {
            file: file.into(),
            line,
            column,
        }
    }
}

/// The payload common to both [`Assertion`] variants: the condition, its
/// evaluated result, the obligatory operator message, and the source location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionData {
    /// The condition that was evaluated.
    pub condition: Condition,
    /// The boolean result of evaluating [`condition`](Self::condition),
    /// computed once at construction time.
    pub result: bool,
    /// Operator-supplied message describing the asserted property. Required by
    /// every construction macro.
    pub message: String,
    /// Where the assertion macro was invoked.
    pub location: Location,
}

impl AssertionData {
    fn new(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        AssertionData {
            result: condition.evaluate(),
            condition,
            message: message.into(),
            location,
        }
    }
}

/// A property checked about guest execution: a [`Condition`] plus its evaluated
/// result, an obligatory message, and the source [`Location`] it was asserted
/// at (all carried in [`AssertionData`]).
///
/// The variant determines how the result is interpreted across the (many) times
/// an assertion of this kind is recorded:
///
/// - [`Assertion::Always`] — must hold on *every* evaluation; a single `false`
///   result is a violation.
/// - [`Assertion::Sometimes`] — must hold on *at least one* evaluation.
///
/// That per-variant semantic is resolved by a collector aggregating the records;
/// a single record only carries its own [`result`](AssertionData::result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assertion {
    /// The condition must hold every time the assertion is evaluated.
    Always(AssertionData),
    /// The condition must hold at least once across all evaluations.
    Sometimes(AssertionData),
}

impl Assertion {
    /// Create an [`Assertion::Always`] for `condition`, recording `message`,
    /// `location`, and the evaluated result.
    pub fn always(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        Assertion::Always(AssertionData::new(condition, message, location))
    }

    /// Create an [`Assertion::Sometimes`] for `condition`, recording `message`,
    /// `location`, and the evaluated result.
    pub fn sometimes(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        Assertion::Sometimes(AssertionData::new(condition, message, location))
    }

    /// The shared payload (condition, result, message, location).
    pub fn data(&self) -> &AssertionData {
        match self {
            Assertion::Always(data) | Assertion::Sometimes(data) => data,
        }
    }

    /// The [`Condition`] recorded on this assertion.
    pub fn condition(&self) -> Condition {
        self.data().condition
    }

    /// Whether the condition was satisfied for this evaluation — the stored
    /// [`result`](AssertionData::result).
    pub fn holds(&self) -> bool {
        self.data().result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.rs", 1, 1)
    }

    #[test]
    fn always_holds_when_condition_true() {
        assert!(Assertion::always(Condition::Bool(true), "m", loc()).holds());
        assert!(Assertion::always(Condition::Lt { x: 1, y: 2 }, "m", loc()).holds());
    }

    #[test]
    fn always_violated_when_condition_false() {
        assert!(!Assertion::always(Condition::Bool(false), "m", loc()).holds());
        assert!(!Assertion::always(Condition::Gt { x: 1, y: 2 }, "m", loc()).holds());
    }

    #[test]
    fn records_result_message_and_location() {
        let a = Assertion::always(
            Condition::Gt { x: 5, y: 2 },
            "five beats two",
            Location::new("f.rs", 10, 4),
        );
        let d = a.data();
        assert!(d.result);
        assert_eq!(d.message, "five beats two");
        assert_eq!(d.condition, Condition::Gt { x: 5, y: 2 });
        assert_eq!(d.location, Location::new("f.rs", 10, 4));
    }

    #[test]
    fn result_reflects_false_condition() {
        assert!(
            !Assertion::always(Condition::Lt { x: 9, y: 2 }, "m", loc())
                .data()
                .result
        );
    }

    #[test]
    fn sometimes_holds_evaluates_condition() {
        assert!(Assertion::sometimes(Condition::Bool(true), "m", loc()).holds());
        assert!(!Assertion::sometimes(Condition::Bool(false), "m", loc()).holds());
    }

    #[test]
    fn round_trips_through_serde() {
        let a = Assertion::always(
            Condition::Gt { x: 9, y: 2 },
            "nine gt two",
            Location::new("m.rs", 3, 7),
        );
        let json = serde_json::to_string(&a).unwrap();
        let back: Assertion = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
