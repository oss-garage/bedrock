// SPDX-License-Identifier: GPL-2.0

use super::*;

#[test]
fn test_null_instruction_counter() {
    let mut counter = NullInstructionCounter;

    assert!(!counter.is_configured());

    // Default prepare/finish should be no-ops.
    assert_eq!(counter.prepare(), Ok(()));
    assert_eq!(counter.finish(), Ok(()));

    assert_eq!(counter.read(), 0);
    assert!(counter.perf_global_ctrl_values().is_none());
}

#[test]
fn test_null_counter_is_copy() {
    let counter = NullInstructionCounter;
    let _copy = counter;
    let _another = counter;
}

/// Mock counter for testing VM code that uses instruction counting.
#[derive(Debug, Default)]
pub struct MockInstructionCounter {
    pub count: u64,
    pub prepare_count: u32,
    pub finish_count: u32,
}

impl MockInstructionCounter {
    pub fn new(count: u64) -> Self {
        Self {
            count,
            ..Default::default()
        }
    }
}

impl InstructionCounter for MockInstructionCounter {
    fn prepare(&mut self) -> Result<(), InstructionCounterError> {
        self.prepare_count += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), InstructionCounterError> {
        self.finish_count += 1;
        Ok(())
    }

    fn read(&self) -> u64 {
        self.count
    }

    fn is_configured(&self) -> bool {
        true
    }

    fn perf_global_ctrl_values(&self) -> Option<(u64, u64)> {
        None
    }
}

#[test]
fn test_mock_instruction_counter() {
    let mut counter = MockInstructionCounter::new(1000);

    assert!(counter.is_configured());
    assert_eq!(counter.read(), 1000);

    assert_eq!(counter.prepare(), Ok(()));
    assert_eq!(counter.prepare_count, 1);
    assert_eq!(counter.finish(), Ok(()));
    assert_eq!(counter.finish_count, 1);

    counter.count = 5000;
    assert_eq!(counter.read(), 5000);
}
