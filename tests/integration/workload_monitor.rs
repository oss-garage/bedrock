//! The guest-side assertion pipeline.
//!
//! At guest boot the `workload-monitor` service watches `podman events` and, on
//! every container or `podman exec` death, emits an exit-code [`Assertion`]. The
//! pipeline surfaces each assertion onto the serial console inside a compact
//! journald JSON record (`{"SYSLOG_IDENTIFIER":"assertions","MESSAGE":<json>}`;
//! see `guest/init`) — the same stream the host-side oracle reads. These tests
//! observe assertions there (via `Event::SerialLine`, captured by
//! [`common::capture_sink`]) and decode them back into [`Assertion`]s, covering
//! both the monitor and the `bedrock-assertions` wire format. The on-disk sink
//! the pipeline uses internally is an implementation detail and is never
//! touched.
//!
//! The monitor records two kinds of death, and these tests provoke both:
//!
//! - an `exec_died` event (message `"exec exit code is zero"`): container
//!   `bash` commands run as `podman exec <container> /bin/sh -c <cmd>` (see
//!   `guest/bedrock-io/bedrock-io.c`), so each one's death is one such event;
//! - a `died` event (message `"container <name> exit code is zero"`): a
//!   container's main process exiting, provoked here with a throwaway
//!   `podman run`.
//!
//! Without a VM every test skips, like the rest of the suite.

use bedrock_assertions::{Assertion, Condition};
use bedrock_lab::{BashTarget, Branch};
use bedrock_vm::ConsoleLine;

use crate::common;

/// Message the monitor records for a `podman exec` session death. Kept in sync
/// with `EXEC_DEATH_MSG` in `guest/workload-monitor/src/main.rs`.
const EXEC_DEATH_MSG: &str = "exec exit code is zero";

/// The journald `SYSLOG_IDENTIFIER` the assertion sink's lines carry. `guest/init`
/// pipes `/bedrock/assertions.jsonl` through `systemd-cat -t assertions`, so each
/// assertion reaches the serial console inside a journal record tagged this.
const ASSERTION_TAG: &str = "assertions";

/// Decode one serial line into an [`Assertion`] if it is an assertion record,
/// else `None`.
///
/// The runtime console carries one compact journald JSON object per line, which
/// [`ConsoleLine::parse`] classifies (see `guest/init`). An assertion is a
/// [`ConsoleLine::Journal`] record tagged [`ASSERTION_TAG`] whose `MESSAGE` is
/// the serialized [`Assertion`]. A line tagged `assertions` whose payload is not
/// valid `bedrock-assertions` JSON fails the test — the wire format the oracle
/// parses must hold.
fn assertion_from_serial(raw: &str) -> Option<Assertion> {
    let ConsoleLine::Journal { source, message } = ConsoleLine::parse(raw) else {
        return None;
    };
    if source != ASSERTION_TAG {
        return None;
    }
    let json = message.trim();
    Some(serde_json::from_str::<Assertion>(json).unwrap_or_else(|e| {
        panic!("`assertions` serial line is not a valid Assertion: {e}\njson: {json}")
    }))
}

/// Every assertion seen so far on `branch`'s serial log, decoded. A freshly
/// forked branch starts with none (the pipeline replays existing sink lines on
/// the boot branch, before the fork), so what shows up here is what this branch
/// provoked.
fn assertions_on_serial(branch: &Branch) -> Vec<Assertion> {
    common::capture_sink()
        .serial_lines(branch.id())
        .iter()
        .filter_map(|line| assertion_from_serial(line))
        .collect()
}

/// Advance the guest until an assertion matching `pred` appears on `branch`'s
/// serial log, then return it. The pipeline (monitor → journald → serial) is
/// asynchronous, so we poll, advancing virtual time, up to a generous budget
/// that is only ever hit on failure.
fn wait_for_assertion(
    branch: &mut Branch,
    what: &str,
    pred: impl Fn(&Assertion) -> bool,
) -> Assertion {
    let deadline = branch.current_time() + vt_dur!(20 s);
    loop {
        if let Some(found) = assertions_on_serial(branch).into_iter().find(|a| pred(a)) {
            return found;
        }
        assert!(
            branch.current_time() < deadline,
            "no assertion matching {what} reached the serial log within the budget",
        );
        branch.run_for(vt_dur!(200 ms)).expect("advance guest");
    }
}

/// Whether `a` is an `Always` exec-death record asserting `x == 0` for the
/// given observed exit `code` — the shape the monitor emits via
/// `always_eq!(exit_code, 0, …)` for a `podman exec` death.
fn is_exec_death(a: &Assertion, code: i128) -> bool {
    matches!(a, Assertion::Always(_))
        && a.data().message == EXEC_DEATH_MSG
        && a.condition() == Condition::Eq { x: code, y: 0 }
}

/// Whether `a` is an `Always` container-death record for container `name`
/// asserting `x == 0` for the given observed exit `code` — the shape the
/// monitor emits for a container's main process dying (a `died` event). The
/// message names the container, so it is distinct from an exec death.
fn is_container_death(a: &Assertion, name: &str, code: i128) -> bool {
    matches!(a, Assertion::Always(_))
        && a.data().message == format!("container {name} exit code is zero")
        && a.condition() == Condition::Eq { x: code, y: 0 }
}

#[test]
fn workload_monitor_records_clean_exec_exit() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("workload_monitor_records_clean_exec_exit");
    };

    let mut branch = ready.branch().expect("fork branch");

    // A clean container exec. bedrock-io runs it as `podman exec`, so its death
    // is an `exec_died` event the monitor records as a held always-zero invariant.
    let out = branch
        .bash(BashTarget::container("idle"), "exit 0", false)
        .expect("run clean exec");
    assert_eq!(out.exit_code, 0, "exec should exit 0");

    let recorded = wait_for_assertion(&mut branch, "a clean exec death", |a| is_exec_death(a, 0));
    assert!(
        recorded.holds(),
        "exit code 0 must satisfy the always-zero invariant: {recorded:?}",
    );
}

#[test]
fn workload_monitor_flags_failing_exec_exit() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("workload_monitor_flags_failing_exec_exit");
    };

    let mut branch = ready.branch().expect("fork branch");

    // A distinctive non-zero exit code, so our exec's record is unambiguous on
    // the serial log. A real workload fault surfaces exactly this way: as a
    // failed `Always`, with no container-specific test code.
    const FAIL_CODE: i128 = 42;
    let out = branch
        .bash(BashTarget::container("idle"), "exit 42", false)
        .expect("run failing exec");
    assert_eq!(out.exit_code, 42, "exec should exit 42");

    let recorded = wait_for_assertion(&mut branch, "a failing exec death", |a| {
        is_exec_death(a, FAIL_CODE)
    });
    assert!(
        !recorded.holds(),
        "a non-zero exec exit must violate the always-zero invariant: {recorded:?}",
    );
}

#[test]
fn workload_monitor_records_container_death() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("workload_monitor_records_container_death");
    };

    let mut branch = ready.branch().expect("fork branch");

    // Provoke the `died` branch of the monitor (a container's main process
    // dying, not a `podman exec`): run a throwaway container whose main process
    // exits with a distinctive non-zero code. It reuses the image the workload
    // already loaded, overriding the entrypoint so it just exits instead of
    // signalling ready. `--network none` keeps startup light (no netavark) and
    // `--rm` cleans it up; the `died` event fires before removal.
    const NAME: &str = "expiring-probe";
    const EXIT_CODE: i128 = 17;
    let out = branch
        .bash(
            BashTarget::host(),
            &format!(
                "podman run --rm --network none --name {NAME} --entrypoint /bin/sh \
                 bedrock/integration-tests-ready:latest -c 'exit {EXIT_CODE}'"
            ),
            false,
        )
        .expect("run throwaway container");
    assert_eq!(
        i128::from(out.exit_code),
        EXIT_CODE,
        "container main process should exit {EXIT_CODE}",
    );

    let recorded = wait_for_assertion(&mut branch, "the container death", |a| {
        is_container_death(a, NAME, EXIT_CODE)
    });
    assert!(
        !recorded.holds(),
        "a non-zero container exit must violate the always-zero invariant: {recorded:?}",
    );
}
