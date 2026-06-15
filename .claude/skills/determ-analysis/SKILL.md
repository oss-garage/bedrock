---
name: determ-analysis
description: Analyze bedrock determinism test output directories on the remote machine. Invoke for checking test results, finding failures, comparing runs, and diagnosing divergences.
---

You are an expert at analyzing bedrock hypervisor determinism test results. The test data lives on a remote machine and must be accessed via SSH.

## Remote Access

The remote host is configured in the `.env` file at the project root (see `.env.example` for the format). Read `REMOTE_HOST` from `.env` before running commands.

All commands must be run via `ssh $REMOTE_HOST '<command>'`. Test output directories are typically under `~/workspace/determ-tests/` on the remote machine.

## Test Output Directory Structure

The `bedrock-determinism` binary creates a timestamped subdirectory under the workdir (e.g. `vmlinux_3072mb_vt2490.0s_n1000000_20260312-155249/`). Only run-001 (the reference) and divergent runs are kept — matching runs are deleted immediately after comparison. A successful test directory contains only run-001.

```
<test-dir>/
├── config.txt                  # Test configuration parameters
├── summary.txt                 # Per-run results and divergence details
├── run-001/                    # Reference run (always kept)
│   ├── command.txt             # Exact bedrock-cli command and copy-pasteable version
│   ├── status.txt              # "exit_code: Some(0)\nsuccess: true"
│   ├── stdout.txt              # Guest console output + exit handler stats table
│   ├── stderr.txt              # bedrock-cli log messages
│   ├── events.jsonl            # Unified event stream (JSONL, one record per line)
│   └── exit-stats.json         # Exit type counts (ExitStats JSON)
├── run-NNNNNN/                 # Divergent runs only (moved from temp dir)
│   └── (same structure as run-001)
```

**Important**: Matching (non-divergent) runs are deleted after comparison. Only run-001 and divergent runs remain in the test directory. The run numbering is zero-padded to 3 digits (`run-001` through `run-999`), then plain (`run-1000`, etc.).

## Event Stream (`events.jsonl`)

`bedrock-cli` writes one JSONL file, `events.jsonl`, via `--events-jsonl <path>`. It is the
**unified event stream**: a time-ordered log of every record whose kind is captured.
`--event-categories` selects the non-exit kinds; `Exit` records are gated by
`--exit-capture <mode>` (and `--single-step`). The determinism binary captures only `Exit`
records (it passes `--exit-capture all` / `at-shutdown` / `checkpoints:N`), so for
determinism analysis every line is an exit record — but the same file can also carry
`serial`, `inject`, `randomness`, and `io_channel` records when those categories are enabled.

Each line is a flat JSON object: a small envelope plus the kind-specific body under `data`.

```json
{"seq": 1234, "tsc": 987654321, "real_tsc": 140737488355328, "deterministic": true,
 "kind": "exit", "data": { ... }}
```

**Envelope fields (present on every record):**
- `seq` (u64) — monotonic sequence number; total order tie-breaker for records sharing a `tsc`
- `tsc` (u64) — emulated (deterministic) TSC at emit time; the comparison time axis
- `real_tsc` (u64) — host RDTSC at emit time; **non-deterministic**, for wall-clock correlation only, never compared
- `deterministic` (bool) — whether the record participates in run-vs-run comparison
- `kind` (string) — `exit`, `serial`, `inject`, `randomness`, `io_channel`, or `unknown`
- `data` — the kind-specific body (shape depends on `kind`)

There is no separate non-determ file: deterministic and non-deterministic exits are
interleaved in `events.jsonl` and distinguished by the top-level `deterministic` flag.
`contrib/determ-divergence.py` does the split itself (keep `kind == "exit"`, partition the
`data` bodies on `deterministic`).

### Exit record `data` fields

For `kind: "exit"`, `data` holds the exit snapshot (the `ExitRecord` body):

**Exit info:**
- `tsc` (u64) - Emulated TSC value at exit
- `exit_reason` (u32) - VM exit reason code
- `flags` (u32) - Bit 0 = deterministic exit (mirrors the envelope `deterministic` flag)
- `exit_qualification` (u64) - Context-dependent qualification value

**Guest registers:**
- `rax`, `rcx`, `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi` (u64)
- `r8` through `r15` (u64)
- `rip` (u64) - Instruction pointer
- `rflags` (u64)

**Device state hashes:**
- `memory_hash` (u64) - Hash of guest physical memory (0 if `--no-memory-hash`)
- `apic_hash` (u64) - Local APIC state
- `serial_hash` (u64) - Serial port state
- `ioapic_hash` (u64) - I/O APIC state
- `rtc_hash` (u64) - Real-time clock state
- `mtrr_hash` (u64) - MTRR state
- `rdrand_hash` (u64) - RDRAND/RDSEED state

## Exit Reason Codes

| Code | Name | Deterministic | Notes |
|------|------|:---:|-------|
| 0 | EXCEPTION_NMI | no | |
| 1 | EXTERNAL_INTERRUPT | no | Host timer ticks, IPIs |
| 10 | CPUID | yes | |
| 12 | HLT | yes | |
| 16 | RDTSC | yes | Common in tight loops |
| 28 | CR_ACCESS | yes | |
| 30 | IO_INSTRUCTION | yes | |
| 31 | MSR_READ | yes | |
| 32 | MSR_WRITE | yes | |
| 36 | MWAIT | yes | Guest idle (expected) |
| 39 | MONITOR | yes | |
| 48 | EPT_VIOLATION | no | CoW faults, memory access |
| 51 | RDTSCP | yes | |
| 55 | XSETBV | yes | |
| 57 | RDRAND | yes | |
| 61 | RDSEED | yes | |
| 258 | VMCALL_SHUTDOWN | yes | Guest initiated shutdown |
| 260 | VMCALL_SNAPSHOT | yes | |

## Exit Capture Modes

`Exit` records are part of the event stream; the determinism test binary chooses *which*
exits become records via these flags (it lowers them to bedrock-cli's `--exit-capture` /
`--single-step`):
- *(no flag)* — one record at VM shutdown (the default)
- `--checkpoint-interval INTERVAL` — periodic snapshots every INTERVAL emulated-TSC ticks
- `--all-exits` — every exit is captured (large event streams)

Additional modifiers:
- `--no-memory-hash` — skip memory hashing (memory_hash will be 0)
- `--capture-exits-after-tsc TSC` — only start capturing exits after this TSC value
- `--single-step START-END` — MTF single-stepping in a TSC range (TscRange capture)
- `--intercept-pf` — trap guest #PF exceptions

## Comparison Logic

The determinism binary compares runs in two ways:
1. **Log entries**: Field-by-field comparison of all fields (TSC, registers, hashes). For checkpoint/all-exits mode, finds the first divergent entry index.
2. **Exit stats**: Compares deterministic exit type counts only. Non-deterministic exits (external_interrupt, exception_nmi, ept_violation) are excluded.

A run is marked DIVERGENT if either comparison finds a difference.

## Analysis Workflow

### 1. Read Configuration

```bash
ssh $REMOTE_HOST 'cat ~/workspace/determ-tests/<dir>/config.txt'
```

Note the key parameters: `runs`, `parallel`, `stop_at_tsc`/`stop_at_vt`, `checkpoint_interval`, `all_exits`, `parent_id`, `no_memory_hash`, `intercept_pf`.

### 2. Check Summary (with caveat)

```bash
ssh $REMOTE_HOST 'cat ~/workspace/determ-tests/<dir>/summary.txt'
```

**WARNING**: The summary.txt may be stale (from an older test run that reused the same directory). Always verify by cross-referencing the number of runs in the summary against the actual run directories.

The summary format is:
```
Run 001: REFERENCE
Run 002: OK
Run 003: DIVERGENT
...
RESULT: DIVERGENCE DETECTED  (or ALL RUNS IDENTICAL)
```

### 3. Count Actual Runs and Find Divergent Runs

Since matching runs are deleted, the remaining run directories (besides run-001) are the divergent ones:

```bash
# List all run directories (these are run-001 + divergent runs only)
ssh $REMOTE_HOST 'find ~/workspace/determ-tests/<dir> -maxdepth 1 -type d -name "run-*" | sort'
```

### 4. Analyze Divergent Runs

For each divergent run, examine artifacts:

```bash
# Status
ssh $REMOTE_HOST 'cat ~/workspace/determ-tests/<dir>/run-NNNNNN/status.txt'

# Diff guest console output (shows crash messages, extra output, etc.)
ssh $REMOTE_HOST 'diff ~/workspace/determ-tests/<dir>/run-001/stdout.txt ~/workspace/determ-tests/<dir>/run-NNNNNN/stdout.txt'

# Full guest console output if diff is large or you need more context
ssh $REMOTE_HOST 'cat ~/workspace/determ-tests/<dir>/run-NNNNNN/stdout.txt'

# Hypervisor logs
ssh $REMOTE_HOST 'cat ~/workspace/determ-tests/<dir>/run-NNNNNN/stderr.txt'

# Event stream sizes (total records; exit records dominate in determinism runs)
ssh $REMOTE_HOST 'wc -l ~/workspace/determ-tests/<dir>/run-NNNNNN/events.jsonl ~/workspace/determ-tests/<dir>/run-001/events.jsonl'
```

### 5. Find Divergence Point

Use the `determ-divergence.py` script to analyze divergent runs. The script must be copied to the remote machine first.

First run `just sync` to ensure the remote has the latest scripts, then:

```bash
# Run divergence analysis
ssh $REMOTE_HOST 'python3 $REMOTE_DIR/contrib/determ-divergence.py ~/workspace/determ-tests/<dir> run-NNNNNN'

# With more context exits before divergence
ssh $REMOTE_HOST 'python3 $REMOTE_DIR/contrib/determ-divergence.py ~/workspace/determ-tests/<dir> run-NNNNNN --context 20'

# Widen the non-determ exit search window beyond the divergence point
ssh $REMOTE_HOST 'python3 $REMOTE_DIR/contrib/determ-divergence.py ~/workspace/determ-tests/<dir> run-NNNNNN --nondeterm-window 50000'
```

The script outputs:
1. **Divergence point**: The exact deterministic exit index where runs diverge
2. **Context exits**: The last N matching exits before divergence
3. **Detailed comparison**: Full register and hash state for the last matching and first divergent exits, plus TSC delta analysis
4. **Non-determ exits in the divergence window**: All non-deterministic exits (EPT violations, external interrupts, NMIs) between the last matching and first divergent deterministic exits
5. **Non-determ exit summary**: Per-type counts for the full run

### Understanding the output

The first divergent deterministic exit tells you that **something between it and the prior exit caused the guest to execute differently**. The non-determ exits in that TSC window are the key suspects:

- **External interrupts** (exit=1): Host interrupts cause VM exit/re-entry cycles that can shift the hardware instruction counter, affecting the emulated TSC
- **EPT violations** (exit=48): CoW faults are usually benign but can cause collateral TLB invalidation leading to spurious guest #PFs
- **NMIs** (exit=0): Similar to external interrupts

If one run has a non-determ exit in the window that the other doesn't, that's likely the trigger. The TSC delta in the divergent exit shows the magnitude of the instruction count shift.

## Reporting

When reporting results, always include:
1. Total runs and failure count
2. Test configuration (parallelism, memory, stop condition, logging mode)
3. For each divergent run: the divergence point, differing fields, TSC shift, non-determ exits in the window
4. Guest consequences (crash details from stdout.txt if any)
