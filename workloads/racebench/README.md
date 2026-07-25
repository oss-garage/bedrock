# RaceBench workload

A benchmark corpus for the concurrency-fuzz scheduler: real concurrent programs
with **pre-injected, self-observing concurrency bugs**. When a bug's specific
thread interleaving fires, the injected harness prints
`RaceBench crashes deliberately.` and `abort()`s (SIGABRT), recording the bug id
in a stat file. The crash is self-observable with **no external race detector**
(no TSan) - unlike the LLVM TSan test suite, whose races are silent without the
detector. This makes it a direct measure of whether the scheduler manufactures
the rare interleavings that trigger bugs.

Under bedrock (single vCPU + emulated TSC) the schedule is a pure function of the
getrandom stream, so a trigger reproduces from a fixed seed. Repro of a triggered
bug = `(target, input file, scheduler seed)`. Vary the seed across boots to
explore interleavings - the same fuzzing loop the concurrency-fuzz workload uses
for `queue.c`, but against real programs with ground-truth bugs.

## How it runs

Same contract as the concurrency-fuzz workload. The sched_ext fuzzing scheduler
is guest infrastructure loaded at boot (scx-init); `thread-fuzz` is bind-mounted
into the container by the guest (see `nix/podman-initrd.nix`). `run.sh` wraps
each target in `thread-fuzz`, which switches it into SCHED_EXT so the fuzzing
scheduler governs it. Nothing scheduler-specific is baked into this image.

```bash
./build.sh                                # build image -> images.tar (needs docker)
nix run .#test-racebench-fork-parent      # boot a held "parent" on the host
# then, in another shell, fork a re-seeded child off its printed vm_id:
BEDROCK_PARENT_ID=<vm_id> RDRAND_SEED=1 nix run .#test-racebench-fork-child
```

Runs are **fork-based**: one parent boots to the ready checkpoint and is held
there, then each child forks off it (copy-on-write) and re-seeds. Cold-booting a
fresh guest per seed is gone - the strict late-inject abort fires during early
boot, so the throwaway parent boot tolerates it (`BEDROCK_IGNORE_LATE_INJECT`)
while scored children run strict. See `scripts/` for the coverage driver; a child
runs the corpus once under one schedule. Most seeds will NOT trigger (a bug needs
its specific interleaving); a clean `rc=0` is the expected "no bug this seed"
outcome. `rc=134` (SIGABRT) means a bug fired; the `RACEBENCH_STAT` file records
which of the target's 20 injected bugs.

## Corpus

Three PARSEC compute kernels, RaceBench variant `.1` (20 injected bugs each):
`blackscholes`, `streamcluster`, `fluidanimate`. These were chosen because they
build from source with only a base toolchain (`gcc`/`g++`/`make`/libc) - no
third-party libraries - and run cleanly (canneal, and the SPLASH-2 targets which
need K&R compiler flags, were excluded on purpose). Each target's binary is
compiled **from source** by `fuzz/Dockerfile`; the prebuilt binaries shipped by
RaceBench are never used.

Bug count (`RACEBENCH_BUG_0`..`RACEBENCH_BUG_19` in each `racebench_bugs.h`):

| Target          | Injected bugs |
| --------------- | ------------- |
| `blackscholes`  | 20            |
| `streamcluster` | 20            |
| `fluidanimate`  | 20            |
| **Total**       | **60**        |

Any single boot fires at most a handful (each needs its own interleaving), so 60
is the full ground-truth space the scheduler tries to reach across seeds, not
what one run hits.

Only variant `.1` of each target is used. Upstream ships five variants per
program (`blackscholes.1`..`blackscholes.5`); a variant is a different random
injection instance of the *same* program (a different set of 20 bugs at
different sites), so `.2`..`.5` would add bug diversity in code we already build,
while a new program name (e.g. `pigz`) adds new concurrency structure.

### Bug types

We do **not** have a per-bug type label: upstream RaceBench does not tag bugs by
category, and nothing in the fetched files does either. All 20 bugs per target
are the same fundamental kind: a hidden state machine (the `rb_stateN` struct of
counters plus a mutex) whose code is spliced into the real program across
threads. It reads the input file (`rb_input`) and shared racing variables, and
calls `racebench_trigger(id)` when a data invariant breaks under a specific
interleaving (see the `if (!(x == y)) racebench_trigger(N)` checks in each
target's instrumented source). So every bug is an interleaving-dependent
invariant violation (data-race / atomicity- / order-violation style) that aborts
via SIGABRT: there are no deadlock or livelock bugs, and `trigger_num[i]` records
only *which* id fired, not a type.

To add more later: add another target's name to the `TARGETS` list in
`fuzz/fetch_targets.sh` (it must exist upstream as `<name>.1/code`) and to the
loops in `fuzz/Dockerfile` and `fuzz/run.sh`, then confirm it builds and runs
clean.

## Provenance and licensing

The target corpus is **not vendored**. `fuzz/fetch_targets.sh` downloads it from
RaceBench at build time (called by `build.sh`), pinned to a single commit:

- Data:    https://github.com/rb130/RaceBenchData  commit `cb79cc5` (2023-04-03)
- Tooling: https://github.com/rb130/RaceBench      commit `8c4b3e8`

The pinned commit lives in `fetch_targets.sh` (`RB_DATA_COMMIT`); bump it there
and update the hash above to move the corpus. The fetch is a partial + sparse
clone that pulls only each target's `.1/code` tree and three input files. It
never downloads upstream's prebuilt binaries (`<name>.1/install/`): those are
explicitly untrusted, and every target is compiled from source by
`fuzz/Dockerfile`. The extra source files a full `code/` tree carries (SIMD
variants, Windows project files, sample data) are ignored by the build's
Makefiles and never reach the image.

Licenses:

- The RaceBench harness (`racebench.c`, `racebench.h`, `racebench_bugs.c`,
  `racebench_bugs.h` under each `code/`) is licensed under **Mulan PSL v2** - see
  `LICENSE.racebench` (full text: http://license.coscl.org.cn/MulanPSL2).
- Each target's underlying program is from the **PARSEC** benchmark suite; the
  original copyright notice is retained at `fuzz/targets/<name>/code/src/COPYRIGHT`
  (blackscholes, fluidanimate: Intel Corp.; streamcluster: Princeton University).
