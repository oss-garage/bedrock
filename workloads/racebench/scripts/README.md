# RaceBench scripts

Helper scripts for the RaceBench workload.

## `baseline.sh` - native (no-bedrock) baseline

Records how many of the 60 injected bugs the host's **stock scheduler** reaches
**without bedrock** (no `thread-fuzz`, no deterministic TSC/getrandom). This is
the control to compare bedrock's concurrency-fuzz coverage against: bugs bedrock
reaches that this baseline never does are the scheduler's payoff.

It runs the *identical* from-source binaries from the workload image, inside a
container on the bare host, looping each target until coverage plateaus, and
prints the union of triggered bug ids per target plus a `TOTAL /60`.

### 1. Build and load the image

The script runs the binaries from the `bedrock/racebench:latest` image, so build
it and load it into the local container runtime first. From the workload dir
(one level up from here):

```bash
cd ..
./build.sh                       # builds targets FROM SOURCE -> images.tar
docker load -i images.tar        # load the archive into docker
```

`build.sh` defaults to `docker` (`DOCKER=docker`); it fetches Debian packages
(gcc/g++/make) during the image build, so it needs network access.

> **podman note:** `podman` is not installed on this host, so use `docker`
> (the daemon is reachable here). Everything below assumes docker. If you ever
> run somewhere with podman instead, pass `RUNTIME=podman` to `baseline.sh` and
> use `podman load -i images.tar` above.

### 2. Run the baseline

Capture each run to its own file with `tee` (so you see it live and keep the
log). Record **both** CPU configs - they answer different questions:

```bash
cd scripts

# single-core: apples-to-apples with bedrock's single vCPU (isolates the
# scheduler-fuzzing contribution from the host's parallelism)
CPUSET=0 ./baseline.sh 2>&1 | tee "baseline-$(hostname -s)-$(date +%F)-cpuset0.txt"

# all cores: the realistic "what a normal test run catches" host baseline
./baseline.sh 2>&1 | tee "baseline-$(hostname -s)-$(date +%F)-allcores.txt"
```

This produces e.g. `baseline-galactus-2026-07-07-cpuset0.txt` and
`...-allcores.txt`. The filename encodes the CPU config (the dimension being
contrasted), the host (baselines are host-specific: core count, scheduler, CPU),
and the date (so re-runs accumulate instead of clobbering).

`2>&1` matters: the header line goes to stdout and runtime errors (e.g.
image-not-found) go to stderr - you want both in the log.

### Knobs (environment variables)

| Var       | Default                  | Meaning                                              |
| --------- | ------------------------ | ---------------------------------------------------- |
| `CPUSET`  | *(empty = all cores)*    | `CPUSET=0` pins to one core (`--cpuset-cpus 0`).      |
| `PLATEAU` | `500`                    | Stop a target after this many runs add no new bug.   |
| `MAX`     | `20000`                  | Hard cap on attempts per target.                     |
| `RUNTIME` | `docker`                 | Container runtime (`podman` if available).            |
| `IMAGE`   | `bedrock/racebench:latest` | Image to run the binaries from.                    |

### Reading the output

```
blackscholes: reached 3/20 in 812 runs -> bug_ids: 2 7 14
streamcluster: reached 1/20 in 611 runs -> bug_ids: 9
fluidanimate: reached 0/20 in 500 runs -> bug_ids:
TOTAL native baseline: 4/60
```

`reached N/20` is that target's bug-id union across all attempts; `TOTAL /60` is
the baseline number. Expect it to be **low** - many RaceBench bugs need a narrow
interleaving the stock scheduler almost never hits even over thousands of tries,
which is exactly what makes bedrock's coverage number meaningful.

## `bedrock.sh` - bedrock coverage (the payoff number)

The counterpart to `baseline.sh`: how many of the 60 bugs the concurrency-fuzz
scheduler reaches **under bedrock** (single vCPU, emulated TSC, `thread-fuzz`
SCHED_EXT). Run both and compare `TOTAL`s: bugs bedrock reaches that the native
baseline never does are the scheduler's payoff.

Under bedrock each schedule is **deterministic** - the getrandom stream that
drives the fuzzing scheduler is a pure function of the rdrand seed. So coverage
comes from **sweeping the seed**, not from re-running one seed. Runs are now
**fork-based**: `bedrock.sh` boots ONE parent guest to the ready checkpoint
(`test-racebench-fork-parent`, holding at `--wait`) and forks a re-seeded child
off it per seed (`test-racebench-fork-child`, child `i` uses `SEED_BASE + (i-1)`).
Cold-booting a fresh guest per seed is gone: the strict late-inject abort fires
during early boot, so the throwaway parent boot tolerates it
(`BEDROCK_IGNORE_LATE_INJECT`) while scored children run strict and a late inject
inside a real schedule aborts (surfaced as a `LATE-INJECT ABORT`). The driver
unions the triggered `bug_ids` per target with the same `PLATEAU`/`MAX` plateau
semantics as `baseline.sh` so the two numbers are directly comparable.

Because it is deterministic, this sweep needs **no reps**: re-running the same
`(BOOT_SEED, child-seed range)` reproduces byte-identical coverage (that is the
whole point). The baseline needs reps only because the host scheduler is
nondeterministic. The repro of any triggered bug is
`(target, input file, boot_seed, child_seed)`.

### 1. Prerequisites

Unlike `baseline.sh` (which only needs docker), the bedrock scripts boot a real
guest through `/dev/bedrock`, so they must run **on the bare-metal host where the
bedrock module is loaded** (e.g. galactus) - not in a plain checkout or a VM
without VMX. Both `bedrock.sh` and `bedrock_reps.sh` share these prerequisites.

1. **bedrock module loaded**, with its char device present:

   ```bash
   lsmod | grep bedrock       # module present
   ls -l /dev/bedrock         # char device present
   ```

   If missing, load the module built for this host's kernel (the module and
   kernel must match - same version, `.config`, and rustc):

   ```bash
   sudo insmod bedrock.ko     # from wherever the module was built for this host
   ```

   Building/booting the matching host kernel + module is the host-kernel
   workflow, out of scope for these scripts; do that first if the checks above
   fail.

2. **`nix` on `PATH`** - the scripts wrap the flake apps
   `nix run .#test-racebench-fork-parent` / `.#test-racebench-fork-child`, run
   from the repo root (the scripts `cd` there for you). The guest kernel it boots
   already has sched_ext + BTF baked in.

3. **Workload image built** - same `images.tar` the baseline uses:

   ```bash
   cd .. && ./build.sh        # -> workloads/racebench/images.tar (needs docker + network)
   ```

Sanity-check one parent boot + one fork before launching a long sweep:

```bash
PLATEAU=1 MAX=1 ./bedrock.sh    # boot the parent, fork one child, score it
```

You should see the parent reach `vm_id=N`, then a `<target>: BUG TRIGGERED ...`
or `<target>: no trigger this seed` line per target. A clean run means the
prerequisites are satisfied.

### 2. Run it

```bash
cd scripts

# smoke-test the pipeline first (minutes, not hours)
PLATEAU=20 MAX=100 ./bedrock.sh 2>&1 | tee "bedrock-$(hostname -s)-$(date +%F)-smoke.txt"

# the real number: matches the baseline's PLATEAU=500. LONG - run detached:
#   tmux new -s bedrock   # paste; detach with Ctrl-b d
./bedrock.sh 2>&1 | tee "bedrock-$(hostname -s)-$(date +%F).txt"
```

The filename mirrors the baseline's (host + date), minus the CPU-config tag:
bedrock is always single vCPU, so its apples-to-apples control is the baseline's
**`cpuset0`** file.

> **Cost:** a boot is far heavier than a native run (it boots a podman guest,
> then runs all three targets), so `PLATEAU=500` is many hours. Validate at
> `PLATEAU=20` first, then commit to the full run.

### Knobs (environment variables)

| Var         | Default | Meaning                                                  |
| ----------- | ------- | -------------------------------------------------------- |
| `SEED_BASE` | `1`     | First rdrand seed; boot `i` uses `SEED_BASE + (i-1)`.    |
| `PLATEAU`   | `500`   | Stop a target after this many boots add no new bug.      |
| `MAX`       | `20000` | Hard cap on total boots.                                 |

### Reading the output

Same format as the baseline (so they line up), with `boots` in place of `runs`:

```
blackscholes: reached 6/20 in 1240 boots -> bug_ids: 2 5 7 11 14 18
streamcluster: reached 3/20 in 1240 boots -> bug_ids: 4 9 15
fluidanimate: reached 2/20 in 1240 boots -> bug_ids: 1 12
TOTAL bedrock coverage: 11/60
```

Compare `TOTAL bedrock coverage: X/60` against the single-core baseline's
`TOTAL native baseline: N/60`. The gap `X - N` is what the fuzzing scheduler buys
you: interleavings the stock scheduler never manufactures.

## `bedrock_reps.sh` - coverage spread across seed windows

Runs `bedrock.sh` `REPS` times and saves each to `bedrock-<host>-<date>-run<NN>.txt`,
the counterpart to `baseline_reps.sh`. The **reason for reps differs**, though:
`baseline_reps.sh` reruns the same config to average out the host scheduler's
nondeterminism, but bedrock has none - rerunning the same seed range reproduces
byte-identical coverage, so plain reps would just write `REPS` identical files.

So each rep gets a **disjoint seed window** instead: rep `i` sweeps
`[1 + (i-1)*MAX, ...)`, non-overlapping because one `bedrock.sh` run boots at most
`MAX` times. The reps then answer a real question: is the coverage number stable
across independent seed windows, or does it depend on which seeds you swept?

Same prerequisites as `bedrock.sh` above (module loaded, `/dev/bedrock`, `nix`,
`images.tar`) - this just calls it in a loop.

```bash
cd scripts
tmux new -s bedrock-reps            # LONG job: each rep is a full plateau sweep

./bedrock_reps.sh                   # 10 reps, disjoint windows (default)
REPS=5 PLATEAU=100 ./bedrock_reps.sh
```

| Var       | Default | Meaning                                                     |
| --------- | ------- | ----------------------------------------------------------- |
| `REPS`    | `10`    | Number of reps (each a disjoint seed window).               |
| `MAX`     | `20000` | Boots per rep, and the per-rep seed stride (keeps windows disjoint). |
| `PLATEAU` | `500`   | Passed through to `bedrock.sh`.                             |

Each rep's `TOTAL` is a coverage sample from an independent seed budget; a tight
cluster across reps means the number is seed-robust, a wide spread means coverage
is still climbing and you want a larger `PLATEAU` (or to union the reps).

## Monitoring progress

`bedrock.sh` emits **one progress line per boot to stderr**, so a long sweep is
never silent. The final `reached .../TOTAL` summary goes to stdout; only the
`BUG TRIGGERED` / `no trigger` lines are parsed, not the per-boot `bedrock-cli`
exit-stats block (that is captured only to grep, then discarded). A progress line
looks like:

```
boot 42 seed 42: coverage 8/60; slowest-plateau 137/500 NEW: blackscholes+{5 11}
```

- `coverage N/60` - running union across all targets so far.
- `slowest-plateau M/PLATEAU` - `min(noNew)` across targets; the sweep ends when
  it reaches `PLATEAU`. It **resets to 0** whenever any target finds a new bug
  (a new bug restarts the "no-new streak"), so watching it climb toward `PLATEAU`
  is the ETA signal.
- `NEW: <target>+{ids}` - only present on boots that found a new bug.
- `WARNING ... no OK marker` - a boot that did not finish cleanly (e.g. module
  unloaded); investigate rather than let it silently pad the plateau.

Since the documented invocation redirects `2>&1 | tee <file>`, both streams land
in the log, so monitor a live run with:

```bash
tail -f bedrock-<host>-<date>.txt              # single sweep
tail -f bedrock-<host>-<date>-run<NN>.txt      # the active rep (files appear per rep)
tmux attach -t bedrock-reps                    # or watch the whole batch
```

**Estimating runtime.** A boot is ~10-15s wall clock (it boots a podman guest,
then runs all three targets), so `PLATEAU=500` is a floor of ~500 boots even for
a zero-coverage target: on the order of ~2h **per rep**, and 10 reps is most of a
day. Use a smaller `PLATEAU` (and the `-smoke` run) to size it on your host first.
