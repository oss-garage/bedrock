# contrib

Standalone helper scripts for development and analysis. None are required to
build or run the hypervisor; they're convenience tooling.

| Script                   | Purpose                                                                                                                                                                                                                       |
| ---                      | ---                                                                                                                                                                                                                           |
| `check_stack.py`         | Parse `objdump` output of `bedrock.ko` and report per-function and worst-case call-chain stack usage, to keep the module under the kernel's 8KB stack limit. Run in CI via `nix flake check` (`check-stack`).                 |
| `determ-divergence.py`   | Pinpoint where a divergent VM run first differs from a reference run: finds the last matching / first divergent deterministic exit and dumps the non-deterministic exits in the TSC window between them.                      |
| `pebs-skid-histogram.py` | Plot the distribution of PEBS-induced EPT-violation skids (TSC ticks between where a PEBS violation fired and the armed target). Precise PEBS should skid 0–1; anything else points to hardware imprecision or an arming bug. |
| `setup-skills.sh`        | Download the gitignored source trees the Claude skills search: Linux kernel source (`linux`) and the pinned FreeBSD source tree (`bhyve`). (The `sdm` skill's PDFs are committed, so they need no setup.) Idempotent; run with no args for both or name a skill. Runs automatically on first use of the `linux`/`bhyve` skills via the `PreToolUse` hook in `.claude/settings.json`. |

Each script is self-documenting — run with `--help` or read the module
docstring for usage.
