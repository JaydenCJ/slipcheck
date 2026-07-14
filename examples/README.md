# slipcheck examples

`fixtures/` contains six tiny, committed archives — one clean, five hostile.
They are inert bytes (nothing executes), built deterministically, and they
double as the corpus for the integration tests and `scripts/smoke.sh`.

| Fixture | What it demonstrates | Expected verdict |
|---|---|---|
| `clean.tar.gz` | A boring, well-formed package | exit 0, `clean` |
| `traversal.tar` | Entry named `../../etc/cron.d/backdoor` | `traversal` (critical) |
| `absolute.tar` | Entry named `/usr/local/bin/definitely-fine` | `absolute-path` (critical) |
| `symlink-escape.tar` | Symlink `build -> ../../target`, then a file written *through* it | `link-escape` + `link-indirection` (critical) |
| `setuid.tar` | `bin/helper` with mode `4755` | `setuid` (critical) |
| `sneaky.zip` | Central directory says `docs/readme.txt`, local header says `../../evil.sh`; plus an absolute symlink and a case collision | `name-mismatch`, `traversal`, `link-escape`, `case-collision` |

Scan them all at once:

```bash
cargo run --quiet -- scan examples/fixtures/*
```

Or reproduce a CI gate — extract only if slipcheck stays quiet:

```bash
slipcheck scan release.tar.gz --quiet && tar -xzf release.tar.gz -C build/
```

Machine-readable output for pipelines:

```bash
slipcheck scan examples/fixtures/sneaky.zip --json
```

Every fixture is a few hundred bytes; open them with `xxd` to see exactly
which header field carries the attack.
