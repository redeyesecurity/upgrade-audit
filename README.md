# upgrade-audit

Check what actually changed in a dependency **before** you install it.
**npm, PyPI and crates.io.**

No dependencies, no install, no account. One stdlib Python file.

```sh
python3 upgrade-audit.py npm   keyv     4.5.4   6.0.0
python3 upgrade-audit.py pypi  requests 2.31.0  2.32.3
python3 upgrade-audit.py cargo serde    1.0.200 1.0.210
```

## Why this exists

On 4 August 2026 a maintainer account behind the `keyv` and `cacheable` npm
namespaces was compromised. Eleven packages went out with a `preinstall` hook
that downloaded a 728 KB credential stealer, and a worm carried the same payload
to 434 more packages across 1,381 versions. `eslint` depends on
`file-entry-cache`, which depends on `flat-cache`, which depends on `keyv`, so
the blast radius was enormous and almost nobody installed these on purpose.

The detail worth internalising: **the worm republished through npm OIDC trusted
publishing, so the malicious versions carried valid sigstore provenance.** The
signature was real. It attested that a build produced the artifact, not that the
artifact was safe. If your supply-chain policy is "require provenance", this
campaign satisfied it.

So this tool ignores signatures and looks at the code.

## The one check that matters

Every ecosystem has a place where a package runs arbitrary code on the machine
installing it. That is where these attacks live, and it is what `CRITICAL` looks at:

| Ecosystem | Install-time execution |
|---|---|
| npm | lifecycle scripts (`preinstall`, `install`, `postinstall`) |
| PyPI | `setup.py` in an sdist, which executes at build time |
| cargo | `build.rs`, which compiles and runs before your crate does |

A hook that the previous version did not have is `CRITICAL`. That single rule
would have caught the keyv compromise, the `event-stream` incident, and most of
what came before them.

## What else it checks

It pulls both artifacts from the registry and diffs them.

| Severity | Check | Why |
|---|---|---|
| `HIGH` | New executable file at the package root | `setup.mjs` and `Math_Symbol.js` both landed here |
| `HIGH` | Large new file (>200 KB) | The stealer was 728 KB in a tiny cache library |
| `HIGH` | High-entropy new code | Packed or obfuscated payloads |
| `HIGH` | New or changed code referencing credentials, IMDS, or process execution | `~/.npmrc`, `~/.aws/credentials`, `169.254.169.254`, `child_process` |
| `HIGH` | Publisher identity changed | Account takeover, or a legitimate move to CI publishing. Worth a look either way |
| `MEDIUM` | Version younger than the cooldown | See below |

Behaviour checks run on code only. Scanning READMEs made every package that
mentions `bun.sh` a finding.

## The cooldown matters more than the clever checks

Socket flagged the malicious `keyv` release about six minutes after publication,
and npm pulled the versions within hours. **Anyone who refused to install
versions younger than a few days was never exposed**, with no analysis at all.

```sh
python3 upgrade-audit.py npm --lockfile package-lock.json --check-updates --cooldown 7
```

If you adopt one thing from this repository, adopt the cooldown, not the tool.

## Dependencies with no lockfile

A lockfile is what makes "audit the diff" possible: it records the exact version
you had, so there is something to compare against. Plenty of Python projects
depend on ranges instead (`boto3>=1.34`) and commit no lockfile at all. Those
projects have a blind spot that a pull-request check cannot see, because the
version is chosen at install time and **no file in the repository changes when a
new release lands**. A compromised release is picked up by the next build.

For those, resolve first and audit what would actually be installed:

```sh
python3 upgrade-audit.py pypi --resolve requirements.txt --cooldown 3
python3 upgrade-audit.py pypi --resolve .            # a pyproject.toml project
```

This asks pip what it would install (`--dry-run --report`, nothing is
installed), then audits every resolved release published inside the cooldown
window, diffing it against the release before it. Old, settled versions are
skipped, so a run costs a couple of downloads rather than hundreds.

Extras are resolved too, one group at a time. Projects park the interesting
dependencies there (a lake sink's `boto3` and `pyarrow` under `[parquet]`, not
in the base list), and resolving the bare project audits almost nothing. Going
one at a time means a `[windows]` extra pinning `pywin32`, which will never
resolve on a Linux runner, costs that group rather than the whole audit.

It is worth seeing what this prints on a real repository:

```
  resolved 11 packages; auditing any published in the last 9 days
  HIGH      boto3  1.43.62 -> 1.43.63
      [HIGH] setup.py changed, and it executes at build/install time from an sdist
      [MEDIUM] published 0d ago, under the 3d cooldown
```

A range resolved to a release published that same day. Nothing was wrong with
it, but that is the window an account takeover lives in, and the repository's
own history gave no indication anything had moved.

## Usage

```sh
# one upgrade
python3 upgrade-audit.py npm keyv 4.5.4 5.6.0

# everything in a lockfile that has a newer version available
python3 upgrade-audit.py npm --lockfile package-lock.json --check-updates

# a batch, machine readable, for CI
python3 upgrade-audit.py npm --batch pkgs.txt --json --fail-on CRITICAL
```

`pkgs.txt` is `name old_version new_version`, one per line.

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `HIGH`),
`2` usage or network error.

## In CI

Block on `CRITICAL`, warn on `HIGH`. A new install hook is nearly always worth a
human look; a publisher change often is not, because projects legitimately move
to CI publishing. `flat-cache` really did move from `jaredwray` to GitHub Actions
between 4.0.1 and 6.1.23, and that trips a `HIGH` correctly.

```yaml
- name: Audit dependency changes
  run: |
    python3 upgrade-audit.py npm --batch changed.txt --fail-on CRITICAL
```

## Expect some benign HIGH findings

Real examples from live packages, all correct and all harmless:

- `flat-cache` moved from an individual maintainer to GitHub Actions publishing, which trips `publisher-change`
- `serde` changed its `build.rs` between 1.0.200 and 1.0.210, which trips `changed-install-hook`
- `requests` restructured into `src/`, so files look new

This is why the recommended policy is **block on `CRITICAL`, warn on `HIGH`**. A
new install hook is nearly always worth a human look. A new publisher usually is
not. A tool that pretends it has no false positives is one nobody keeps running.

## What this does not do

It is not a scanner and it will not out-detect Socket, Aikido or Wiz, who did the
primary analysis on this campaign. It answers one narrower question: *is there
anything about this specific version bump that a human should look at before it
reaches a build runner that has credentials on it.*

It also cannot see a payload that arrives through a transitive dependency you did
not audit, or one that behaves normally at install time and waits. Pair it with a
cooldown, `--ignore-scripts`, and monitoring on your build runners: the loud
signals after install are IMDS access, an unexpected runtime appearing, and
egress from CI to somewhere that is not your registry.

## Background

- [Shai-Hulud Returns: keyv, cacheable and 434 More npm Packages Compromised](https://threat-intelligence.redeyesecurity.com/blog/keyv-cacheable-npm-supply-chain-shai-hulud-2026)
- [Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack) ·
  [Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack) ·
  [Socket](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain)

MIT licensed. Built by [RedEye Security](https://redeyesecurity.com).
