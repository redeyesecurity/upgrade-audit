# npm-upgrade-audit

Check what actually changed in an npm dependency **before** you install it.

No dependencies, no install, no account. One stdlib Python file.

```sh
python3 npm-upgrade-audit.py keyv 4.5.4 6.0.0
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

## What it checks

It pulls both tarballs from the registry and diffs them.

| Severity | Check | Why |
|---|---|---|
| `CRITICAL` | A lifecycle script (`preinstall`, `install`, `postinstall`) the previous version did not have | The mechanism behind nearly every npm supply-chain attack, including this one |
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
python3 npm-upgrade-audit.py --lockfile package-lock.json --check-updates --cooldown 7
```

If you adopt one thing from this repository, adopt the cooldown, not the tool.

## Usage

```sh
# one upgrade
python3 npm-upgrade-audit.py keyv 4.5.4 5.6.0

# everything in a lockfile that has a newer version available
python3 npm-upgrade-audit.py --lockfile package-lock.json --check-updates

# a batch, machine readable, for CI
python3 npm-upgrade-audit.py --batch pkgs.txt --json --fail-on CRITICAL
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
    python3 npm-upgrade-audit.py --batch changed.txt --fail-on CRITICAL
```

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
