#!/usr/bin/env python3
"""Audit an npm upgrade BEFORE you install it.

Written after the 2026-08-04 keyv / cacheable compromise, where a maintainer
account takeover put a credential stealer inside packages that sit underneath
eslint. The malicious versions were live for hours and carried valid sigstore
provenance, so "is it signed" answered the wrong question.

This does not try to out-detect a scanning vendor. It answers a narrower and
more useful question: *is there anything about this specific version bump that
a human should look at before it reaches a build runner with credentials on it.*

It compares the version you have against the version you are about to install,
pulling both tarballs straight from the registry, and reports:

  CRITICAL  a lifecycle script (preinstall/install/postinstall) that the
            previous version did not have. This is the mechanism nearly every
            npm supply-chain attack has used, including this one.
  HIGH      new files at the package root, large new files, high-entropy blobs,
            or a publisher who has not published this package before.
  MEDIUM    the version is younger than the cooldown, unusual size growth,
            a major jump with no repository field.

Stdlib only, no install required:

    python3 npm-upgrade-audit.py keyv 4.5.4 6.0.0
    python3 npm-upgrade-audit.py --lockfile package-lock.json --check-updates
    python3 npm-upgrade-audit.py --batch pkgs.txt --cooldown 7 --json

Exit codes: 0 clean, 1 findings at HIGH or above, 2 usage/network error.
"""
from __future__ import annotations
import argparse, datetime, io, json, math, os, re, sys, tarfile, urllib.request, urllib.error

REGISTRY = os.environ.get("NPM_REGISTRY", "https://registry.npmjs.org")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
# Big obfuscated blobs are the payload shape. The keyv stealer was 728 KB.
BIG_FILE = 200 * 1024
ENTROPY_MIN_SIZE = 20 * 1024
ENTROPY_THRESHOLD = 5.2
SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
# Docs and maps mention things like bun.sh in prose. Only scan executable code
# for behaviour, or every README turns into a finding.
CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".py", ".json")
DOC_EXT = (".md", ".markdown", ".txt", ".map", ".d.ts", "LICENSE")


def is_code(path: str) -> bool:
    return path.endswith(CODE_EXT) and not path.endswith(DOC_EXT)

# Strings that are unremarkable in isolation but notable in a NEW file inside a
# cache library. Presence alone is not a verdict, it is a reason to go look.
SUSPICIOUS = [
    (rb"169\.254\.169\.254", "cloud instance metadata endpoint"),
    (rb"/\.aws/credentials", "AWS credentials file"),
    (rb"\.npmrc", "npm auth token file"),
    (rb"id_rsa|id_ed25519", "SSH private key names"),
    (rb"/var/run/secrets/kubernetes\.io", "Kubernetes service account token"),
    (rb"GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN", "CI credential environment variables"),
    (rb"child_process|execSync|spawnSync", "process execution"),
    (rb"eval\(|Function\(", "dynamic code evaluation"),
    (rb"bun\.sh|bun-dl", "Bun runtime download"),
]


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "npm-upgrade-audit/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.load(r)


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "npm-upgrade-audit/1.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def tarball_files(url: str) -> dict[str, bytes]:
    """package/<path> -> content, with a size guard so a hostile tar cannot blow us up."""
    raw = fetch_bytes(url)
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        total = 0
        for m in tf.getmembers():
            if not m.isfile() or m.size > 25 * 1024 * 1024:
                continue
            total += m.size
            if total > 120 * 1024 * 1024:
                break
            f = tf.extractfile(m)
            if f:
                out[re.sub(r"^package/", "", m.name)] = f.read()
    return out


class Finding:
    def __init__(self, sev, code, detail):
        self.sev, self.code, self.detail = sev, code, detail

    def __repr__(self):
        return f"{self.sev}: {self.detail}"


def audit(name: str, old_version: str | None, new_version: str, cooldown: int) -> list[Finding]:
    f: list[Finding] = []
    meta = fetch_json(f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}")
    versions = meta.get("versions", {})
    times = meta.get("time", {})

    if new_version not in versions:
        return [Finding("INFO", "not-found",
                        f"{name}@{new_version} is not on the registry (unpublished, or a typo). "
                        f"Latest is {meta.get('dist-tags', {}).get('latest')}")]

    new_meta = versions[new_version]

    # 1. Cooldown. The single highest-value control: this compromise was caught
    # within minutes and pulled within hours, so anything installing only
    # versions older than a few days was never exposed.
    published = times.get(new_version)
    if published:
        age = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))).days
        if age < cooldown:
            f.append(Finding("MEDIUM", "cooldown",
                             f"published {age}d ago, under the {cooldown}d cooldown"))

    # 2. Lifecycle scripts. The mechanism, not a heuristic.
    new_scripts = {k: v for k, v in (new_meta.get("scripts") or {}).items() if k in LIFECYCLE}
    old_scripts = {}
    if old_version and old_version in versions:
        old_scripts = {k: v for k, v in (versions[old_version].get("scripts") or {}).items()
                       if k in LIFECYCLE}
    for k, v in new_scripts.items():
        if k not in old_scripts:
            f.append(Finding("CRITICAL", "new-lifecycle-script",
                             f"adds a {k} script that {old_version or 'the previous version'} "
                             f"did not have: {v[:120]}"))
        elif old_scripts[k] != v:
            f.append(Finding("HIGH", "changed-lifecycle-script",
                             f"{k} script changed: {v[:120]}"))

    # 3. Publisher change.
    npm_user = (new_meta.get("_npmUser") or {}).get("name")
    if old_version and old_version in versions:
        prev_user = (versions[old_version].get("_npmUser") or {}).get("name")
        if npm_user and prev_user and npm_user != prev_user:
            f.append(Finding("HIGH", "publisher-change",
                             f"published by '{npm_user}', previous version by '{prev_user}'"))

    # 4. Content diff, the part that actually looks at the code.
    new_url = (new_meta.get("dist") or {}).get("tarball")
    if not new_url:
        return f
    try:
        new_files = tarball_files(new_url)
    except Exception as e:
        f.append(Finding("INFO", "tarball-error", f"could not read tarball: {e}"))
        return f

    old_files: dict[str, bytes] = {}
    if old_version and old_version in versions:
        old_url = (versions[old_version].get("dist") or {}).get("tarball")
        if old_url:
            try:
                old_files = tarball_files(old_url)
            except Exception:
                pass

    added = [p for p in new_files if p not in old_files]
    for p in added:
        body = new_files[p]
        at_root = "/" not in p
        if at_root and p.endswith((".js", ".mjs", ".cjs", ".ts", ".sh")):
            f.append(Finding("HIGH", "new-root-script",
                             f"new executable file at package root: {p} ({len(body):,} bytes)"))
        if len(body) > BIG_FILE:
            f.append(Finding("HIGH", "large-new-file",
                             f"new file {p} is {len(body):,} bytes"))
        if len(body) > ENTROPY_MIN_SIZE and is_code(p):
            e = entropy(body)
            if e > ENTROPY_THRESHOLD:
                f.append(Finding("HIGH", "high-entropy",
                                 f"new file {p} looks packed or obfuscated "
                                 f"(entropy {e:.2f}, {len(body):,} bytes)"))
        hits = [why for pat, why in SUSPICIOUS if re.search(pat, body)] if is_code(p) else []
        if hits:
            f.append(Finding("HIGH", "suspicious-strings",
                             f"new file {p} references: {', '.join(sorted(set(hits))[:4])}"))

    # Changed files that gained credential or execution behaviour they did not have.
    for p in (set(new_files) & set(old_files)):
        if new_files[p] == old_files[p]:
            continue
        if not is_code(p):
            continue
        gained = [why for pat, why in SUSPICIOUS
                  if re.search(pat, new_files[p]) and not re.search(pat, old_files[p])]
        if gained:
            f.append(Finding("HIGH", "behaviour-change",
                             f"{p} now references: {', '.join(sorted(set(gained))[:4])}"))

    if old_files:
        grew = sum(len(v) for v in new_files.values()) - sum(len(v) for v in old_files.values())
        if grew > 500 * 1024:
            f.append(Finding("MEDIUM", "size-jump", f"package grew by {grew:,} bytes"))
    return f


def installed_from_lockfile(path: str) -> dict[str, str]:
    d = json.load(open(path))
    out = {}
    for p, meta in (d.get("packages") or {}).items():
        if "node_modules" not in p:
            continue
        out[p.split("node_modules/")[-1]] = meta.get("version")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit an npm upgrade before installing it.")
    ap.add_argument("package", nargs="?")
    ap.add_argument("old_version", nargs="?")
    ap.add_argument("new_version", nargs="?")
    ap.add_argument("--lockfile", help="package-lock.json to read current versions from")
    ap.add_argument("--check-updates", action="store_true",
                    help="with --lockfile: audit every dependency against its current latest")
    ap.add_argument("--batch", help="file of 'name old new' lines")
    ap.add_argument("--cooldown", type=int, default=int(os.environ.get("NPM_COOLDOWN_DAYS", 3)))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", default="HIGH", choices=list(SEV_ORDER))
    a = ap.parse_args()

    jobs: list[tuple[str, str | None, str]] = []
    if a.batch:
        for line in open(a.batch):
            parts = line.split()
            if len(parts) == 3:
                jobs.append((parts[0], parts[1], parts[2]))
    elif a.lockfile and a.check_updates:
        installed = installed_from_lockfile(a.lockfile)
        for name, cur in sorted(installed.items()):
            if not cur:
                continue
            try:
                latest = fetch_json(f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}") \
                    .get("dist-tags", {}).get("latest")
            except Exception:
                continue
            if latest and latest != cur:
                jobs.append((name, cur, latest))
    elif a.package and a.new_version:
        jobs.append((a.package, a.old_version, a.new_version))
    else:
        ap.print_help()
        return 2

    results, worst = [], 0
    for name, old, new in jobs:
        try:
            fs = audit(name, old, new, a.cooldown)
        except urllib.error.URLError as e:
            print(f"  {name}: network error {e}", file=sys.stderr)
            return 2
        results.append({"package": name, "from": old, "to": new,
                        "findings": [{"severity": x.sev, "code": x.code, "detail": x.detail}
                                     for x in fs]})
        for x in fs:
            worst = max(worst, SEV_ORDER[x.sev])
        if not a.json:
            head = f"{name}  {old or '?'} -> {new}"
            if not fs:
                print(f"  OK        {head}")
            else:
                top = max(fs, key=lambda x: SEV_ORDER[x.sev]).sev
                print(f"  {top:<9} {head}")
                for x in sorted(fs, key=lambda x: -SEV_ORDER[x.sev]):
                    print(f"      [{x.sev}] {x.detail}")

    if a.json:
        print(json.dumps({"audited": len(jobs), "results": results}, indent=1))
    return 1 if worst >= SEV_ORDER[a.fail_on] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
