#!/usr/bin/env python3
"""Audit a dependency upgrade BEFORE you install it. npm, PyPI and crates.io.

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

    python3 upgrade-audit.py npm keyv 4.5.4 6.0.0
    python3 upgrade-audit.py pypi requests 2.31.0 2.32.0
    python3 upgrade-audit.py cargo serde 1.0.200 1.0.210
    python3 upgrade-audit.py npm --lockfile package-lock.json --check-updates
    python3 upgrade-audit.py npm --batch pkgs.txt --cooldown 7 --json

Every ecosystem has one place where a package gets to run arbitrary code on the
machine that installs it. That is where these attacks live, so it is what the
CRITICAL check looks at:

    npm    lifecycle scripts (preinstall / install / postinstall)
    pypi   setup.py in an sdist, which executes at build time
    cargo  build.rs, which compiles and runs before your crate does

Exit codes: 0 clean, 1 findings at HIGH or above, 2 usage/network error.
"""
from __future__ import annotations
import argparse, datetime, io, json, math, os, re, sys, tarfile, zipfile, urllib.parse, urllib.request, urllib.error

REGISTRY = os.environ.get("NPM_REGISTRY", "https://registry.npmjs.org")
PYPI = os.environ.get("PYPI_REGISTRY", "https://pypi.org")
CRATES = os.environ.get("CRATES_REGISTRY", "https://crates.io")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
# Big obfuscated blobs are the payload shape. The keyv stealer was 728 KB.
BIG_FILE = 200 * 1024
ENTROPY_MIN_SIZE = 20 * 1024
ENTROPY_THRESHOLD = 5.2
SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
# Docs and maps mention things like bun.sh in prose. Only scan executable code
# for behaviour, or every README turns into a finding.
CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".py", ".json", ".rs", ".toml", ".cfg")
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
    (rb"base64\.b64decode|codecs\.decode|marshal\.loads", "encoded payload decoding"),
    (rb"os\.system|subprocess\.(Popen|run|call)|Command::new", "process execution"),
]


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "upgrade-audit/1.1"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.load(r)


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "upgrade-audit/1.1"})
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


def archive_files(url: str) -> dict[str, bytes]:
    """Read a package archive into path -> bytes.

    npm .tgz and cargo .crate are gzipped tars; PyPI ships either a tar.gz sdist
    or a zip (wheel, or occasionally an sdist). The leading directory is stripped
    so the same path shows up on both sides of a diff.
    """
    raw = fetch_bytes(url)
    if raw[:2] == b"PK":
        return _zip_files(raw)
    return _tar_files(raw)


def _strip_top(name: str) -> str:
    return name.split("/", 1)[1] if "/" in name else name


def _zip_files(raw: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for i in zf.infolist():
            if i.is_dir() or i.file_size > 25 * 1024 * 1024:
                continue
            total += i.file_size
            if total > 120 * 1024 * 1024:
                break
            out[_strip_top(i.filename)] = zf.read(i)
    return out


def _tar_files(raw: bytes) -> dict[str, bytes]:
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
                out[_strip_top(m.name)] = f.read()
    return out




# --------------------------------------------------------------------------
# Ecosystem adapters. Each returns the same shape so the diff logic below does
# not care which registry it came from.
#   versions      : {version: metadata}
#   published(v)  : ISO timestamp or None
#   archive(v)    : URL of the artifact to diff
#   exec_hooks(v) : {hook_name: description} for code that runs at install time
#   publisher(v)  : identity string or None
# --------------------------------------------------------------------------

class Npm:
    name = "npm"
    def __init__(self, pkg):
        self.pkg = pkg
        self.meta = fetch_json(f"{REGISTRY}/{urllib.parse.quote(pkg, safe='@')}")
        self.versions = self.meta.get("versions", {})
        self.latest = (self.meta.get("dist-tags") or {}).get("latest")
    def published(self, v): return (self.meta.get("time") or {}).get(v)
    def archive(self, v): return ((self.versions.get(v) or {}).get("dist") or {}).get("tarball")
    def publisher(self, v): return ((self.versions.get(v) or {}).get("_npmUser") or {}).get("name")
    def exec_hooks(self, v, files):
        sc = (self.versions.get(v) or {}).get("scripts") or {}
        return {k: sc[k] for k in LIFECYCLE if k in sc}

class PyPI:
    name = "pypi"
    def __init__(self, pkg):
        self.pkg = pkg
        self.meta = fetch_json(f"{PYPI}/pypi/{urllib.parse.quote(pkg)}/json")
        self.releases = self.meta.get("releases", {})
        self.versions = {v: {} for v, files in self.releases.items() if files}
        self.latest = (self.meta.get("info") or {}).get("version")
    def _pick(self, v):
        files = self.releases.get(v) or []
        # Prefer the sdist: it is the artifact that can execute setup.py on install.
        for f in files:
            if f.get("packagetype") == "sdist":
                return f
        return files[0] if files else None
    def published(self, v):
        f = self._pick(v)
        return f.get("upload_time_iso_8601") if f else None
    def archive(self, v):
        f = self._pick(v)
        return f.get("url") if f else None
    def publisher(self, v): return None          # PyPI does not expose the uploader
    def exec_hooks(self, v, files):
        out = {}
        for path in ("setup.py", "setup.cfg"):
            if path in files:
                out[path] = "executes at build/install time from an sdist"
        for path, body in files.items():
            if path.endswith(".py") and re.search(rb"cmdclass\s*=", body):
                out[path] = "overrides a distutils/setuptools command"
        return out

class Crates:
    name = "cargo"
    def __init__(self, pkg):
        self.pkg = pkg
        self.meta = fetch_json(f"{CRATES}/api/v1/crates/{urllib.parse.quote(pkg)}")
        self.versions = {x["num"]: x for x in self.meta.get("versions", [])}
        self.latest = (self.meta.get("crate") or {}).get("max_stable_version")
    def published(self, v): return (self.versions.get(v) or {}).get("created_at")
    def archive(self, v):
        return f"{CRATES}/api/v1/crates/{urllib.parse.quote(self.pkg)}/{v}/download" if v in self.versions else None
    def publisher(self, v): return ((self.versions.get(v) or {}).get("published_by") or {}).get("login")
    def exec_hooks(self, v, files):
        return {p: "compiles and runs before your crate does"
                for p in files if p == "build.rs" or p.endswith("/build.rs")}

ECOSYSTEMS = {"npm": Npm, "pypi": PyPI, "cargo": Crates}


class Finding:
    def __init__(self, sev, code, detail):
        self.sev, self.code, self.detail = sev, code, detail

    def __repr__(self):
        return f"{self.sev}: {self.detail}"


def audit(eco: str, name: str, old_version, new_version: str, cooldown: int):
    f = []
    reg = ECOSYSTEMS[eco](name)
    if new_version not in reg.versions:
        return [Finding("INFO", "not-found",
                        f"{name}@{new_version} is not on {eco} (unpublished, yanked, or a typo). "
                        f"Latest is {reg.latest}")]

    published = reg.published(new_version)
    if published:
        try:
            age = (datetime.datetime.now(datetime.timezone.utc)
                   - datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))).days
            if age < cooldown:
                f.append(Finding("MEDIUM", "cooldown",
                                 f"published {age}d ago, under the {cooldown}d cooldown"))
        except ValueError:
            pass

    npub, opub = reg.publisher(new_version), (reg.publisher(old_version) if old_version else None)
    if npub and opub and npub != opub:
        f.append(Finding("HIGH", "publisher-change",
                         f"published by '{npub}', previous version by '{opub}'"))

    new_url = reg.archive(new_version)
    if not new_url:
        return f
    try:
        new_files = archive_files(new_url)
    except Exception as e:
        f.append(Finding("INFO", "archive-error", f"could not read artifact: {e}"))
        return f

    old_files = {}
    if old_version and old_version in reg.versions:
        old_url = reg.archive(old_version)
        if old_url:
            try:
                old_files = archive_files(old_url)
            except Exception:
                pass

    # The one thing that matters most: code that runs at install time and did
    # not run before. npm lifecycle scripts, a PyPI sdist's setup.py, a cargo
    # build.rs. Same class of problem, three different names for it.
    new_hooks = reg.exec_hooks(new_version, new_files)
    old_hooks = reg.exec_hooks(old_version, old_files) if old_version and old_files else {}
    for k, why in new_hooks.items():
        if k not in old_hooks:
            f.append(Finding("CRITICAL", "new-install-hook",
                             f"adds {k}, which {why}, and the previous version did not have it"))
        elif eco == "npm" and old_hooks.get(k) != why:
            f.append(Finding("HIGH", "changed-install-hook", f"{k} changed: {str(why)[:120]}"))
        elif eco != "npm" and k in old_files and new_files.get(k) != old_files.get(k):
            f.append(Finding("HIGH", "changed-install-hook",
                             f"{k} changed, and it {why}"))

    added = [p for p in new_files if p not in old_files]
    for p_ in added:
        body = new_files[p_]
        if "/" not in p_ and p_.endswith((".js", ".mjs", ".cjs", ".ts", ".sh", ".py", ".rs")):
            f.append(Finding("HIGH", "new-root-script",
                             f"new executable file at package root: {p_} ({len(body):,} bytes)"))
        if len(body) > BIG_FILE:
            f.append(Finding("HIGH", "large-new-file", f"new file {p_} is {len(body):,} bytes"))
        if len(body) > ENTROPY_MIN_SIZE and is_code(p_):
            e = entropy(body)
            if e > ENTROPY_THRESHOLD:
                f.append(Finding("HIGH", "high-entropy",
                                 f"new file {p_} looks packed or obfuscated "
                                 f"(entropy {e:.2f}, {len(body):,} bytes)"))
        if is_code(p_):
            hits = [why for pat, why in SUSPICIOUS if re.search(pat, body)]
            if hits:
                f.append(Finding("HIGH", "suspicious-strings",
                                 f"new file {p_} references: {', '.join(sorted(set(hits))[:4])}"))

    for p_ in (set(new_files) & set(old_files)):
        if new_files[p_] == old_files[p_] or not is_code(p_):
            continue
        gained = [why for pat, why in SUSPICIOUS
                  if re.search(pat, new_files[p_]) and not re.search(pat, old_files[p_])]
        if gained:
            f.append(Finding("HIGH", "behaviour-change",
                             f"{p_} now references: {', '.join(sorted(set(gained))[:4])}"))

    if old_files:
        grew = sum(len(v) for v in new_files.values()) - sum(len(v) for v in old_files.values())
        if grew > 500 * 1024:
            f.append(Finding("MEDIUM", "size-jump", f"package grew by {grew:,} bytes"))
    return f


def previous_release(ad, version: str) -> str | None:
    """The release published immediately before `version`.

    Ordered by publish time rather than version number on purpose: a backport to
    an old branch can be published after a newer release, and what we want to
    diff against is what the world saw before this artifact appeared.
    """
    dated = []
    for v in ad.versions:
        p = ad.published(v)
        if p:
            dated.append((p, v))
    dated.sort()
    for i, (_, v) in enumerate(dated):
        if v == version:
            return dated[i - 1][1] if i else None
    return None


def _pyproject(path: str) -> dict:
    p = os.path.join(path, "pyproject.toml")
    if not os.path.exists(p):
        return {}
    try:
        import tomllib
        with open(p, "rb") as fh:
            return tomllib.load(fh)
    except Exception:
        return {}


def _project_name(path: str) -> str | None:
    """The name of the project being resolved, so it can be left out.

    Resolving a directory installs the project itself alongside its
    dependencies. Pinning your own version in your own lockfile is noise: it
    changes on every release and there is no upstream to audit it against.
    """
    data = _pyproject(path)
    name = ((data.get("project") or {}).get("name")
            or ((data.get("tool") or {}).get("poetry") or {}).get("name"))
    return name.lower().replace("_", "-") if name else None


def _extras(path: str) -> list[str]:
    """Every extra the project declares."""
    data = _pyproject(path)
    if not data:
        return []
    extras = list((data.get("project") or {}).get("optional-dependencies") or {})
    if not extras:
        extras = list(((data.get("tool") or {}).get("poetry") or {}).get("extras") or {})
    return extras


def _pip_resolve(args: list[str]) -> tuple[dict[str, str], str]:
    """(resolved versions, error). Installs nothing."""
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--dry-run", "--quiet",
             "--ignore-installed", "--report", report, *args],
            capture_output=True, text=True)
        if not os.path.exists(report):
            return {}, (proc.stderr or proc.stdout).strip()[:400]
        data = json.load(open(report))
    out = {}
    for item in data.get("install", []):
        meta = item.get("metadata") or {}
        n, v = meta.get("name"), meta.get("version")
        if n and v:
            out[n.lower().replace("_", "-")] = v
    return out, ""


def resolve_pypi(target: str) -> dict[str, str]:
    """Ask pip what it would actually install, without installing it.

    Repositories that depend on ranges (`boto3>=1.34`) have no lockfile, so a
    pull request diff cannot show a dependency change: the version is chosen at
    install time. Resolving is the only way to see what a build would really
    pull down today.
    """
    if os.path.isfile(target):
        out, err = _pip_resolve(["-r", target])
        if err:
            raise RuntimeError(f"pip could not resolve {target}: {err}")
        return out

    # Projects routinely park the interesting dependencies in extras: a lake
    # sink's boto3 and pyarrow live under [parquet], not in the base list, so
    # resolving the bare project would audit almost nothing.
    out, err = _pip_resolve([target])
    if err:
        raise RuntimeError(f"pip could not resolve {target}: {err}")

    extras = _extras(target)
    if not extras:
        return out

    # One extra at a time. Asking for all of them at once fails outright the
    # moment any single extra cannot be satisfied here, and a [windows] extra
    # pinning pywin32 will never resolve on a Linux runner. Per-extra means one
    # unsatisfiable group costs that group, not the whole audit.
    for extra in extras:
        got, err = _pip_resolve([f"{target}[{extra}]"])
        if err:
            print(f"  skipped extra [{extra}]: does not resolve here", file=sys.stderr)
            continue
        out.update(got)

    own = _project_name(target)
    if own:
        out.pop(own, None)
    return out


def installed_from_lockfile(path: str) -> dict[str, str]:
    d = json.load(open(path))
    out = {}
    for p, meta in (d.get("packages") or {}).items():
        if "node_modules" not in p:
            continue
        out[p.split("node_modules/")[-1]] = meta.get("version")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audit a dependency upgrade before you install it (npm, pypi, cargo).")
    ap.add_argument("ecosystem", choices=sorted(ECOSYSTEMS))
    ap.add_argument("package", nargs="?")
    ap.add_argument("old_version", nargs="?")
    ap.add_argument("new_version", nargs="?")
    ap.add_argument("--lockfile", help="package-lock.json to read current versions from (npm)")
    ap.add_argument("--check-updates", action="store_true",
                    help="with --lockfile: audit every dependency against its current latest")
    ap.add_argument("--resolve", metavar="PATH",
                    help="pypi: resolve requirements.txt or a project directory with pip and "
                         "audit every release younger than the cooldown window")
    ap.add_argument("--lock", metavar="PATH",
                    help="pypi: resolve PATH and write a pinned lockfile to --lock-out, "
                         "so later changes are visible as a diff")
    ap.add_argument("--lock-out", metavar="FILE", default="requirements.lock",
                    help="where --lock writes (default requirements.lock)")
    ap.add_argument("--batch", help="file of 'name old new' lines")
    ap.add_argument("--cooldown", type=int, default=int(os.environ.get("COOLDOWN_DAYS", 3)))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", default="HIGH", choices=list(SEV_ORDER))
    a = ap.parse_args()

    if a.lock:
        if a.ecosystem != "pypi":
            print("--lock is pypi only", file=sys.stderr)
            return 2
        try:
            resolved = resolve_pypi(a.lock)
        except RuntimeError as e:
            print(f"  {e}", file=sys.stderr)
            return 2
        if not resolved:
            # Never truncate a lockfile to nothing on a bad resolve: that reads
            # as "no dependencies" rather than "the resolve failed".
            print("  nothing resolved, refusing to write an empty lockfile", file=sys.stderr)
            return 2
        body = "".join(f"{n}=={v}\n" for n, v in sorted(resolved.items()))
        with open(a.lock_out, "w") as fh:
            fh.write(
                "# Generated by upgrade-audit: the versions pip resolves for this project.\n"
                "# Regenerate rather than editing by hand.\n"
                "#\n"
                "# This pins versions, not artifact hashes. The point is to have a record\n"
                "# of what you depend on, so that a change to it shows up as a diff and can\n"
                "# be reviewed. Without one, a range picks up a new release and nothing in\n"
                "# the repository changes at all.\n"
                "#\n"
                "# Resolution depends on the platform it ran on, so generate this where you\n"
                f"# deploy. Resolved on {sys.platform}, python {sys.version_info.major}.{sys.version_info.minor}.\n"
                "\n" + body)
        print(f"  wrote {a.lock_out}: {len(resolved)} pinned packages", file=sys.stderr)
        return 0

    jobs = []
    if a.batch:
        for line in open(a.batch):
            parts = line.split()
            if len(parts) == 3:
                jobs.append((parts[0], parts[1], parts[2]))
    elif a.resolve:
        if a.ecosystem != "pypi":
            print("--resolve is pypi only", file=sys.stderr)
            return 2
        try:
            resolved = resolve_pypi(a.resolve)
        except RuntimeError as e:
            print(f"  {e}", file=sys.stderr)
            return 2
        # Auditing all of them would mean two tarball downloads per package on
        # every run. The ones that matter are the ones that appeared recently:
        # a range pulls in a brand-new release the moment it is published, which
        # is exactly the window an account takeover lives in.
        window = max(a.cooldown, 1) * 3
        now = datetime.datetime.now(datetime.timezone.utc)
        print(f"  resolved {len(resolved)} packages; auditing any published in the "
              f"last {window} days", file=sys.stderr)
        for name, ver in sorted(resolved.items()):
            try:
                ad = ECOSYSTEMS["pypi"](name)
                published = ad.published(ver)
                if not published:
                    continue
                age = (now - datetime.datetime.fromisoformat(
                    published.replace("Z", "+00:00"))).days
                if age <= window:
                    jobs.append((name, previous_release(ad, ver), ver))
            except Exception:
                continue
        if not jobs:
            print("  nothing resolved to a release inside the window", file=sys.stderr)
    elif a.lockfile and a.check_updates:
        for name, cur in sorted(installed_from_lockfile(a.lockfile).items()):
            if not cur:
                continue
            try:
                latest = ECOSYSTEMS[a.ecosystem](name).latest
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
            fs = audit(a.ecosystem, name, old, new, a.cooldown)
        except urllib.error.URLError as e:
            print(f"  {name}: network error {e}", file=sys.stderr)
            return 2
        except Exception as e:
            fs = [Finding("INFO", "error", f"{type(e).__name__}: {e}")]
        results.append({"ecosystem": a.ecosystem, "package": name, "from": old, "to": new,
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
