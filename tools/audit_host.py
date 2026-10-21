#!/usr/bin/env python3
"""Collect a private, read-only vendor/PHP security-update audit."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


# Import only this repository's administration library, never application code.
REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))
from phese.cli import FIXED, PolicyError, VERSION_CODE, private_json  # noqa: E402


TARGET_CVES = ["CVE-2026-109618", "CVE-2026-109619"]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
REFERENCE_RE = re.compile(r"(?:CVE-\d{4}-\d{4,}|[A-Z][A-Z0-9_-]*-\d{4}:\S+)\Z")
PACKAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.:%~\-]*\Z")
CLASSIFICATION_RE = re.compile(r"(?:Critical|Important|Moderate|Low|Unknown|None|Unspecified)/Sec\.?\Z", re.I)
MAX_OUTPUT = 4 * 1024 * 1024


def command(argv, timeout):
    return subprocess.run(argv, check=False, capture_output=True, text=True,
                          timeout=timeout, shell=False, stdin=subprocess.DEVNULL)


def unknown(reason, **extra):
    return {"state": "unknown", "reason": reason, **extra}


def os_identity(path=Path("/etc/os-release")):
    """Read only ID/VERSION_ID from the standard OS identity file."""
    try:
        with Path(path).open("r", encoding="utf-8") as source:
            content = source.read(64 * 1024 + 1)
        if len(content) > 64 * 1024:
            return unknown("os_release_oversized")
        result = {}
        for line in content.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in {"ID", "VERSION_ID"}:
                continue
            tokens = shlex.split(value, comments=True, posix=True)
            if len(tokens) == 1 and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", tokens[0]):
                result[key.lower()] = tokens[0]
        if set(result) != {"id", "version_id"}:
            return unknown("os_identity_incomplete", **result)
        return {"state": "checked", **result}
    except (OSError, UnicodeError, ValueError):
        return unknown("os_identity_unreadable")


def kernel_identity(uname=os.uname):
    try:
        identity = uname()
        return {"state": "checked", "release": identity.release, "machine": identity.machine,
                "scope": "running_kernel_identity_only"}
    except OSError:
        return unknown("kernel_identity_unavailable")


def php_audit(binary, runner=command):
    # The operator explicitly selects a trusted interpreter. -n avoids host INI
    # and prepend hooks; this constant probe never includes an application file.
    path = Path(binary)
    if not path.is_absolute():
        return unknown("php_path_must_be_absolute", path=str(path))
    try:
        path = path.resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            return unknown("php_binary_unavailable", path=str(path))
        result = runner([str(path), "-n", "-r", VERSION_CODE], timeout=10)
    except subprocess.TimeoutExpired:
        return unknown("php_probe_timeout", path=str(path))
    except (OSError, UnicodeError):
        return unknown("php_probe_unavailable", path=str(path))
    if result.returncode:
        return unknown("php_probe_failed", path=str(path), exit_code=result.returncode)
    if result.stderr.strip() or len(result.stdout) > 4096:
        return unknown("php_probe_warning_or_oversized", path=str(path))
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, list) or len(value) != 3:
            raise ValueError
        version, number, zts = value
        if (not isinstance(version, str) or len(version) > 80
                or not re.fullmatch(r"\d+\.\d+\.\d+[A-Za-z0-9.+_\-]*", version)
                or type(number) is not int or number < 10000
                or type(zts) not in {bool, int} or zts not in {0, 1, False, True}):
            raise ValueError
        components = tuple(map(int, re.match(r"(\d+)\.(\d+)\.(\d+)", version).groups()))
        if number != components[0] * 10000 + components[1] * 100 + components[2]:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        return unknown("php_probe_invalid_json", path=str(path))
    branch = (number // 10000, number // 100 % 100)
    info = {"path": str(path), "version": version, "version_id": number, "zts": bool(zts),
            "scope": "selected_binary_version_only", "target_cves": TARGET_CVES,
            "native_seccomp_state": "not_probed", "running_workers": "not_inspected"}
    if branch not in FIXED or re.search(r"(?:dev|alpha|beta|rc)", version, re.I):
        return unknown("php_branch_or_prerelease_not_validated", **info,
                       upstream_version_gate="unknown",
                       recommendation="Verify a supported stable release and vendor security evidence before use.")
    passed = number % 100 >= FIXED[branch]
    return {"state": "checked", **info, "upstream_version_gate": "passed" if passed else "review_required",
            "recommendation": ("Retain upstream patches; audit extensions and running workers separately."
                               if passed else "Upgrade this branch to its upstream fixed release, or document the exact vendor backport. A version-only result does not prove exploitability.")}


def parse_updateinfo(output):
    rows, unparsed = [], 0
    for line in output.splitlines():
        text = line.strip()
        if not text or text.startswith("Last metadata expiration check:"):
            continue
        columns = text.split()
        if columns and columns[0] in {"i", "*"}:
            columns = columns[1:]
        if (len(columns) == 3 and REFERENCE_RE.fullmatch(columns[0])
                and CLASSIFICATION_RE.fullmatch(columns[1])
                and PACKAGE_RE.fullmatch(columns[2])):
            rows.append({"reference": columns[0], "classification": columns[1], "package": columns[2]})
        else:
            unparsed += 1
    # Only structured advisory/package identifiers are retained. Never save
    # raw output, which can include authenticated repository URLs or errors.
    cves = sorted({match.upper() for row in rows for match in CVE_RE.findall(row["reference"])})
    unique = sorted({(x["reference"], x["classification"], x["package"]) for x in rows})
    return [{"reference": x[0], "classification": x[1], "package": x[2]} for x in unique], cves, unparsed


def dnf_audit(runner=command, candidates=(Path("/usr/bin/dnf"), Path("/bin/dnf"))):
    # Fixed locations avoid reading PATH or other environment variables.
    binary = next((str(path) for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)
    if binary is None:
        return unknown("dnf_missing", advisories=[], cves=[])
    try:
        help_result = runner([binary, "updateinfo", "--help"], timeout=10)
        required = ("--security", "--available", "--list", "--with-cve")
        if (help_result.returncode or any(flag not in help_result.stdout for flag in required)):
            return unknown("dnf_updateinfo_unsupported", advisories=[], cves=[])
        if help_result.stderr.strip() or len(help_result.stdout) > MAX_OUTPUT:
            return unknown("dnf_help_warning_or_oversized", advisories=[], cves=[])
        result = runner([binary, "-q", "updateinfo", "list", "--security", "--available", "--with-cve"], timeout=45)
    except subprocess.TimeoutExpired:
        return unknown("dnf_timeout", advisories=[], cves=[])
    except (OSError, UnicodeError):
        return unknown("dnf_unavailable", advisories=[], cves=[])
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        return unknown("dnf_output_oversized", advisories=[], cves=[])
    rows, cves, unparsed = parse_updateinfo(result.stdout)
    common = {"advisories": rows, "cves": cves,
              "scope": "enabled_repository_updateinfo_with_cve_references_only",
              "all_cves_protected": False,
              "absence_of_findings_is_not_proof": True,
              "recommendation": "Review vendor advisories, approve a compatible update plan, and verify running binaries after a separately authorized rollout."}
    if result.returncode:
        return unknown("dnf_query_failed", exit_code=result.returncode, **common)
    if result.stderr.strip():
        return unknown("dnf_reported_warnings", **common)
    if unparsed:
        return unknown("dnf_output_not_fully_parsed", unparsed_lines=unparsed, **common)
    return {"state": "checked", **common}


def audit(php_binaries, runner=command, os_release=Path("/etc/os-release"), uname=os.uname,
          dnf_candidates=(Path("/usr/bin/dnf"), Path("/bin/dnf"))):
    identity = os_identity(os_release)
    kernel = kernel_identity(uname)
    php = [php_audit(binary, runner) for binary in dict.fromkeys(php_binaries)]
    packages = dnf_audit(runner, dnf_candidates)
    checks = [identity, kernel, packages, *php]
    missing_php = not php
    counts = {"checked": sum(x["state"] == "checked" for x in checks),
              "unknown": sum(x["state"] == "unknown" for x in checks) + int(missing_php),
              "php_binaries": len(php),
              "php_version_review_required": sum(x.get("upstream_version_gate") == "review_required" for x in php),
              "package_security_rows": len(packages["advisories"]),
              "package_cves": len(packages["cves"])}
    return {"schema": 1, "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "mode": "read_only_audit", "all_cves_protected": False,
            "os": identity, "kernel": kernel, "php": php,
            "php_selection": "explicit_only" if php else "unknown_no_binaries_selected",
            "vendor_updates": packages, "counts": counts,
            "limitations": ["No application source, process command lines, authentication files or environment variables are read.",
                            "No package installation, service restart, firewall/network change or scheduler is performed.",
                            "DNF may read enabled repository metadata and update its metadata cache; packages are not changed.",
                            "Repository coverage and vendor metadata freshness cannot prove absence of all vulnerabilities.",
                            "Custom PHP, containers, native libraries, application dependencies and running worker versions require separate review.",
                            "A passing PHP version gate covers only the two specified upstream CVE fixes; it does not prove kernel confinement or all-CVE protection."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", action="append", default=[], metavar="ABSOLUTE_BINARY",
                        help="explicit trusted PHP CLI binary; repeat for each interpreter")
    parser.add_argument("--output", required=True, type=Path, help="private JSON report destination")
    args = parser.parse_args(argv)
    try:
        report = audit(args.php)
        private_json(args.output, report)
    except (OSError, PolicyError):
        print("audit-host: private report could not be written", file=sys.stderr)
        return 2
    # Vulnerability identifiers, packages, versions and recommendations stay in
    # the private report. Console output contains counts and its path only.
    print(json.dumps({**report["counts"], "report": str(args.output.absolute())}, ensure_ascii=False))
    if report["counts"]["unknown"]:
        return 2
    if report["counts"]["php_version_review_required"] or report["counts"]["package_security_rows"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
