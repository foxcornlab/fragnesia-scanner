#!/usr/bin/env python3
"""Detection-only local triage for Linux kernel Fragnesia, CVE-2026-46300.

Fragnesia is a local privilege escalation in the kernel's XFRM
ESP-in-TCP path: `skb_try_coalesce()` drops the shared-frag marker,
so ESP input decrypts in place over page-cache pages, and a local
user can rewrite the cached contents of files they may only read.
The public proof of concept targets the cached copy of `/usr/bin/su`.
CISA added it to KEV on 2026-10-28 with a federal due date of
2026-10-31, and CISA's entry says it can be chained with the
PHP2Shell flaws (CVE-2026-109618, CVE-2026-109619) to implant PHP
webshells and run commands as root. Dream Security reported that
chain rooting 25 firewall appliances, including systems on a US
government-affiliated network.

Scored CVSS 3.1 7.8 High by the kernel CNA and NVD. One secondary
source swaps this score with the VMware ESX entry from the same KEV
update and prints 2.7; this tool follows NVD and the kernel CNA.

This tool never touches the network, never loads an exploit, never
triggers the bug. It grades kernel version strings: the one your
machine is running, the ones your package manager has installed,
or any version you paste in. A VULNERABLE grade is triage, not
proof of exploitability, and a clean grade is only as good as the
version string you fed it.

Two traps this tool catches on purpose:

  * The `uname` trap (Ubuntu). `uname -r` prints `6.8.0-124-generic`
    but the fixed build is `6.8.0-124.124`. The upload number after
    the second dot never appears in `uname` output, so a running
    kernel whose ABI matches the fixed ABI cannot be cleared from
    `uname` alone. It grades UNKNOWN and tells you to check the
    installed package version instead. An ABI below the fixed ABI
    is definitively VULNERABLE; an ABI above it is FIXED.
  * The installed-but-not-booted trap. A fixed kernel package that
    is installed but not running does nothing. `--local` compares
    the running kernel against the newest installed kernel package
    and says so plainly when they differ.

Distribution kernels backport fixes under their own version
numbers, so an upstream version comparison alone can mislead.
Where a distro publishes an exact fixed build (Ubuntu, Debian),
this tool grades against that build. Where it does not (RHEL
streams, anything unrecognised), it grades against the upstream
fix and says to confirm against the vendor advisory.

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable or
no-fix finding, 1 = scan error. UNKNOWN does not change the
exit code, but it is not clean.
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys

# Upstream stable fixes, per the Linux CNA record (fix commit
# f84eca581739, "net: skbuff: preserve shared-frag marker during
# coalescing"). Line -> first fixed version. 7.1 and later are not
# affected. Lines with no entry here have no upstream fixed
# release in this tool's data (checked 2026-10-31).
UPSTREAM_FIXED = {
    (5, 10): (5, 10, 257),
    (5, 15): (5, 15, 208),
    (6, 1): (6, 1, 174),
    (6, 6): (6, 6, 141),
    (6, 12): (6, 12, 91),
    (6, 18): (6, 18, 33),
    (7, 0): (7, 0, 10),
}

# Ubuntu fixed builds, per Ubuntu's advisories as reported
# 2026-10-29/30. Release -> (base, abi, upload).
UBUNTU_FIXED = {
    "26.04": ((7, 0, 0), 22, 22),
    "25.10": ((6, 17, 0), 35, 35),
    "24.04": ((6, 8, 0), 124, 124),
    "22.04": ((5, 15, 0), 181, 191),
}

# Debian fixed builds. Codename -> (base, debian revision).
DEBIAN_FIXED = {
    "trixie": ((6, 12, 90), 1),
    "bookworm": ((6, 1, 174), 1),
    "bullseye": ((5, 10, 257), 1),
}

RHEL_NOTE = "RHEL and derivatives: check RHSA-2026:19521 and later for your stream"

VULNERABLE = "VULNERABLE"
FIXED = "FIXED"
NOT_AFFECTED = "NOT_AFFECTED"
NO_FIX = "EOL_NO_FIX"
UNKNOWN = "UNKNOWN"

ESP_MODULES = ("esp4", "esp6", "rxrpc")


def parse_kernel(raw):
    """Parse a kernel version string.

    Accepts upstream ('6.6.140'), Ubuntu uname ('6.8.0-124-generic'),
    Ubuntu package ('6.8.0-124.124'), Debian package ('6.1.174-1').
    Returns {'base': (6, 8, 0), 'abi': 124|None, 'sub': 124|None,
    'flavor': 'generic'|None} or None when unparseable.
    """
    if raw is None:
        return None
    text = str(raw).strip().lstrip("vV")
    if not text:
        return None
    # Drop a trailing +suffix (e.g. distro build metadata).
    text = text.split("+", 1)[0]
    head, _, tail = text.partition("-")
    parts = head.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    base = tuple(int(p) for p in parts)
    while len(base) < 3:
        base = base + (0,)
    base = base[:3]
    abi = sub = None
    flavor = None
    if tail:
        fields = tail.split("-")
        first = fields[0]
        nums = first.split(".")
        if nums and all(n.isdigit() for n in nums):
            abi = int(nums[0])
            if len(nums) > 1:
                sub = int(nums[1])
            flavor = "-".join(fields[1:]) or None
        else:
            flavor = tail
    return {"base": base, "abi": abi, "sub": sub, "flavor": flavor}


def fmt_kernel(parsed):
    if parsed is None:
        return "?"
    text = ".".join(str(n) for n in parsed["base"])
    if parsed["abi"] is not None:
        text += "-%d" % parsed["abi"]
        if parsed["sub"] is not None:
            text += ".%d" % parsed["sub"]
    if parsed["flavor"]:
        text += "-" + parsed["flavor"]
    return text


def fmt_base(base):
    return ".".join(str(n) for n in base)


def grade_upstream(parsed):
    """Grade a bare upstream kernel version. Returns (verdict, detail)."""
    if parsed is None:
        return UNKNOWN, "unparseable kernel version"
    base = parsed["base"]
    if base < (3, 9, 0):
        return NOT_AFFECTED, "affected range starts at 3.9 per the CVE record"
    if base >= (7, 1, 0):
        return NOT_AFFECTED, "7.1 and later are not affected"
    line = base[:2]
    if line in UPSTREAM_FIXED:
        fixed = UPSTREAM_FIXED[line]
        if base < fixed:
            return VULNERABLE, "%s < fixed %s" % (fmt_base(base), fmt_base(fixed))
        return FIXED, "%s >= fixed %s" % (fmt_base(base), fmt_base(fixed))
    return UNKNOWN, (
        "no upstream fixed release listed for the %s line, "
        "move to a fixed line or check your vendor advisory"
        % fmt_base(line)
    )


def grade_ubuntu(version_id, running, package):
    """Grade an Ubuntu host. running/package are parsed kernels or None.

    The package version (dpkg `linux-image-*` version) is definitive.
    The running `uname -r` string hides the upload number, so an ABI
    match against the fixed ABI grades UNKNOWN, not clean.
    """
    if version_id == "20.04":
        # Ubuntu tracker lists the standard 5.4 kernel as not affected;
        # the 5.15 HWE kernel on 20.04 needs an Ubuntu Pro fix.
        if running is not None and running["base"][:2] == (5, 4):
            return NOT_AFFECTED, "Ubuntu 20.04 standard 5.4 kernel listed as not affected by Ubuntu"
        if running is not None and running["base"][:2] == (5, 15):
            return UNKNOWN, "Ubuntu 20.04 5.15 HWE kernel: fix is Ubuntu Pro only, check your Pro advisory"
    fixed = UBUNTU_FIXED.get(version_id)
    if fixed is None:
        verdict, detail = grade_upstream(running)
        return verdict, detail + " (Ubuntu release not in this tool's fixed-build table, upstream comparison only)"
    fixed_base, fixed_abi, fixed_sub = fixed
    if package is not None:
        key = (package["base"], package["abi"] or 0, package["sub"] or 0)
        fixed_key = (fixed_base, fixed_abi, fixed_sub)
        if key < fixed_key:
            return VULNERABLE, "installed %s < fixed %s" % (
                fmt_kernel(package),
                "%s-%d.%d" % (fmt_base(fixed_base), fixed_abi, fixed_sub),
            )
        return FIXED, "installed %s >= fixed %s" % (
            fmt_kernel(package),
            "%s-%d.%d" % (fmt_base(fixed_base), fixed_abi, fixed_sub),
        )
    if running is None:
        return UNKNOWN, "no kernel version supplied"
    if running["base"] != fixed_base:
        verdict, detail = grade_upstream(running)
        return verdict, detail + " (running kernel base does not match this Ubuntu release's fixed build, upstream comparison only)"
    if running["abi"] is None:
        return UNKNOWN, "running version has no ABI number, check the installed package version"
    if running["abi"] < fixed_abi:
        return VULNERABLE, "running ABI %d < fixed ABI %d" % (running["abi"], fixed_abi)
    if running["abi"] > fixed_abi:
        return FIXED, "running ABI %d > fixed ABI %d" % (running["abi"], fixed_abi)
    return UNKNOWN, (
        "running ABI %d matches the fixed ABI but uname hides the upload "
        "number (fixed build is %s-%d.%d); check the installed "
        "linux-image package version" % (
            fixed_abi, fmt_base(fixed_base), fixed_abi, fixed_sub)
    )


def grade_debian(codename, package):
    """Grade a Debian host from its installed kernel package version."""
    fixed = DEBIAN_FIXED.get(codename)
    if fixed is None:
        return UNKNOWN, "Debian release %s not in this tool's fixed-build table, check DSA" % (codename or "?")
    fixed_base, fixed_rev = fixed
    if package is None:
        return UNKNOWN, (
            "Debian uname strings carry only an ABI number, not the package "
            "version; pass --package-version (dpkg linux-image version) for a "
            "definitive grade. Fixed build is %s-%d"
            % (fmt_base(fixed_base), fixed_rev)
        )
    key = (package["base"], package["abi"] or 0)
    fixed_key = (fixed_base, fixed_rev)
    if key < fixed_key:
        return VULNERABLE, "installed %s < fixed %s-%d" % (
            fmt_kernel(package), fmt_base(fixed_base), fixed_rev)
    return FIXED, "installed %s >= fixed %s-%d" % (
        fmt_kernel(package), fmt_base(fixed_base), fixed_rev)


def grade_host(distro_id, version_id, codename, running, package):
    """Grade one host. Returns a result dict."""
    notes = []
    if distro_id == "ubuntu":
        verdict, detail = grade_ubuntu(version_id, running, package)
    elif distro_id == "debian":
        verdict, detail = grade_debian(codename, package)
        if running is not None and package is None:
            notes.append("running kernel %s recorded for reference only; Debian grade needs the package version" % fmt_kernel(running))
    elif distro_id in ("rhel", "rocky", "almalinux", "centos", "ol", "fedora"):
        verdict, detail = grade_upstream(running)
        detail += " (distro backports may differ, %s)" % RHEL_NOTE
        notes.append(RHEL_NOTE)
    else:
        verdict, detail = grade_upstream(running)
        if distro_id:
            detail += " (distro %s not in this tool's fixed-build table, upstream comparison only; distro backports may differ)" % distro_id
    return {"verdict": verdict, "detail": detail, "notes": notes}


def read_os_release(path="/etc/os-release"):
    info = {}
    try:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if not line or "=" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return info


def read_loaded_modules(path="/proc/modules"):
    loaded = set()
    try:
        with open(path) as handle:
            for line in handle:
                parts = line.split()
                if parts:
                    loaded.add(parts[0])
    except OSError:
        pass
    return loaded


def installed_kernel_packages():
    """Return a list of parsed installed kernel package versions (best effort)."""
    found = []
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}\n", "linux-image-*"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        for line in out.splitlines():
            parsed = parse_kernel(line.strip())
            if parsed is not None:
                found.append(parsed)
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not found:
        try:
            out = subprocess.run(
                ["rpm", "-qa", "kernel"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines():
                parsed = parse_kernel(line.strip().removeprefix("kernel-"))
                if parsed is not None:
                    found.append(parsed)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return found


def php_version():
    try:
        out = subprocess.run(
            ["php", "-v"], capture_output=True, text=True, timeout=15,
        ).stdout
        match = re.search(r"PHP (\d+\.\d+\.\d+)", out)
        if match:
            return match.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def newest(packages):
    if not packages:
        return None
    return max(packages, key=lambda p: (p["base"], p["abi"] or 0, p["sub"] or 0))


def build_local_result():
    os_release = read_os_release()
    distro_id = os_release.get("ID", "")
    version_id = os_release.get("VERSION_ID", "")
    codename = os_release.get("VERSION_CODENAME", "")
    running = parse_kernel(platform.uname().release)
    packages = installed_kernel_packages()
    newest_pkg = newest(packages)
    result = grade_host(distro_id, version_id, codename, running, newest_pkg)
    result["running_kernel"] = fmt_kernel(running) if running else None
    result["distro"] = "%s %s" % (distro_id, version_id) if distro_id else None
    result["installed_kernel_package"] = fmt_kernel(newest_pkg) if newest_pkg else None
    loaded = read_loaded_modules()
    present = [m for m in ESP_MODULES if m in loaded]
    result["esp_modules_loaded"] = present
    if present:
        result["notes"].append(
            "IPsec ESP modules loaded (%s): this host uses the subsystem "
            "Fragnesia corrupts, so a vulnerable kernel here is directly "
            "reachable once an attacker has any local code execution"
            % ", ".join(present)
        )
    else:
        result["notes"].append(
            "no ESP modules loaded: the vulnerable path is not active right "
            "now, but a module load or a reboot into an IPsec setup reopens it"
        )
    if newest_pkg is not None and running is not None:
        run_key = (running["base"], running["abi"] or 0, running["sub"] or 0)
        pkg_key = (newest_pkg["base"], newest_pkg["abi"] or 0, newest_pkg["sub"] or 0)
        if pkg_key > run_key:
            result["notes"].append(
                "installed kernel %s is NEWER than the running kernel %s: "
                "reboot into the installed kernel before calling this host fixed"
                % (fmt_kernel(newest_pkg), fmt_kernel(running))
            )
    if os.path.exists("/var/run/reboot-required"):
        result["notes"].append("reboot required flag is set: a kernel update is staged, reboot to activate it")
    php = php_version()
    result["php_version"] = php
    if php is not None:
        result["notes"].append(
            "PHP %s is installed on this host: Fragnesia is the second half "
            "of the PHP2Shell chain, grade the PHP side with "
            "foxcornlab/php2shell-scanner" % php
        )
    result["notes"].append(
        "Fragnesia corrupts the page cache, not the disk: check for signs of "
        "compromise BEFORE rebooting, a reboot wipes the in-memory evidence "
        "along with any backdoor"
    )
    return result


def render_text(result):
    lines = []
    lines.append("kernel: %s" % (result.get("running_kernel") or result.get("kernel") or result.get("package_version") or "?"))
    if result.get("distro"):
        lines.append("distro: %s" % result["distro"])
    if result.get("installed_kernel_package"):
        lines.append("installed package: %s" % result["installed_kernel_package"])
    lines.append("verdict: %s (%s)" % (result["verdict"], result["detail"]))
    if result.get("esp_modules_loaded") is not None:
        loaded = result["esp_modules_loaded"]
        lines.append("ESP modules loaded: %s" % (", ".join(loaded) if loaded else "none"))
    if result.get("php_version"):
        lines.append("PHP installed: %s (grade separately with php2shell-scanner)" % result["php_version"])
    for note in result["notes"]:
        lines.append("Note: %s" % note)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detection-only Fragnesia (CVE-2026-46300) kernel triage.")
    parser.add_argument("--kernel", help="Kernel version to grade, e.g. 6.6.140 or 6.8.0-124-generic")
    parser.add_argument("--ubuntu", metavar="RELEASE", help="Grade as Ubuntu release, e.g. 24.04")
    parser.add_argument("--debian", metavar="CODENAME", help="Grade as Debian release, e.g. bookworm")
    parser.add_argument("--package-version", help="Installed kernel package version, e.g. 6.8.0-124.124 (Debian: 6.1.174-1)")
    parser.add_argument("--local", action="store_true", help="Grade this host: uname, os-release, installed packages, ESP modules")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    args = parser.parse_args(argv)

    if args.local:
        result = build_local_result()
    elif args.kernel or args.ubuntu or args.debian:
        running = parse_kernel(args.kernel)
        package = parse_kernel(args.package_version)
        if args.ubuntu:
            verdict, detail = grade_ubuntu(args.ubuntu, running, package)
            distro = "ubuntu %s" % args.ubuntu
        elif args.debian:
            verdict, detail = grade_debian(args.debian, package)
            distro = "debian %s" % args.debian
        else:
            verdict, detail = grade_upstream(running)
            distro = None
        result = {
            "kernel": fmt_kernel(running) if running else args.kernel,
            "package_version": fmt_kernel(package) if package else None,
            "distro": distro,
            "verdict": verdict,
            "detail": detail,
            "notes": [],
        }
        if args.ubuntu and running is not None and package is None and verdict == UNKNOWN:
            result["notes"].append("pass --package-version with the dpkg linux-image version for a definitive grade")
    else:
        parser.print_usage(sys.stderr)
        print("error: pass --kernel, --local, or a distro flag", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))

    if result["verdict"] in (VULNERABLE, NO_FIX):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
