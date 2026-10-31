# `fragnesia-scanner`

Local triage for `Fragnesia`, the `Linux` kernel privilege escalation `CVE-2026-46300`. Give it a kernel version you own, it tells you whether that build is still open, and it catches the traps that make a version check lie. It never touches the network, never loads an exploit, never triggers the bug.

## `The flaw`

| `Detail` | `Value` |
| --- | --- |
| `CVE` | `CVE-2026-46300`, nicknamed `Fragnesia`, a `Dirty Frag` variant |
| `Bug` | `skb_try_coalesce()` drops the shared-frag marker, so `ESP-in-TCP` input decrypts in place over page-cache pages (`CWE-456`) |
| `Impact` | A local user rewrites the cached contents of files they may only read. The public proof of concept targets the cached copy of `/usr/bin/su`, so the next run of that program executes attacker code as `root` |
| `Severity` | `7.8` high, scored by the kernel `CNA` and `NVD` (`AV:L/AC:L/PR:L/UI:N`) |
| `Exploitation` | Added to `CISA KEV` on `2026-10-28`, federal due date `2026-10-31`, flagged for forensic triage. `CISA`'s entry says it can be chained with the `PHP2Shell` flaws to implant `PHP` webshells and run commands as `root` |
| `The chain` | `Dream Security` reported the chain rooting `25` firewall appliances, including systems on a `US` government-affiliated network: `PHP2Shell` gets code running as the web user, `Fragnesia` turns it into `root`, even under `SELinux` confinement, because it never asks the filesystem for write access |

`Fragnesia` is not a remote attack. Nobody uses it against a server from the network alone. It needs code already running on the machine, which is exactly what a webshell, a stolen `SSH` login, or a compromised `CI` job provides. That is why it pairs with `foxcornlab/php2shell-scanner`: grade the `PHP` side there, grade the kernel side here.

## `Fixed versions`

### `Upstream stable` (fix commit `f84eca581739`)

| `Line` | `Fixed in` |
| --- | --- |
| `7.0` | `7.0.10` |
| `6.18` | `6.18.33` |
| `6.12` | `6.12.91` |
| `6.6` | `6.6.141` |
| `6.1` | `6.1.174` |
| `5.15` | `5.15.208` |
| `5.10` | `5.10.257` |
| `7.1` and later | `Not affected` |
| `Older than 3.9` | `Not affected`, per the `CVE` record |
| `Any other line` (e.g. `6.17`, `6.5`) | `No upstream fixed release listed`, move to a fixed line |

### `Ubuntu` (exact fixed builds)

| `Release` | `Fixed build` |
| --- | --- |
| `26.04` | `7.0.0-22.22` |
| `25.10` | `6.17.0-35.35` |
| `24.04` | `6.8.0-124.124` |
| `22.04` | `5.15.0-181.191` |
| `20.04` standard `5.4` kernel | `Listed as not affected` by `Ubuntu` |
| `20.04` `5.15 HWE` kernel | `Ubuntu Pro` only, check your `Pro` advisory |

### `Debian` (exact fixed builds)

| `Release` | `Fixed build` |
| --- | --- |
| `13 trixie` | `6.12.90-1` (`DSA-6295-1`) |
| `12 bookworm` | `6.1.174-1` (`DSA-6306-1`) |
| `11 bullseye` | `5.10.257-1` (`DLA-4606-1`) |

### `RHEL` and derivatives

Per stream, see `RHSA-2026:19521` and later. This tool grades `RHEL` hosts against the upstream fix and names the advisory, because `Red Hat` publishes no single version number this tool can grade against.

## `Where sources disagree`

Two disagreements, both followed deliberately. One secondary write-up of the `October 28 KEV` update prints `2.7` for this `CVE`; that is the `VMware ESX` score from the same update, swapped onto the kernel entry. `NVD`, the kernel `CNA` and `Red Hat` all say `7.8`, so this tool follows `7.8`. Second: `NVD`'s range for the `5.10` line runs through `5.10.257`, while the upstream record and `Debian` both list `5.10.257-1` as the fixed build. This tool follows upstream and `Debian` and grades `5.10.257` as fixed.

## `Trap 1: uname hides the upload number`

`Ubuntu`'s fixed build for `24.04` is `6.8.0-124.124`. `uname -r` prints `6.8.0-124-generic`. The upload number after the second dot never appears in `uname` output, so a running kernel whose `ABI` matches the fixed `ABI` cannot be cleared from `uname` alone. This tool grades that case `UNKNOWN`, not clean, and tells you to check the installed `linux-image` package version. An `ABI` below the fixed `ABI` is definitively `VULNERABLE`; an `ABI` above it is `FIXED`. Pass `--package-version` with the `dpkg` version for a definitive grade.

## `Trap 2: installed is not booted`

A fixed kernel package that is installed but not running does nothing. `--local` compares the running kernel against the newest installed kernel package and says so plainly when they differ, and it flags `/var/run/reboot-required` when a kernel update is staged.

## `Trap 3: the evidence lives in memory, not on disk`

`Fragnesia` writes into the kernel's page cache and never touches the disk. A reboot clears the backdoor and the evidence together. If you suspect a host was touched, look before you restart anything: compare a normal read of a file against a direct read that bypasses the cache, and collect what you need first. File-integrity tools that only hash stored files after a reboot will miss it.

## `What it checks`

- `A kernel version you supply` (`--kernel`), graded against the upstream fix table
- `An Ubuntu release` (`--ubuntu 24.04`) with the `ABI` trap above, or `--package-version` for a definitive grade
- `A Debian release` (`--debian bookworm`) from the installed package version (`Debian uname` strings carry only an `ABI` number, so they grade `UNKNOWN` on their own)
- `This host` (`--local`): running kernel, `os-release`, newest installed kernel package, loaded `ESP` modules (`esp4`, `esp6`, `rxrpc`), reboot-required flag, and whether `PHP` is installed (graded separately, see below)
- `ESP module presence`: a vulnerable kernel with `esp4`/`esp6` loaded has the reachable path active right now

## `Usage`

```sh
# grade one version
python3 fragnesia_scanner.py --kernel 6.6.140

# Ubuntu 24.04, uname only (ABI match -> UNKNOWN, upload hidden)
python3 fragnesia_scanner.py --ubuntu 24.04 --kernel 6.8.0-124-generic

# Ubuntu 24.04, definitive grade from the installed package
python3 fragnesia_scanner.py --ubuntu 24.04 --kernel 6.8.0-124-generic --package-version 6.8.0-124.124

# Debian bookworm from the installed package
python3 fragnesia_scanner.py --debian bookworm --package-version 6.1.174-1

# this host, everything at once
python3 fragnesia_scanner.py --local

# machine-readable output for fleets
python3 fragnesia_scanner.py --local --json
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean.

## `The PHP half of the chain`

If `--local` finds `PHP` on the host, it says so and points at `foxcornlab/php2shell-scanner` for the `PHP` grade. This tool deliberately does not grade `PHP` itself: that scanner already owns the `PHP 8.2.35`, `8.3.36`, `8.4.27` and `8.5.12` fix table, and one tool owning one fix table beats two tools drifting apart.

## `Mitigation if you cannot patch today`

Block the `esp4` and `esp6` modules with a `modprobe` install rule and unload them. That turns off `IPsec` on the host, so do not use it on `VPN` gateways. It is a stopgap, not a fix: patch the kernel and reboot into it.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`19` tests: upstream boundary for every fixed line, the `Ubuntu ABI` trap in all three directions, `Debian` package comparison, the `20.04` special cases, `RHEL` advisory notes, and version parsing for all four string shapes.

## `Thanks to`

- `William Bowling` and the `V12` team, who disclosed `Fragnesia` on `13 May 2026`
- `Wiz`, for the technical analysis of the page-cache corruption
- `Dream Security`, for documenting the `PHP2Shell` + `Fragnesia` chain in the wild
- `CISA`, for the `KEV` listing and the chain note that made the urgency clear
- The `Linux` kernel team, for the fix and the `CNA` record

## `Disclaimer`

Defensive triage only. This tool checks version strings and reports whether a kernel build is in a fixed range. It sends no traffic, triggers no vulnerability, and is not a substitute for your distribution's advisory. Use it on systems you own or are authorised to audit.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
