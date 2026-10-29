# UU Armada Compatibility v0.1.0

An independent compatibility tool providing exact-build xt_nat modules for Armada ARM64. It addresses the DNS DNAT initialization incompatibility observed with the official UU Linux accelerator. After installation, the module is prepared at boot; users control acceleration through the official UU mobile app.

**Not an official UU or Armada product. This tool does not include, modify, or distribute UU software.**

## Supported builds

- Armada `20260926.c2fd048`
- Armada `20261010.c3d178c`

One installer selects the module using the running kernel Build ID, configuration, dependencies, ABI and module fingerprints. Other builds and changed kernels after OTA are not guaranteed to work. Mismatches stop installation or safely skip boot-time loading.

## Included

- install.sh, upgrade.sh, uninstall.sh and status.sh.
- Boot-time loading, idempotent installation, offline upgrades and safe uninstall transactions.
- Busy uninstall refusal preserves boot-time loading and the installed state.
- `sudo ./status.sh --must-gather` creates an allowlisted English diagnostic archive in the original caller's home directory.
- Both original modules are reused without rebuilding; source inputs, profiles, licenses and provenance are retained.

Download the archive and checksum, verify them, extract into a separate directory and follow the Chinese README. Install and pair official UU separately. This tool never starts acceleration automatically.

Users of the verified dual-kernel candidate should stop acceleration and run `sudo ./upgrade.sh` from this release. Only complete, explicitly recognized predecessor manifests are migrated. Unknown modifications and incomplete uninstall states are not overwritten.

## Known issue and validation limits

Device discovery can be delayed after specific reboot scenarios in a TF/microSD environment. The cause is unconfirmed; this is not attributed to xt_nat.

The user reported completion of the candidate's main device validation. Release preparation itself is offline only. Exact repeat-session counts, long-duration stability evidence for 0926, and acceptance of migration to this final package still require individual records. Offline tests do not establish those results.

External kernel-module risk remains. Keep local recovery available. No forced load/unload, bootc/boot-partition changes, or UU binary changes are performed. See SOURCE.md and TECHNICAL.md for provenance and limits. License: GPL-2.0-only.
