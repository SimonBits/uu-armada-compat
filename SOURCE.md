# Source and licensing

Project scripts and Linux xt_nat module sources are GPL-2.0-only. See LICENSE and each kernels/<build>/source/COPYING.GPL-2.0. No UU binaries, account data, Steam Deck files, stock dependency modules or private logs are included.

Both modules are reused byte-for-byte from preserved, device-tested artifacts. No module was rebuilt for this release. This package contains a single installer and two independent profiles; OS labels are descriptive, not identity gates.

## 20260926.c2fd048

- Official Armada source/configuration context: https://github.com/armada-os/armada/tree/c2fd0485b4dbc4947319d4a512f8061bdc8e7660
- Kernel: 7.2.6, `#1 SMP PREEMPT Sun Sep 27 03:45:50 UTC 2026`.
- Kernel Build ID: `834935cf865cb789843775a107783639c72d74cf`.
- Module Build ID: `d8212f5e6259c0e2453a5dcf84255e2a7f5db4d9`.
- Module SHA-256: `f2e9c6d1993c924196b5d06cbb7850bba82f4734107c1c2af0f841bc02360537`.
- Vermagic: `7.2.6 SMP preempt mod_unload aarch64`.
- Configuration SHA-256: `9c95ab78712b0ea97cc40b09d60a57b5d517e9567911b94f4fd16e8dd9ddf5e2`.

## 20261010.c3d178c

- Official Armada source/configuration context: https://github.com/armada-os/armada/tree/c3d178c9e5cc7107aaa128b8c1f384a9c6bd8dfa
- Kernel: 7.2.6, `#1 SMP PREEMPT Fri Oct  9 12:18:51 UTC 2026`.
- Kernel Build ID: `7ea1d05956372315de207e53aec37aa6ffe002f7`.
- Module Build ID: `4072da4cea38d934c9e888f2eab69bb74da01fa8`.
- Module SHA-256: `8dd14c08888216995dfad5e56032bbf4c6c8bf36bcb42befb82b8f627aaafa3b`.
- Vermagic: `7.2.6 SMP preempt mod_unload aarch64`.
- Configuration SHA-256: `3cae56750274cbd5b90a788335389dfbd38ad9fcb526505593ee878dc208a04f`.

Each source directory contains xt_nat.c, Kbuild, target-kernel.config and recovered-nat-exports.symvers. Modules were built with Kbuild in isolated ARM64 cross-build environments using ARCH=arm64, GCC 16.2.1 and KBUILD_EXTRA_SYMBOLS referencing exports recovered from the corresponding official kernel/dependencies. The C source SHA-256 is 4f21fcef0fe40de78fa054ecc5426fe3fe3c4b15ef0b2897cf5dcf32f7248c09 for both.

Official Module.symvers/SDK was unavailable. CONFIG_MODVERSIONS=n; recovered export material is NOT an official symbol-version file. Cross compiler package revision differs from the target compiler. Selected symbol/type checks are not a complete ABI proof; nf_nat_range lacked reference BTF layout. Successful device tests do not eliminate all runtime risk. Kernel, config, exact stock dependency files, runtime Build IDs and loading policies remain strict.

Full official source trees, original build commands, toolchain provenance and ABI evidence remain in the development workspace. They are not installer dependencies. Installation never downloads or compiles components. Included inputs document the independent builds; no claim of byte-reproducible rebuilding with an arbitrary toolchain is made.

The production native-only isolated DNAT check and systemd unit are unchanged from the validated 1010 tool. The separate 0926 experiment additionally validated FEX DNAT. The preserved 0926 experiment verifies initial loading, native/FEX isolated DNAT, user-reported acceleration, and normal unloading. The user subsequently reported completion of the dual-kernel candidate's main device validation. This release-preparation task did not access devices or collect new per-case logs. Repeat-session counts, sustained-duration evidence and final-package migration acceptance are not inferred from offline tests; see TECHNICAL.md.

This is an independent community tool, not an official UU or Armada product. It does not include, modify, or distribute UU software. Original module bytes (including compiler-generated debug/source paths) are retained for identity compatibility; no runtime logs, credentials or pairing data are bundled.
