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

The complete corresponding source is now supplied as a separate versioned attachment described below. It includes the original Linux archive, both Armada patch/DTS inputs, actual build configurations, generated-input provenance, installation sources and an independently validated offline build entry. The frozen binary installation archive and its embedded SOURCE.md remain unchanged; this repository document supplements that original statement. Installation never downloads or compiles components.

The production native-only isolated DNAT check and systemd unit are unchanged from the validated 1010 tool. The separate 0926 experiment additionally validated FEX DNAT. The preserved 0926 experiment verifies initial loading, native/FEX isolated DNAT, user-reported acceleration, and normal unloading. The user subsequently reported completion of the dual-kernel candidate's main device validation. This release-preparation task did not access devices or collect new per-case logs. Repeat-session counts, sustained-duration evidence and final-package migration acceptance are not inferred from offline tests; see TECHNICAL.md.

This is an independent community tool, not an official UU or Armada product. It does not include, modify, or distribute UU software. Original module bytes (including compiler-generated debug/source paths) are retained for identity compatibility; no runtime logs, credentials or pairing data are bundled.

## Complete corresponding source attachment

- File: `uu-armada-compat-0.1.0-source.tar.xz` (162804052 bytes).
- SHA-256: `12bddc1d15ebf829e811c59e1346e687a702676815b31b06178a4d76f74c7ea5`.
- Checksum file: `uu-armada-compat-0.1.0-source.tar.xz.sha256`.
- Planned publication: [v0.1.0 Release](https://github.com/SimonBits/uu-armada-compat/releases/tag/v0.1.0). These are local prepared assets, not a claim that a tag or Release already exists.
- After publication: [source attachment](https://github.com/SimonBits/uu-armada-compat/releases/download/v0.1.0/uu-armada-compat-0.1.0-source.tar.xz) and [checksum](https://github.com/SimonBits/uu-armada-compat/releases/download/v0.1.0/uu-armada-compat-0.1.0-source.tar.xz.sha256).

Upload both alongside the unchanged binary archive and its checksum. GitHub's automatically generated repository source archives do not contain the full kernel source attachment and must not be presented as its replacement.

### Correspondence and rebuilding

The module hashes and Build IDs in the two sections above remain authoritative for the tested binaries. Inside the source attachment, SOURCE-MAP.json associates each binary with Linux 7.2.6 (archive SHA-256 `039aef84f2b0994aeda3f4fcfc3d02ec9d7a9bbb9020ea264c43f446c860f606`), its exact Armada commit, patches/DTS, actual build.config, target.config, xt_nat.c, Kbuild and recovered exports. The complete base archive includes interface headers, modpost and scripts/module-common.c; build.py regenerates the headers, linker script and xt_nat.mod.c needed to link all three compilation units.

```sh
sha256sum -c uu-armada-compat-0.1.0-source.tar.xz.sha256
tar -xf uu-armada-compat-0.1.0-source.tar.xz
cd uu-armada-compat-0.1.0-source
sha256sum -c SHA256SUMS
python3 build.py --target 20260926.c2fd048 --workdir /absolute/new-build-0926 --cross-compile aarch64-linux-gnu-
python3 build.py --target 20261010.c3d178c --workdir /absolute/new-build-1010 --cross-compile aarch64-linux-gnu-
```

Read the attachment README and TOOLCHAIN.json before building. Prerequisites must already be present; the build downloads or installs nothing and requires an unused output directory. It verifies exact configurations and does not copy expected files over a failed generation result. Historical scripts are retained with local workstation roots replaced by /build-reference; their original and delivered hashes are documented. Provided recovered exports allow the module build without original reference binaries or a full kernel build. The actual historical recovery algorithms and reference identities remain included for review.

Both targets were rebuilt in fresh offline namespaces using only delivered inputs, generic host tools and the recorded isolated toolchain; historical source/build trees were not mounted. Configurations and 66 generated reference files per target matched exactly. All 46 ELF sections other than debug path strings, their two relocation sections and GNU Build ID were byte-identical to the corresponding original module. The dependencies, undefined symbols and vermagic matched. The validation outputs are not replacement release modules, were not loaded, and do not establish additional device/ABI coverage. See [source-delivery review](release/SOURCE-DELIVERY.md).

### License and privacy scope

Project scripts remain GPL-2.0-only. Armada-owned scripts retain GPL-2.0-or-later; kernel/patch/DTS files retain their original licenses and copyright notices. The complete Linux COPYING and LICENSES tree is inside the original upstream archive, and exact-commit Armada LICENSE.md notices are included. These are not uniformly relicensed as GPL-2.0-only.

The unmodified upstream Linux archive contains a public SGX selftest key at tools/testing/selftests/sgx/sign_key.pem, SHA-256 `1f6566d02247dc09d4dcb542ee2399522ceebf9b435ee00fe2053aa5582541e2`. This is a published test fixture, not a device, account or release-signing credential; never reuse it as one. It is explicitly retained, so no claim of zero private-key-format files is made. No user credentials or device logs are bundled. Original released modules still retain their disclosed compiler paths; the source companion does not strip or alter them.

The previously identified engineering source-completeness gaps have been filled and independent builds succeeded. This is not a guarantee of every legal interpretation of GPL obligations. Keep equivalent access to the corresponding source available with the binary distribution.
