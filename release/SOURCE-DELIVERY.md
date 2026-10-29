# v0.1.0 corresponding-source delivery review

Source asset: uu-armada-compat-0.1.0-source.tar.xz

SHA-256: `12bddc1d15ebf829e811c59e1346e687a702676815b31b06178a4d76f74c7ea5`

Size: 162804052 bytes; 680 outer files; archive extraction, file hashes and file modes verified against staging. The nested Linux archive is the unchanged complete 7.2.6 source, including its license tree.

| Target | Series patches | DTS files / patches | Successful commands | Generated references matched |
|---|---:|---:|---:|---:|
| 20260926.c2fd048 | 166 | 31 / 19 | 376 | 66 |
| 20261010.c3d178c | 192 | 32 / 21 | 432 | 66 |

Counts are successful preparation/build commands, not independent unit tests. Both builds started from a new extracted source tree in an unshared network namespace. Only /usr, /etc, generic device/proc mounts, the isolated toolchain, read-only source delivery and one writable fresh output directory were exposed; historical source/build trees and devices were not available. The supplied build.py produced exact recorded configurations. No Image, dependency module, production module replacement or device operation was performed.

The two rebuilt outputs share SHA-256 `4771ef4e03aadbc497ff41b109ba9dd80a19474863d3cf5e6b0282f0c43f7727` and Build ID `5dde3106e3a06cf78c0e4058e96c8e6e1e43972e` in the normalized sandbox paths. This does NOT authorize profile/module interchange on devices. Versus each original, only .debug_line_str, .rela.debug_info, .rela.debug_line and .note.gnu.build-id differ. Normalizing the recorded old/new directory prefixes makes the debug path string sets identical. The other 46 ELF sections, module dependencies, undefined symbols and vermagic match. These results support source correspondence; they are not complete ABI proof or new runtime validation.

The attachment supplies all three compilation units (including generation inputs for xt_nat.mod.c), required headers/Kbuild/modpost, actual and target configurations, exact recovered exports, preparation/link commands, historical algorithms and installation sources. Toolchain package versions and hashes are documented; compiler executables/packages and original reference kernel binaries are not redistributed. The provided exports remove the need for those reference binaries in this build. Full original patch sets and license notices are retained. The kernel's normal MODVERSIONS=n state, absent official SDK and skipped optional module BTF are documented, not bypassed.

Project code is GPL-2.0-only; Armada-owned code retains GPL-2.0-or-later and other upstream files retain their own notices. No uniform relicensing was performed. GPL v2 section 3 is the source-delivery reference: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html . Source and binary assets should be offered together with equivalent access. Engineering source-completeness checks passed; this is not a blanket legal guarantee.

Privacy review found no user account configuration, device logs, private signing credentials, workstation-root paths or GitHub tokens in the outer attachment. The unchanged Linux archive includes its publicly distributed SGX selftest key (tools/testing/selftests/sgx/sign_key.pem); this is a disclosed upstream test fixture, not a secret. Upstream contributor credits and test data remain. No assertion of zero PEM private-key markers is made. No validated binary was stripped or rewritten.

No device tests, Push, tag creation or GitHub Release were performed. The original binary archive SHA-256 remains `84ec92ce1fda641bf7d5ef718c6a21391a62919d1d87de21f10930cfa08d0a26`. Final publication and acceptance of the explicitly disclosed public test fixture await maintainer review.
