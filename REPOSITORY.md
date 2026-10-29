# 仓库布局 / Repository layout

`package/` 是 v0.1.0 发布压缩包解压后的原样内容，包含唯一一套安装器、两套模块及对应源码、配置和完整性清单。根目录 README、LICENSE、SOURCE.md、TECHNICAL.md 与发布包逐字节一致。

普通用户请从 GitHub Release 下载 `uu-armada-compat-0.1.0.tar.gz` 和对应 `.sha256`，按 README 校验、解压后安装。GitHub 自动生成的 Source code 压缩包是仓库快照，不是该安装压缩包。

开发审查从 `package/runtime/`、`package/systemd/` 和 `package/kernels/` 开始。不要把 `.git`、诊断报告或其他文件加入 `package/`，安装器会严格检查额外文件。`release/` 保存中英文发布说明、标题和附件校验文件；安装压缩包本身不进入 Git 历史。

The `package/` directory is byte-for-byte identical to the extracted release archive, including executable modes and its original manifest. Root documentation is copied unchanged. Release assets are distributed separately, not committed. No module is rebuilt or stripped.

Source scope and limits are stated in SOURCE.md: module C sources, Kbuild inputs, target configurations and recovered exports are included. Full kernel build trees, original build commands and toolchain provenance are not bundled here. This preparation does not establish completeness of corresponding source for binary redistribution; that remains a publication review item. No private development evidence has been imported.
