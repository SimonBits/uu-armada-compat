# 仓库布局 / Repository layout

`package/` 是 v0.1.0 发布压缩包解压后的原样内容，包含唯一一套安装器、两套模块及对应源码、配置和完整性清单。根目录 README、LICENSE、TECHNICAL.md 与发布包逐字节一致；根目录 SOURCE.md 另行补充完整对应源码附件的交付说明，package/ 内原始文件保持不变。

普通用户请从 GitHub Release 下载 `uu-armada-compat-0.1.0.tar.gz` 和对应 `.sha256`，按 README 校验、解压后安装。GitHub 自动生成的 Source code 压缩包是仓库快照，不是该安装压缩包。

开发审查从 `package/runtime/`、`package/systemd/` 和 `package/kernels/` 开始。不要把 `.git`、诊断报告或其他文件加入 `package/`，安装器会严格检查额外文件。`release/` 保存中英文发布说明、标题和附件校验文件；安装压缩包本身不进入 Git 历史。

The `package/` directory is byte-for-byte identical to the extracted release archive, including executable modes and its original manifest. Root README, LICENSE and TECHNICAL.md are copied unchanged; SOURCE.md also documents the separate corresponding-source attachment. Release assets are distributed separately, not committed. No module is rebuilt or stripped.

Source scope is stated in SOURCE.md. The independent complete corresponding-source attachment contains the original kernel archive, both patch/DTS sets and the validated build method. It is a separate Release asset and is not stored in Git history. The original binary package remains byte-identical. No private device evidence has been imported.
