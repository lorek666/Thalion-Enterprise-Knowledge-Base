# 私有合成权限配置模板（`synthetic_local`）

本目录仅提供脱敏结构模板，**不包含任何有效令牌、真实员工信息或企业权限数据**。`credentials.json` 中的 `token_sha256` 全部使用 64 位 `0` 占位，切勿在真实环境直接使用。

## 准备私有配置目录

`thalion-serve` 启动前会强制校验配置目录及其 JSON 文件的权限与属主，不满足条件将拒绝启动：

1. 创建独立的私有目录（建议在 `/var/lib/thalion/profile` 与 `/var/lib/thalion/originals`），并设置为 `0700`：

```bash
install -d -m 0700 /var/lib/thalion/profile /var/lib/thalion/originals
install -m 0600 deploy/synthetic-profile.example/credentials.json /var/lib/thalion/profile/credentials.json
install -m 0600 deploy/synthetic-profile.example/source-grants.json /var/lib/thalion/profile/source-grants.json
```

2. 为本地合成测试令牌计算 SHA-256 摘要，并替换 `credentials.json` 中的 `token_sha256`（每位员工令牌摘要必须唯一，且 `employee_ref` / `space_ref` 与数据库注册记录一致）：

```bash
python3 -c 'import hashlib, secrets; tok = secrets.token_hex(24); print("SHA256:", hashlib.sha256(tok.encode("ascii")).hexdigest())'
```

3. 将允许该合成员工读取的片段/文档公开 UUID 填入 `source-grants.json`。

## 可选扩展授权文件（均须为 `0600`）

按合成联调场景按需创建，不存在时默认为空授权（fail-closed）：

- `model-source-grants.json`：允许合成模型派发使用的 `(employee_ref, purpose, passage_id, revision, fields)` 列表（启用模型派发时还须配置独立撤权库）。
- `pdf-page-grants.json`：允许 PDF 页图预览的对象 UUID 列表。
- `original-download-grants.json`：允许员工整件下载的版本 UUID 列表（同时仍须满足逐片段源端读取权限）。
- `archive-grants.json`、`wiki-archive-grants.json`、`transcript-archive-grants.json`、`rebuild-archive-grants.json`、`repair-history-archive-grants.json`：生命周期与空间封存导出授权。
- `feedback-retest-key.json`：单值 64 位十六进制密钥字符串，用于纠错原题复测凭证校验。

严禁将生成的真实私钥、令牌明文或私有配置目录提交到 Git 仓库。
