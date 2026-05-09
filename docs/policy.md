# Policy

`repo-health-doctor` は repository root の `repo-health-doctor.yml` を公開用 policy として読み込みます。
`.repo-health-doctor.local.yml` は local override 用で、git 管理外に置く前提です。

外部 dependency を増やさないため、policy file は JSON または限定的な YAML subset として読み込みます。
対応する YAML は top-level の `ignore_paths` と `allow_findings`、list、文字列値だけです。

## Config Files

- `repo-health-doctor.yml`: repository に含める公開用 policy
- `.repo-health-doctor.local.yml`: local 専用 policy
- `--config <file>`: 公開用 policy path を明示する
- `--local-config <file>`: local policy path を明示する
- `--no-local-config`: local policy を読み込まない

## Validation

scan を実行せず policy だけを検証するには `validate-policy` mode を使います。

```bash
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json
repo-health-doctor validate-policy . --no-local-config
```

`validate-policy` は policy file の読み込み、`ignore_paths` の形式、`allow_findings` の必須 field、期限、rule_id、secret 系 rule の allow 制約を検証します。
block 条件がある場合は通常の report と同じ JSON 契約で `overall_status: block` を返します。

config format の schema は [../schemas/policy-config.schema.json](../schemas/policy-config.schema.json) にあります。

## Public Safetyとの使い分け

- `repo-health-doctor . --public-safety`: repository 内容を走査し、公開前に確認すべき finding を検出します。
- `repo-health-doctor validate-policy .`: repository 内容は走査せず、policy file の形式と期限、rule_id、allow 制約だけを検証します。

CI では両方を実行すると、scan 結果と policy 破損を別々に確認できます。

## ignore_paths

`ignore_paths` は scan 前に path pattern で対象を除外します。
除外 path は report にそのまま出さず、count だけを返します。

```yaml
ignore_paths:
  - <relative-path-pattern>
```

## allow_findings

`allow_findings` は検出後の例外です。scan 自体は実行され、matched finding には safe な policy id だけが付きます。

必須 field:

- `rule_id`
- `path`
- `reason`
- `owner`
- `expires`

```yaml
allow_findings:
  - rule_id: <rule-id>
    path: <relative-path-pattern>
    reason: <reason-category>
    owner: <owner-category>
    expires: <yyyy-mm-dd>
```

## Blocking Policy Errors

次の policy error は `block` です。

- required field が不足している allow
- 期限切れの allow
- 存在しない rule_id の allow
- fixture path 以外に対する secret 系 rule の allow
- 読み込めない、または解釈できない policy file

secret 系 rule は原則 allow できません。test fixture として明確に分離された path のみ例外対象にできます。

## Report Safety

Policy 由来の具体値、reason、owner、path pattern は text / JSON report にそのまま出しません。
JSON には `policy_sources`, count, `matched_policy_id`, `policy_source` のような安全な情報だけを返します。
公開 docs には組織固有の禁止語や具体的な検知値を例示しない方針です。
