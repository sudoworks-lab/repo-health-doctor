# Rules

`repo-health-doctor` の JSON report は `schema_version` で出力契約を示し、finding には安定した `rule_id` と `severity` を含めます。

## Severity

- `pass`: 問題なし。finding は通常出力されません。
- `warn`: 確認推奨。`--fail-on warn` または `--strict` 指定時は exit code `1` になります。
- `block`: 公開・共有前に対応が必要。常に exit code `1` になります。

## Exit Codes

- `0`: `pass` のみ
- `0`: `warn` のみで `--fail-on block`
- `1`: `block` が 1 件以上
- `1`: `--fail-on warn` または `--strict` 指定時に `warn` が 1 件以上

`--strict` は後方互換のための alias で、通常は `--fail-on warn` を明示します。

## Finding Schema

finding は次の情報だけを返します。

- `rule_id`: 安定した rule identifier
- `severity`: `warn` または `block`
- `file`: repository root からの相対 path
- `pattern`: 中立的な検知カテゴリ
- `line`: 該当する場合のみ、1 始まりの行番号
- `size_bytes`: size 系 rule の場合のみ
- `redacted`: 検知値や証跡値をそのまま出していないかどうか

raw の検知文字列、secret 候補、個人環境由来の値、local network 値は report に含めません。

## Rule IDs

| rule_id | 目的 | severity | 出力される情報 | redaction |
| --- | --- | --- | --- | --- |
| `rhd.secret.aws_access_key` | access key 形式の secret 候補を検知する | `block` | file, line, category | raw value は出さない |
| `rhd.secret.github_token` | token 形式の secret 候補を検知する | `block` | file, line, category | raw value は出さない |
| `rhd.secret.slack_token` | token 形式の secret 候補を検知する | `block` | file, line, category | raw value は出さない |
| `rhd.secret.private_key` | private key 形式の secret 候補を検知する | `block` | file, line, category | raw value は出さない |
| `rhd.secret.generic_api_key` | key / token / secret 形式の secret 候補を検知する | `block` | file, line, category | raw value は出さない |
| `rhd.public_text.restricted_term` | 公開本文に不向きな語句カテゴリを検知する | `block` | file, line, category | raw value は出さない |
| `rhd.public_text.private_path` | 個人環境由来の path カテゴリを検知する | `block` | file, line, category | raw value は出さない |
| `rhd.public_text.local_ip` | local network 値カテゴリを検知する | `block` | file, line, category | raw value は出さない |
| `rhd.repository.missing_readme` | README が見当たらない状態を検知する | `warn` | file, category | raw value は出さない |
| `rhd.repository.missing_license` | LICENSE が見当たらない状態を検知する | `warn` | file, category | raw value は出さない |
| `rhd.repository.missing_ci` | workflow file が見当たらない状態を検知する | `warn` | file, category | raw value は出さない |
| `rhd.repository.missing_tests` | tests または test directory が見当たらない状態を検知する | `warn` | file, category | raw value は出さない |
| `rhd.repository.large_file` | repository に大きい file が含まれる状態を検知する | `warn` | file, size_bytes, category | file content は読まない |
| `rhd.tracked_artifact.generated_dir` | tracked された生成物 directory 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.cache_dir` | tracked された cache directory 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.generated_file` | tracked された生成物 file 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.env_file` | tracked された環境 file 候補を検知する | `block` | file, category | content は出さない |
| `rhd.policy.invalid_config` | policy file を読み込めない、または解釈できない状態を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.invalid_ignore` | ignore policy の形式不備を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.invalid_allow` | allow policy の必須 field 不足や形式不備を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.expired_allow` | 期限切れ allow policy を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.unknown_rule_id` | 未定義 rule_id を参照する allow policy を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.unknown_top_level_key` | 未知の top-level key を含む policy を検知する | `block` | policy source, policy id, category | raw config value は出さない |
| `rhd.policy.restricted_secret_allow` | fixture 以外で secret 系 rule を allow しようとする policy を検知する | `block` | policy source, policy id, category | raw config value は出さない |

## CLI UX Note

`validate-policy` mode は scan を実行せずに policy の破損を検出します。
policy validation の finding も通常の JSON report と同じ `schema_version: 1.1`, `rule_id`, `severity`, `redacted` 契約に従います。
