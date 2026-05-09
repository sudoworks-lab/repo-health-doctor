# Rules

`repo-health-doctor` の JSON report は `schema_version` で出力契約を示し、finding には安定した `rule_id` と `severity` を含めます。

## Severity

- `pass`: 問題なし。finding は通常出力されません。
- `warn`: 確認推奨。`--strict` 指定時は exit code `1` になります。
- `block`: 公開・共有前に対応が必要。常に exit code `1` になります。

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
| `rhd.repository.large_file` | repository に大きい file が含まれる状態を検知する | `warn` | file, size_bytes, category | file content は読まない |
| `rhd.tracked_artifact.generated_dir` | tracked された生成物 directory 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.cache_dir` | tracked された cache directory 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.generated_file` | tracked された生成物 file 候補を検知する | `block` | file, category | content は出さない |
| `rhd.tracked_artifact.env_file` | tracked された環境 file 候補を検知する | `block` | file, category | content は出さない |

## Phase2-B Note

次の段階では allowlist / ignore 設定ファイルを追加し、rule_id 単位で理由・期限・対象 path を管理できるようにする予定です。Phase2-A では設定ファイルの読み込みや allowlist 判定は実装しません。
