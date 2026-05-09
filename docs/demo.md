# Demo

この page は、安全な sample repo を使って `repo-health-doctor` の流れを短く確認するためのものです。
例は project root から実行する前提です。

## 1. Prepare A Small Sample Repo

```bash
rm -rf /tmp/repo-health-doctor-demo
cp -R tests/fixtures/demo-repo /tmp/repo-health-doctor-demo
git -C /tmp/repo-health-doctor-demo init
git -C /tmp/repo-health-doctor-demo add .
```

この sample repo は README、LICENSE、workflow、tests、docs、scripts、公開用 policy を含みます。

## 2. Run Public Safety

```bash
PYTHONPATH=src python3 -m repo_health_doctor /tmp/repo-health-doctor-demo --public-safety
```

最初は `PASS` の流れを見るのが目的です。

## 3. Validate Policy Only

```bash
PYTHONPATH=src python3 -m repo_health_doctor validate-policy /tmp/repo-health-doctor-demo
```

`validate-policy` は scan を走らせず、policy file 自体の整合だけを返します。

## 4. Save JSON Artifacts

```bash
PYTHONPATH=src python3 -m repo_health_doctor /tmp/repo-health-doctor-demo --public-safety --format json --output /tmp/repo-health-doctor-demo-public-safety.json
PYTHONPATH=src python3 -m repo_health_doctor validate-policy /tmp/repo-health-doctor-demo --format json --output /tmp/repo-health-doctor-demo-policy.json
python3 -m json.tool /tmp/repo-health-doctor-demo-public-safety.json >/dev/null
python3 -m json.tool /tmp/repo-health-doctor-demo-policy.json >/dev/null
```

artifact を残しておくと、local review と CI の両方で同じ JSON を扱えます。
この sample repo の正規化済み出力は次の golden fixture でも確認できます。

- `tests/fixtures/golden/public-safety-demo.json`
- `tests/fixtures/golden/policy-demo.json`
- `tests/fixtures/golden/public-safety-demo.txt`

## 5. Read The Result

- `PASS`: 問題なし
- `WARN`: 確認推奨。`--fail-on block` では成功、`--fail-on warn` では失敗
- `BLOCK`: 公開・共有前に対応が必要

JSON では `schema_version`, `overall_status`, `summary`, `checks` を見れば十分です。
finding がある場合も raw の検知値は出ず、`rule_id` と中立的な category を使います。
