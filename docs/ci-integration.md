# CI Integration

`repo-health-doctor` は JSON を machine gate に、Markdown を maintainer review に使い分ける想定です。
この page では GitHub Actions での最小構成と Step Summary 連携を示します。

## Minimal CI Gate

install 済み環境では、まず JSON を gate 用 artifact として保存します。

```bash
repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
repo-health-doctor validate-policy .
```

`--strict` は `WARN` と `BLOCK` のどちらでも失敗させる gate 向けです。

## GitHub Step Summary

maintainer 向けの読みやすい report を残したい場合は Markdown を別 file に出してから `GITHUB_STEP_SUMMARY` へ追記します。

```bash
repo-health-doctor . --strict --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
cat /tmp/repo-health-doctor-summary.md >> "$GITHUB_STEP_SUMMARY"
```

Markdown report には title、target repo path、overall status、summary counts、status meanings、checks、redacted findings が含まれます。
raw secret-like value、private path の実値、local IP の実値、policy allow 対象の生値は出しません。

## GitHub Actions Example

```yaml
- name: Install repo-health-doctor
  run: python3 -m pip install -e .

- name: Run repo-health-doctor gate
  run: |
    repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json
    python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
    repo-health-doctor . --strict --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
    cat /tmp/repo-health-doctor-summary.md >> "$GITHUB_STEP_SUMMARY"
    repo-health-doctor validate-policy .
```

## Notes

- JSON は downstream automation や artifact 保存向けです。
- Markdown は Step Summary、review log、手元の確認用に向いています。
- `--output` は format に関係なく使えます。
