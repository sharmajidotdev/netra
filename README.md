
# Netra — Open Source Secret Scanner

**Netra** is a fast, free, and open-source CLI tool that scans your code for hard-coded secrets (API keys, tokens, credentials).
It uses regex patterns, entropy checks, and optional LLM-based reasoning to reduce false positives and explain results.

Built in Go, designed for developers and CI/CD pipelines.

---

## Features

* Scans files, directories, or git diffs
* Detects secrets via:

  * Regex patterns (AWS, GitHub, Slack, Google, JWTs, etc.)
  * High-entropy checks (random-looking strings)
  * Optional LLM filtering for reduced false positives and explanations
* Multiple outputs: JSON, human-readable, SARIF
* CI/CD friendly: proper exit codes (0 = clean, 1 = secrets found)
* GitHub Action to fail PRs automatically when secrets are detected
* Customizable via config file (`.netra.yaml`) and ignore rules (`.secretsignore`)

---

## Quickstart

### Install

Download a prebuilt binary (Linux, macOS, Windows) from [Releases](../../releases) or build from source:

```bash
git clone https://github.com/sharmajidotdev/netra.git
cd netra
go build ./cmd/netra
./netra --help
```

### Scan a directory

```bash
netra ./my-project
```

### Scan a file

```bash
netra secrets.txt
```

### Scan only changed lines in a PR

```bash
git diff -U0 origin/main... > changes.diff
netra --diff-file changes.diff
```

### JSON output (for automation)

```bash
netra ./src --json > results.json
```

### Human-readable output

```bash
netra ./src --human
```

---

## GitHub Action

Add Netra to your workflows to fail PRs when secrets are detected:

```yaml
name: Secret Scan
on:
  pull_request:
    branches: [ main ]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Netra
        uses: sharmajidotdev/netra-action@v1
        with:
          args: --human --exit-on=real --diff-file <(git diff -U0 origin/main...)
```

---

## Configuration

### Ignore secrets

Create a `.secretsignore` file to skip files or directories:

```
node_modules/
vendor/
*.pem
*.jpg
```

### Custom config

`.netra.yaml`:

```yaml
excludes:
  - "node_modules"
  - "dist"
patterns:
  - "CUSTOM_API_KEY_[A-Z0-9]{20}"
```

---

## Exit Codes

* `0` → No secrets found
* `1` → Secrets detected
* `2` → Internal error

---

## Roadmap

* [ ] Add more built-in regex rules
* [ ] Implement LLM filtering (OpenAI/local models)
* [ ] Improve SARIF integration
* [ ] Homebrew/Linuxbrew package
* [ ] VSCode extension

## Next Steps
* [ ] Integrate CI / CD pipeline on push action
* [ ] Dashboard UI to show the data breaches - fixes - throw to JIRA, etc

---

## Contributing

Contributions are welcome.
Check [CONTRIBUTING.md](CONTRIBUTING.md) and open a PR or issue.

Good first issues will be tagged in [Issues](../../issues).

---

## Community & Support

* Post on [Discussions](../../discussions) for help
* File bugs in [Issues](../../issues)

