# Deploying OpenAnt Across GitHub Enterprise

This guide explains how to deploy OpenAnt as an organisation-wide security scanning
capability on GitHub Enterprise (Cloud or Server), so that it runs automatically
against multiple repos without each team having to configure anything themselves.

---

## Overview

There are two complementary deployment patterns:

| Pattern | Best for |
|---------|----------|
| **Reusable workflow** | Teams opt in; they call one line from their own workflow |
| **Required workflow** | Security team enforces it; no per-repo config needed |

Both patterns share the same setup steps. Start with those, then choose your pattern.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| GitHub Enterprise Cloud or Server 3.8+ | Required workflow feature needs GHEC or GHES ≥3.8 |
| Anthropic API key with credits | One key per org is fine; store it as an org secret |
| Python 3.11+ and Go 1.22+ on runners | Only needed if building from source on self-hosted runners |
| GitHub-hosted `ubuntu-latest` runners | Works out of the box; no extra tooling needed |

---

## Step 1 — Fork or mirror OpenAnt into your org

OpenAnt needs to live inside your GitHub Enterprise instance so that workflows can
reference it with `uses: your-org/OpenAnt/...`.

```bash
# Mirror to your GHE instance (adjust hostname as needed)
git clone --mirror https://github.com/Santandersecurityresearch/OpenAnt.git
cd OpenAnt.git
git remote set-url --push origin https://github.your-enterprise.com/your-org/OpenAnt.git
git push --mirror
```

Keep it up to date by running that push on a schedule (cron job or a simple
sync workflow). Pin a specific commit or tag in your org workflows so that an
upstream update cannot break scanning across all repos overnight.

---

## Step 2 — Store the Anthropic API key as an org-level secret

1. Go to **Your org → Settings → Secrets and variables → Actions**
2. Click **New organisation secret**
3. Name: `ANTHROPIC_API_KEY`
4. Value: your Anthropic API key
5. Repository access: choose **All repositories** or limit to a specific set

This means every repo in your org can reference `${{ secrets.ANTHROPIC_API_KEY }}`
without any per-repo secret setup.

---

## Step 3 — Publish a reusable workflow

Create the file below inside your mirrored OpenAnt repo. This is the single
definition that every other repo will call.

**`.github/workflows/openant-scan-reusable.yml`**

```yaml
name: OpenAnt Security Scan (reusable)

on:
  workflow_call:
    inputs:
      language:
        description: "Language hint: python, javascript, go, auto"
        type: string
        default: auto
      level:
        description: "Processing level: all, reachable, sca"
        type: string
        default: reachable
      verify:
        description: "Enable Stage 2 attacker simulation"
        type: boolean
        default: true
      unit_limit:
        description: "Max units to analyse (0 = no limit)"
        type: number
        default: 50
      model:
        description: "Claude model: sonnet or opus"
        type: string
        default: sonnet
    secrets:
      ANTHROPIC_API_KEY:
        required: true

permissions:
  contents: read
  security-events: write   # SARIF upload

jobs:
  openant:
    name: OpenAnt vulnerability scan
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - name: Checkout calling repo
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          fetch-depth: 0

      - name: Checkout OpenAnt (pinned)
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          repository: your-org/OpenAnt          # <-- update this
          ref: main                              # pin to a tag in production
          path: .openant
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Cache OpenAnt binary
        id: cache-binary
        uses: actions/cache@v4
        with:
          path: .openant/apps/openant-cli/bin/openant
          key: openant-bin-${{ hashFiles('.openant/apps/openant-cli/**/*.go', '.openant/apps/openant-cli/go.sum') }}

      - name: Build OpenAnt binary
        if: steps.cache-binary.outputs.cache-hit != 'true'
        run: |
          cd .openant/apps/openant-cli
          go build -o bin/openant .

      - name: Install Python dependencies
        run: |
          pip install -q -r .openant/libs/openant-core/requirements.txt

      - name: Install JS parser dependencies
        run: |
          cd .openant/libs/openant-core/parsers/javascript
          npm ci --silent

      - name: Run OpenAnt scan
        id: scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          PYTHONPATH: .openant/libs/openant-core
        run: |
          mkdir -p /tmp/openant-results
          .openant/apps/openant-cli/bin/openant \
            --api-key "$ANTHROPIC_API_KEY" \
            scan "$GITHUB_WORKSPACE" \
            --language "${{ inputs.language }}" \
            --level "${{ inputs.level }}" \
            --model "${{ inputs.model }}" \
            --limit "${{ inputs.unit_limit }}" \
            --enhance-mode single-shot \
            --workers 8 \
            --no-report \
            --json \
            --output /tmp/openant-results \
            ${{ inputs.verify && '--verify' || '' }} \
            2>/tmp/openant-stderr.log \
            | tee /tmp/openant-stdout.json || true

      - name: Convert findings to SARIF
        if: always()
        env:
          PYTHONPATH: .openant/libs/openant-core
        run: |
          PIPELINE_OUTPUT="/tmp/openant-results/pipeline_output.json"
          if [ -f "$PIPELINE_OUTPUT" ]; then
            python .openant/tools/sarif_convert.py "$PIPELINE_OUTPUT" \
              -o /tmp/openant-results/results.sarif
          else
            printf '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"OpenAnt","version":"1.0.0","rules":[]}},"results":[]}]}\n' \
              > /tmp/openant-results/results.sarif
          fi

      - name: Upload SARIF to Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: /tmp/openant-results/results.sarif
          category: openant

      - name: Fail if confirmed vulnerabilities found
        run: |
          OUTPUT="/tmp/openant-results/pipeline_output.json"
          [ -f "$OUTPUT" ] || { echo "::warning::No pipeline output — scan may have errored"; exit 0; }

          VULNERABLE=$(jq '[.findings[] | select(.stage1_verdict == "vulnerable")] | length' "$OUTPUT" 2>/dev/null || echo 0)
          BYPASSABLE=$(jq '[.findings[] | select(.stage1_verdict == "bypassable")] | length' "$OUTPUT" 2>/dev/null || echo 0)

          echo "Confirmed vulnerable: ${VULNERABLE}"
          echo "Bypassable controls:  ${BYPASSABLE}"

          if [ "$VULNERABLE" -gt 0 ]; then
            echo "::error::${VULNERABLE} confirmed vulnerabilit$([ $VULNERABLE -eq 1 ] && echo y || echo ies) found."
            exit 1
          fi
```

---

## Pattern A — Reusable workflow (opt-in per repo)

Teams add a single file to their repo to trigger OpenAnt. They do not need to
understand how it works.

**`.github/workflows/security.yml`** (in the target repo):

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, master]
  schedule:
    - cron: "0 2 * * 1"   # Weekly on Monday

jobs:
  openant:
    uses: your-org/OpenAnt/.github/workflows/openant-scan-reusable.yml@main
    with:
      language: auto
      level: reachable
      verify: true
      unit_limit: 50
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

That's the entire file. One reference, all logic lives in OpenAnt.

---

## Pattern B — Required workflow (enforced by security team)

GitHub Enterprise Cloud and GHES ≥3.8 support **required workflows**: a workflow
defined in one repo that runs automatically against every repo in the org, or a
selected subset, without any change to those repos.

### Setting it up

1. In your mirrored OpenAnt repo, make the reusable workflow above reachable at
   a stable path (it already is at `.github/workflows/openant-scan-reusable.yml`).

2. Go to **Org Settings → Actions → Required workflows**

3. Click **Add required workflow**

4. Select the OpenAnt repo and the workflow file path

5. Choose which repos it applies to: **All repositories** or a selection

6. Save

GitHub will now inject that workflow into every targeted repo's PR checks. Teams
cannot bypass it. Findings appear in each repo's **Security → Code scanning** tab.

### What repo owners see

- A new check called `OpenAnt vulnerability scan` appears on every PR
- The Security tab shows annotated findings with file + line locations
- They can suppress known-acceptable findings by adding `.openant-suppress.yml`
  to their repo root (see suppression format below)

---

## Suppressing known findings

If a repo intentionally uses a pattern that OpenAnt flags (e.g. an internal
pentest tool that does command execution on purpose), add this file to that repo:

**`.openant-suppress.yml`**:

```yaml
suppressions:
  - id: suppress-001
    reason: "Intentional command execution — internal pentest tooling, not user-facing"
    rule: command_injection
    path_prefix: src/tools/
    expires: 2026-12-31   # optional hard expiry

  - id: suppress-002
    reason: "Known false positive in auth middleware — reviewed by security team 2026-04-20"
    fingerprint: "abc123def456"   # from pipeline_output.json finding.fingerprint
```

Suppressions are applied before the fail gate, so the PR check passes for
suppressed findings. They expire automatically on the `expires` date.

---

## Scanning multiple repos on a schedule (without Required Workflows)

If you want a centralised nightly scan of many repos without modifying them,
run a dispatch workflow from a dedicated security repo:

**`.github/workflows/org-scan.yml`** (in your security team's repo):

```yaml
name: Org-wide nightly scan

on:
  schedule:
    - cron: "0 1 * * *"
  workflow_dispatch:
    inputs:
      repos:
        description: "Comma-separated list of org/repo to scan"
        required: false

jobs:
  matrix:
    runs-on: ubuntu-latest
    outputs:
      repos: ${{ steps.list.outputs.repos }}
    steps:
      - id: list
        run: |
          # Hard-coded list or pull from a config file in this repo
          REPOS='["your-org/repo-a","your-org/repo-b","your-org/repo-c"]'
          echo "repos=$REPOS" >> "$GITHUB_OUTPUT"

  scan:
    needs: matrix
    strategy:
      matrix:
        repo: ${{ fromJson(needs.matrix.outputs.repos) }}
      fail-fast: false     # scan all repos even if one fails
    uses: your-org/OpenAnt/.github/workflows/openant-scan-reusable.yml@main
    with:
      language: auto
      level: reachable
      verify: true
      unit_limit: 100
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

> **Note:** Matrix + `workflow_call` requires each matrix job to check out
> the correct target repo. You may need to pass the repo name as an input to
> the reusable workflow and have it checkout that repo instead of
> `GITHUB_WORKSPACE`. Adjust the reusable workflow's checkout step accordingly.

---

## Cost estimates

These are approximate for Sonnet with Stage 2 verification enabled.

| Scenario | Units | Est. cost |
|----------|-------|-----------|
| Small PR (5 changed files) | ~25 units | $0.30 – $0.50 |
| Medium PR (20 changed files) | ~100 units | $1.50 – $2.50 |
| Full repo scan (DVNA-sized, 13 units) | 13 units | ~$2.85 |
| Full repo scan (medium app, 100 units) | 100 units | $15 – $25 |

**Cost controls:**
- `--level reachable` reduces units by ~94% vs `--level all`
- `--limit 50` caps spend on PR scans
- Skip `--verify` on PRs and reserve Stage 2 for nightly runs to halve cost
- Use `--model sonnet` (default); only upgrade to `--model opus` for targeted deep dives

---

## GitHub Enterprise Server specifics

GHES adds a few differences from GitHub.com:

| Topic | What to change |
|-------|---------------|
| `codeql-action/upload-sarif` | Works on GHES 3.5+. Ensure Code Scanning is enabled in site admin. |
| `actions/checkout`, `actions/cache` | Use the versions bundled with your GHES instance or mirror them to an internal registry |
| Self-hosted runners | Install Go 1.22, Python 3.11, and Node 18+ on runner images |
| Internal CA / proxy | Set `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` env vars on the runner for OSV.dev and Anthropic API calls |
| Air-gapped environments | OSV.dev lookup requires outbound HTTPS to `api.osv.dev`. Anthropic API requires outbound HTTPS to `api.anthropic.com`. Both must be reachable from runners. |

---

## Troubleshooting

**Scan exits with code 1 on every PR**
→ Findings were confirmed. This is intentional — review the Security tab or suppress
the finding with `.openant-suppress.yml` if it's a known acceptable risk.

**`ts-morph` or other Node modules missing**
→ The `npm ci` step in the reusable workflow installs them. Ensure the JS parser's
`package.json` is present in the OpenAnt mirror.

**`ANTHROPIC_API_KEY` not found**
→ Check the secret is set at org level and the workflow's `secrets:` block
passes it through to the reusable workflow call.

**SARIF upload fails on GHES**
→ Code Scanning must be enabled by a site admin under **Admin → Code scanning**.

**High costs on large repos**
→ Lower `unit_limit`, switch to `--level reachable` (already default), or disable
`--verify` on PR scans and only run Stage 2 in the nightly workflow.
