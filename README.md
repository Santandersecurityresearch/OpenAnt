<p align="center">
  <img src="assets/open-ant-black.png" alt="OpenAnt" width="180" />
</p>

# OpenAnt

[OpenAnt](https://knostic.ai/openant) from [Knostic](https://knostic.ai) is an open source LLM-based vulnerability discovery product that helps defenders proactively find verified security flaws while minimizing both false positives and false negatives. Stage 1 detects. Stage 2 attacks. What survives is real.

We're pretty proud of this product and are in the vulnerability disclosure process for its findings, but do keep in mind that this started as a research project, and some of its features are still in beta. We welcome contributions to make it better.

## Why open source?
Considering the explosion of AI-discovered vulnerabilities, we hope OpenAnt will be the tool helping open source maintainers stay ahead of attackers, where they can use it themselves or submit their repo for scanning at no cost.

Then, since Knostic's focus is on protecting agents and coding assistants and not vulnerability research or application security, and we like open source, we decided to release OpenAnt under the Apache 2 license.
Besides, you may have heard about Aardvark from OpenAI (now Codex Security) and Claude Code Security from Anthropic, and we have zero intention of competing with them.

## Technical details and free scanning for open source projects
For technical details, limitations, and token costs, check out this blog post:
[https://knostic.ai/blog/openant](https://knostic.ai/blog/openant)

To submit your repo for scanning:
[https://knostic.ai/blog/oss-scan](https://knostic.ai/blog/oss-scan)

## Supported languages
- Go
- Python
- JavaScript/TypeScript (beta)
- C/C++ (beta)
- PHP (beta)
- Ruby (beta)

## Credits
Research and ideation: [Nahum Korda](https://github.com/NahumKorda/).

Productization: Alex Raihelgaus, Daniel Geyshis.

With thanks to: [Michal Kamensky](https://github.com/kamenskymic/), [Imri Goldberg](https://github.com/lorg), [Gadi Evron](https://github.com/gadievron/), [Daniel Cuthbert](https://github.com/danielcuthbert/). Josh Grossman, and Avi Douglen.

## Check out Knostic
**If you like our work**, check out what we do at [Knostic](https://knostic.ai) to defend your agents and coding assistants, prevent them from deleting your hard drive and code, and control associated supply chain risks such as MCP servers, extensions, and skills.


## GitHub Actions integration

OpenAnt ships with two workflows and a reusable composite action for running scans in CI/CD pipelines.

### Workflows

**`openant-pr-scan.yml`** — runs on every pull request targeting `main` or `master`. It scans only the units reachable from user input (`--level reachable`), uses Stage 2 attacker simulation to eliminate false positives, and posts a summary comment directly on the PR. The check fails if any confirmed vulnerabilities are found. A cost guard (`--limit 50`) caps spend at roughly $5-10 per run using the Sonnet model.

**`openant-nightly.yml`** — runs a full audit on a weekly schedule (Monday 02:00 UTC) or on demand via `workflow_dispatch`. It uses the Opus model with agentic enhancement and generates all report formats (HTML, CSV, summary). Results are uploaded as workflow artefacts with 90-day retention, SARIF is pushed to the Security tab, and a GitHub issue is opened automatically if confirmed findings are present.

### Setup action

`.github/actions/setup-openant/action.yml` is a composite action that handles the full install: Go toolchain, Python dependencies, and building the `openant` binary. Both workflows call it to keep setup DRY. Go modules and pip packages are cached between runs.

### SARIF converter

`tools/sarif_convert.py` converts `pipeline_output.json` to SARIF 2.1.0 so findings appear in the **Security > Code scanning** tab with CWE rule metadata, severity labels, and stable fingerprints for deduplication across scans. Only actionable findings (`vulnerable`, `bypassable`, `inconclusive`) are emitted; `protected` and `safe` results are omitted to keep the Security tab signal-rich.

### Required secret

Add your Anthropic API key as a repository secret before the workflows will run:

```
Settings > Secrets and variables > Actions > New repository secret
Name:  ANTHROPIC_API_KEY
Value: sk-ant-...
```

### What a PR scan produces

When a pull request is opened or updated, the workflow:

1. Parses the repository and filters to entry-point-reachable units (typically a 90-95% reduction in units analysed).
2. Runs Stage 1 detection against each unit using Claude Sonnet.
3. Runs Stage 2 attacker simulation on any `vulnerable` or `bypassable` findings to confirm exploitability.
4. Posts a comment on the PR with a verdict table and finding list.
5. Uploads a SARIF file to the Security tab with per-finding CWE annotations.
6. Fails the check if any confirmed vulnerabilities are found; `bypassable` findings raise a warning but do not block by default.

---

## Local setup

Build the CLI binary (requires Go 1.25+):

```bash
cd apps/openant-cli && make build
```

This compiles the Go source and outputs the binary to `apps/openant-cli/bin/openant`.

Symlink it onto your PATH so you can run `openant` from anywhere:

```bash
ln -sf "$(pwd)/apps/openant-cli/bin/openant" /usr/local/bin/openant
```

_Note: run this from the repo root so `$(pwd)` resolves to the correct absolute path._

Set your Anthropic API key (required for analyze, verify, and scan):

```bash
openant set-api-key <your-key>
```

**The key must have access to the Claude Opus 4.6 model.** Get a key at [console.anthropic.com](https://console.anthropic.com/settings/keys).

## Data directories

OpenAnt creates two directories:

- **`~/.config/openant/`** — CLI configuration (`config.json`). Stores your API key, active project, and preferences. File permissions are restricted to `0600`.
- **`~/.openant/`** — Project data. Each initialized project gets a workspace under `~/.openant/projects/<org>/<repo>/` containing `project.json` and a `scans/` directory with per-commit outputs.

## Analyzing a project

### 1. Initialize

Point OpenAnt at a repository. The `-l` flag (language) is required — use `go` or `python`.

```bash
# Remote — clones the repo
openant init <repo-url> -l go

# Remote — pin to a specific commit
openant init <repo-url> -l go --commit <sha>

# Local — references the directory in-place
openant init <path-to-repo> -l go --name <org/repo>
```

This creates a project workspace and sets it as the active project. All subsequent commands operate on the active project automatically — no path arguments needed.

### 2. Run the pipeline

Each step picks up the output of the previous one from the project's scan directory:

```bash
openant parse
openant enhance
openant analyze
openant verify
openant build-output
openant report -f summary
```

Or run the full pipeline in one command:

```bash
openant scan --verify
```

### Working with multiple projects

The pipeline operates on one project at a time. Running `openant init` sets the newly initialized project as the active one, so all subsequent commands target it by default.

If you're working with several projects, you have two options:

```bash
# Option 1: switch the active project
openant project switch org/repo
openant parse

# Option 2: target a project directly with -p
openant parse -p org/repo
```

### Project management

```bash
openant project list              # shows all projects, marks active
openant project show              # details of active project
openant project switch <org/repo> # switch active project
```


## LICENSE
This project is licensed under Apache 2. See the LICENSE file for details.


## Disclaimer and legal notice
This project is intended for defensive and research purposes only. OpenAnt is still in the research phase, use it carefully and at your own risk. Knostic, OpenAnt, and associated developers, researchers, and maintainers assume no responsibility whatsoever for any misuse, damage, or consequences arising from the use of this tool.

Only scan code you own or have explicit permission to test. If you discover a vulnerability in someone else's project through legitimate means, please follow coordinated vulnerability disclosure practices and report it to the maintainers before making it public.
