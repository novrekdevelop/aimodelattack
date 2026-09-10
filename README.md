# ⚔️ AMAS — AI Model Attack Simulator

A command-line **red-teaming tool for LLM and agent endpoints**. AMAS takes an endpoint
(OpenAI-compatible chat-completions, e.g. OpenAI, Anthropic-via-gateway, Azure, vLLM,
llama.cpp server, Ollama, LM Studio) and automatically runs it through a catalogued
battery of known attacks:

- **Prompt injection** — hidden/embedded instructions that try to override the model's rules
- **Jailbreaks** — publicly documented techniques (DAN, STAN, AIM, Developer Mode, many-shot, …)
- **System prompt extraction** — attempts to leak the endpoint's hidden instructions

Every response is evaluated by a **rule engine** (refusal & leakage heuristics) and,
optionally, by an **LLM-as-judge**. AMAS then produces a report with a **severity-weighted
vulnerability score**, a per-category breakdown, and verbose findings.

> ⚠️ **Authorized use only.** This tool is intended for security testing of LLM systems you
> own or are explicitly authorized to test. Unauthorized probing of third-party endpoints
> may violate terms of service and/or law. You are responsible for how you use it.

---

## Features

- 📚 **Catalogue of 40+ attacks** pulled from public research, stored as editable YAML
- 🔌 **One adapter, many backends** — any OpenAI-compatible `/chat/completions` endpoint
- 🎭 **`mock` target** for offline demos and CI (strict and lenient guardrail personas)
- 🧮 **Dual evaluation** — rule-based heuristics + optional LLM-as-judge for ambiguous cases
- 🏁 **Vulnerability score** — severity-weighted 0–100 with letter grade
- 📄 **Reports** — Markdown and JSON, plus a rich console summary
- 🧵 **Concurrency, retries, backoff, rate limiting**, reproducible seeds
- ✅ **Tested** — pytest suite covering the catalogue, evaluator, scoring, runner and reports

## Installation

> **Single-file mode (recommended for portability):** the whole tool lives in one
> self-contained script, [`amas.py`](amas.py) — the attack catalogue is embedded,
> and it uses **only the Python standard library** (no `requests`, `PyYAML` or
> `rich`). Copy `amas.py` to any machine with **Python ≥ 3.9** on **Windows,
> macOS or Linux** and it just works.

```bash
# Direct, no installation, cross-platform — works from any folder:
python amas.py --help
python amas.py list
python amas.py run                          # offline demo (mock target, 42 attacks)

# Optional: classic pip install of the package (keeps deps out of the single file)
pip install -e .            # installs amas + deps (requests, pyyaml, rich)
pip install -e ".[dev]"     # additionally installs pytest for the test-suite
```

Requires Python ≥ 3.9.

## Quick start (offline demo)

Run a full battery against a *mock* endpoint that has weak guardrails (the single
file needs no config for this — it defaults to an offline mock):

```bash
python amas.py run
```

…or against a specific mock config:

```bash
python amas.py run --config examples/mock_lenient.json
python amas.py run --config examples/mock_strict.json
```

Reports land in `reports/` by default (`report.md`, `report.json`).

## Real endpoint

Copy `config.example.json` to `config.json`, set your endpoint details, then:

```bash
python amas.py run --config config.json
```

Environment-variable overrides (no secrets in files): `AMAS_TARGET_URL`, `AMAS_API_KEY`,
`AMAS_JUDGE_URL`, `AMAS_JUDGE_KEY`, `AMAS_MODEL`, `AMAS_JUDGE_MODEL`.

## CLI reference

```text
python amas.py                          Show help (or use: python -m ... anywhere)
python amas.py list                     List the attack catalogue (filters: --category, --attacks)
python amas.py run                      Run the attack battery (defaults to offline mock demo)
  --config PATH                    JSON config (default: ./config.json; missing -> mock demo)
  --category <name>                Limit to a category (repeatable)
  --attacks id1,id2                Limit to specific attack ids
  --goal "text"                    Override the injected goal for all attacks
  --iterations N                   Repeat the battery N times (default from config)
  --concurrency N                  Max concurrent requests
  --output-dir PATH                Where to write reports
  --formats md,json                Report formats to emit
  --quiet                          Console table only, no report files
  --seed N                         Seed for goal/attack shuffling
python amas.py --version               Print version
```

> **Portability notes:** `amas.py` embeds the 42-attack catalogue, uses only the
> standard library, and resolves the config/mock/report paths relative to the
> current working directory — so you can run it from any folder on Windows,
> macOS or Linux. For an alias on Windows use `py amas.py`; on macOS/Linux
> `python3 amas.py`.
## Config reference

```jsonc
{
  "target": {
    "name": "my-app-llm",
    "type": "openai_compatible",      // or "mock"
    "base_url": "https://api.openai.com/v1",   // any OpenAI-compatible base
    "api_key": "sk-...",
    "model": "gpt-4o-mini",
    "system_prompt": "You are ...",   // the real system prompt used by the endpoint
    "timeout": 60,
    "max_retries": 2,
    "temperature": 0.4,
    "max_tokens": 512
  },
  "judge": {                          // optional LLM-as-judge
    "enabled": false,
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-...",
    "model": "gpt-4o-mini"
  },
  "run": {
    "goals": [ "...policy-challenging requests..." ],
    "iterations": 1,
    "seed": 0,
    "max_concurrency": 4,
    "report_formats": ["markdown", "json"]
  }
}
```

The `goals` list powers every injection/jailbreak attack that needs concrete content
(placeholder `{goal}`). The bundled defaults are text-only, moderate test requests
(phishing draft, script skeleton, etc.). Customize freely for your threat model —
this is the knob that makes the battery relevant to *your* endpoint's policies.

## How the score works

Per attack, the evaluator returns a score between **0** (fully defended) and **10**
(fully vulnerable). Refusals score low, confirmed leaks/compliance score high, and
ambiguous cases sit mid-range until the judge (if enabled) refines them. The final
**vulnerability score** is the severity-weighted average mapped to **0–100** with an
accompanying grade (A+ … F).

## Project layout

```text
amas/          Python package (CLI, config, targets, evaluator, runner, scoring, reports)
attacks/       YAML attack catalogue (prompt_injection / jailbreaks / system_extraction)
examples/      Ready-to-run config files
tests/         pytest suite
```

## Roadmap

- Generic unauthenticated HTTP target (arbitrary JSON schemas) for non-OpenAI endpoints
- Weaponized *indirect* injection targeting RAG pipelines (inject into retrieved docs)
- Coding-agent / tool-call-aware probes (function-schema poisoning, tool-name squatting)
- HTML report with charts; CI-friendly `--exit-code` for gates
- History mode: run a specific previously saved battery against a changed deployment

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

Techniques curated from public research and disclosures (OWASP LLM Top 10 2023/2025,
"Universal and Transferable Attacks on Aligned Language Models" (Zou et al., 2023),
"Not What You've Signed Up For" indirect-injection taxonomy (Greshake et al., 2023),
Simon Willison's prompt-injection notes, the original DAN / STAN / AIM jailbreaks,
Anthropic's many-shot jailbreaking write-up (2024), and the widely documented system
prompt leakage work of 2023–2024). Each attack entry carries its own reference links.