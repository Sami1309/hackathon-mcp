Apify “Signals → Summaries” Pipeline (MCP‑ready)

Purpose
- Continuously collect public security signals (KEV, NVD, GitHub advisories, EPSS, vendor advisories, community chatter), normalize + score them, and hand a ranked list to your agent/app.
- Designed to run in two modes: mock (offline, sample data) and real (Apify API + public feeds). Agents can additionally invoke Apify via the MCP server.

What’s Included
- Library: `apify/lib/pipeline.mjs` — normalization, enrichment, ranking.
- Demo runner: `apify/demo_run.mjs` — end‑to‑end run (mock or real).
- Webhook example: `apify/webhook_example.mjs` — receives Apify Actor run webhooks.
- Schemas & config: `apify/schemas/finding.schema.json`, `apify/config.example.json`, `apify/mcp-tools.json`.
- Samples: `apify/sample/*` — KEV/NVD/EPSS/Exploit‑DB/advisories + search results.

Quick Start
1) Mock mode (offline, safe)
   - Run: `node apify/demo_run.mjs --mock`
   - Output: `apify/mock_output.json` (ranked findings) and `apify/mock_dataset.jsonl` (normalized records).

2) Real mode (uses public APIs; configure tokens)
   - Set env:
     - `APIFY_TOKEN=...` (required to run Actors)
   - Optional: set `APIFY_DATASET=findings-demo` and `WEBHOOK_URL=http://localhost:8787/apify/webhook`.
   - Start webhook listener (optional): `node apify/webhook_example.mjs`
   - Run: `node apify/demo_run.mjs`

How It Works
1) Collection (Apify Actors)
   - Example: Run Google Search Scraper with whitelisted queries like `site:vendor.com (advisory OR CVE) 2025`.
   - Store raw pages in Apify Key‑Value Store; store normalized rows in an Apify Dataset.
   - Webhook notifies your summarizer on completion.

2) Enrichment
   - Join with CISA KEV (exploited in the wild) and NVD CVE/CPE.
   - Add EPSS scores (likelihood of exploitation) and PoC signal (Exploit‑DB presence only; no code ingestion).

3) Normalization & Ranking
   - Normalize to `schemas/finding.schema.json`.
   - Ranking logic:
     - If `kev=true`, promote to top.
     - Else sort by EPSS score/percentile; boost if `poc_public=true`.
     - Filter/boost by CPE relevance to your in‑scope stack.

MCP Integration (Agents)
- Apify MCP server endpoint: `mcp.apify.com`.
- Curate the actors your agent may use (see `apify/mcp-tools.json`). Typical set:
  - `apify/google-search-scraper` (vendor advisories)
  - `apify/web-scraper` (crawl allowed docs only)
  - Reddit scraper for r/netsec & r/cybersecurity
- Constrain inputs: domains allowlist, time window, max pages; throttle and schedule.
- Pattern: agent invokes Actor → webhook triggers summarizer → app fetches dataset rows → call `pipeline.rankFindings()` and display.

Safety & Governance
- OSINT‑only: public, consensual sources. Do not automate exploitation or access controlled forums.
- Attribution: Always keep source URLs.
- Auditability: Raw pages to KV Store (`raw_store_key`); normalized rows to Dataset (append‑only).
- Rate limiting & scheduling via Apify schedule/runs; favor nightly pulls for KEV/NVD/GH/EPSS and on‑demand search via MCP for ad‑hoc questions.

Wiring Into This App
- Backend: call `pipeline.runVendorAdvisorySearch()` then `pipeline.processAndRank()` with real or mock mode based on environment; expose as `/signals/collect`.
- Frontend: surface top N ranked findings with source badges (kev|nvd|github|vendor|reddit|exploit-db) and link to raw artifacts.

Files
- `apify/lib/pipeline.mjs`: core functions to collect (via Apify API), enrich (KEV/NVD/EPSS), normalize, and rank.
- `apify/demo_run.mjs`: CLI example that runs the pipeline and writes outputs locally.
- `apify/webhook_example.mjs`: minimal webhook for Actor completion.
- `apify/schemas/finding.schema.json`: unified record schema.
- `apify/config.example.json`: curated actors, allowlists, dataset names, webhook URL.
- `apify/mcp-tools.json`: MCP tools manifest (which actors and input schema are allowed).
- `apify/sample/*`: sample inputs for mock mode.

Environment Variables
- `APIFY_TOKEN` — Apify API token (required in real mode)
- `APIFY_DATASET` — Target dataset name (default: findings-demo)
- `WEBHOOK_URL` — Webhook endpoint for run completion (optional)
- `MOCK` — If `1`, force mock mode (equivalent to `--mock`)

Notes
- This folder is self‑contained and safe to run offline. Swap mock → real incrementally.
