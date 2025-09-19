Scope and Practices for Agents in apify/

Purpose
- Provide a safe, well-scoped way for MCP-aware agents to use Apify Actors for public security signals collection and summarization.

Agent Rules (within apify/)
- Only use curated Apify Actors listed in mcp-tools.json.
- Stay within allowed domains and queries for vendor advisories and public sources.
- Do not ingest exploit code; treat Exploit‑DB presence as a boolean signal only.
- Prefer scheduled/nightly pulls for KEV/NVD/GitHub advisories/EPSS; use on-demand search runs via MCP sparingly and rate-limited.
- Preserve attribution (source URLs) and raw artifacts (store keys) in every record.

MCP Configuration
- Server: mcp.apify.com
- Tools: see `apify/mcp-tools.json` (google-search-scraper, web-scraper with domain allowlist, reddit scraper for r/netsec and r/cybersecurity).
- Webhooks: on run completion, POST to the summarizer endpoint (example in `webhook_example.mjs`).

Data Model
- Normalize to `schemas/finding.schema.json`.
- Raw HTML/PDF/screenshots go to Apify Key‑Value Store (record `raw_store_key`).
- Normalized rows append to the findings Dataset.

Ranking Logic
- Promote KEV=true to top; otherwise sort by EPSS score/percentile with PoC presence boost and in‑scope CPE relevance.

Operational Safety
- OSINT‑only, respect site terms; never automate exploitation.
- Rate limit Actors and configure schedules in Apify (avoid scraping bursts).
- Keep logs and raw artifacts for auditability.

Integration Pattern
1) Agent triggers an Actor via MCP (from the curated list) with constrained inputs.
2) Webhook notifies the app; the app fetches dataset rows via Apify API.
3) App calls `lib/pipeline.mjs` to normalize, enrich (KEV/NVD/EPSS), and rank.
4) App displays summaries with links and signals; humans can drill into raw artifacts if needed.

Coding Conventions (for this folder)
- ESM (Node >=18); no external dependencies required.
- Keep functions small, composable, and side‑effect‑free where possible.
- Support mock mode for all network functions; default to mock if env lacks tokens.
