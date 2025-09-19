awesome—here’s a “ground-truth” implementation plan you can drop into a repo. it’s scoped to hit the judging rubric hard (idea, technical wow, multi-tool use, clear 3-min demo), and it’s specific enough to guide a fast build. --- # repo blueprint
pentest-to-fix/
├─ README.md
├─ docs/
│  ├─ arch-overview.md
│  ├─ demo-script.md
│  ├─ one-slide-postmortem.pptx     # exported by Airia flow at demo time
│  └─ security-model.md
├─ infra/
│  ├─ aws/
│  │  ├─ cdk/                        # optional CDK for preview envs on ECS/Lambda URLs
│  │  └─ github-actions/preview.yml  # PR -> ephemeral env on AWS
│  └─ redis/
│     └─ docker-compose.yml
├─ orchestrator/
│  ├─ airia_flow.json                # Airia agent flow (nodes + MCP tools) :contentReference[oaicite:0]{index=0}
│  └─ prompts/
│     ├─ fix_pr_composer.md
│     ├─ cve_summary.md
│     └─ postmortem_slide.md
├─ mcp-servers/
│  ├─ horizon3-nodezero/             # NodeZero® MCP client config (bridge to H3 API) :contentReference[oaicite:1]{index=1}
│  ├─ gram-github/                    # Gram MCP: GitHub PRs/branches/labels, CI triggers :contentReference[oaicite:2]{index=2}
│  ├─ brightdata-web/                 # Web access for CVE intel (search, navigate, extract) :contentReference[oaicite:3]{index=3}
│  ├─ apify-actors/                   # Run actors to pull SBOM/maintainer notes (optional) :contentReference[oaicite:4]{index=4}
│  ├─ honeyhive/                      # Eval runs + traces (merge gates) :contentReference[oaicite:5]{index=5}
│  ├─ qodo/                           # PR-Agent / Merge hooks for tests/review :contentReference[oaicite:6]{index=6}
│  ├─ stytch/                         # Passkeys/WebAuthn login :contentReference[oaicite:7]{index=7}
│  ├─ gladia/                         # Async/Realtime STT for bridge calls :contentReference[oaicite:8]{index=8}
│  └─ llamaindex/                     # RAG + timeline extraction over transcripts/docs :contentReference[oaicite:9]{index=9}
├─ services/
│  ├─ api/
│  │  ├─ app.py                       # FastAPI/Express – unifies flows + webhooks
│  │  ├─ routes/
│  │  │  ├─ auth.py                   # Stytch passkeys
│  │  │  ├─ pentest.py                # start/poll NodeZero jobs
│  │  │  ├─ pr.py                     # create PR via Gram->GitHub
│  │  │  ├─ verify.py                 # re-run NodeZero + HoneyHive gate
│  │  │  └─ postmortem.py             # Gladia->LlamaIndex->Airia slide
│  │  └─ clients/                     # typed clients to each API
│  ├─ workers/
│  │  ├─ cve_watcher.py               # OSV/GHSA/NVD + Bright Data + Apify (optional) :contentReference[oaicite:10]{index=10}
│  │  └─ repro_test_gen.py            # Qodo tests from NodeZero finding + RedisVL tickets
│  ├─ rag/
│  │  ├─ index_tickets.py             # embed ~50 sample tickets with RedisVL :contentReference[oaicite:11]{index=11}
│  │  └─ query_tickets.py
│  └─ postmortem/
│     └─ timeline_extractor.py        # LlamaIndex graph of events
├─ ci/
│  ├─ github/
│  │  ├─ create-pr.yml                # Gram/GitHub PR + Qodo test generation
│  │  └─ verify-and-gate.yml          # build preview on AWS, NodeZero verify, HoneyHive gate
│  └─ scripts/
│     ├─ build_preview.sh
│     ├─ nodezero_verify.sh
│     └─ publish_artifacts.sh
├─ data/
│  ├─ sample_tickets.jsonl            # anonymized tickets for RedisVL embeddings
│  └─ sample_call_audio.wav           # demo call for Gladia
├─ .env.example
└─ LICENSE
--- # core user journey (maps 1:1 to demo) **1) kickoff & scope** * User signs in with **Stytch passkeys (WebAuthn)**, we store a workspace session and permitted repos/environments. ([Stytch][1]) **2) pentest → prioritized finding** * The API triggers **NodeZero® via the NodeZero MCP server**, filtered to the ephemeral preview URL; we poll job status and fetch an exploitable finding with remediation hints. ([Horizon3][2]) **3) fix PR with tests** * **RedisVL** semantically finds similar support tickets to shape repro steps; **Qodo PR-Agent/Merge** generates failing tests + a minimal patch; **Gram MCP (GitHub)** opens a PR and attaches artifacts. ([Redis Vector Library][3]) **4) re-verify automatically** * **GitHub Actions → AWS** creates a preview env (Lambda URL or ECS “preview envs”), **NodeZero re-runs a targeted verify** on that URL; **HoneyHive** runs pass/fail eval and displays traces that gate merge. ([Amazon Web Services, Inc.][4]) **5) one-slide postmortem** * **Gladia** transcribes the bridge (or sample audio) → **LlamaIndex** extracts timeline/owners → **Airia** auto-generates a single slide with links to the HoneyHive trace + NodeZero proof-of-fix. ([Gladia][5]) --- # env & secrets Copy .env.example → .env and fill:
# auth
STYTCH_PROJECT_ID=...
STYTCH_SECRET=...

# horizon3 nodezero
H3_API_TOKEN=...
H3_ORG_ID=...

# gram / github
GITHUB_APP_ID=...
GITHUB_INSTALLATION_ID=...
GITHUB_PRIVATE_KEY=...
GRAM_API_URL=https://api.gram.speakeasy.com  # example; see docs :contentReference[oaicite:17]{index=17}

# honeyhive
HONEYHIVE_API_KEY=...

# qodo
QODO_API_KEY=...  # or PR-Agent self-host config; see OSS repo :contentReference[oaicite:18]{index=18}

# redis
REDIS_URL=redis://localhost:6379

# gladia
GLADIA_API_KEY=... :contentReference[oaicite:19]{index=19}

# aws preview
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1

# optional intel
BRIGHT_DATA_API_TOKEN=...  :contentReference[oaicite:20]{index=20}
APIFY_TOKEN=...           :contentReference[oaicite:21]{index=21}
--- # service contracts (thin but real) ## /auth/start (POST) * Initiates **Stytch** passkey/WebAuthn flow; returns challenge. ([Stytch][6]) ## /auth/finish (POST) * Verifies assertion → issues session JWT. ## /pentest/start (POST) Body: { "target_url": "<preview-url>", "scope": "quick" } Behavior: calls **NodeZero MCP** startAssessment, returns job_id. ([Horizon3][2]) ## /pentest/result (GET) Query: job_id → returns { finding_id, cwe, service, evidence_url } (only exploitable/critical). ([Horizon3.ai][7]) ## /pr/create (POST) Body: { "repo":"org/app", "base":"main", "finding_id":"...", "tickets_topk":5 } * Queries **RedisVL** for similar tickets, launches **Qodo** test generation + patch draft, then **Gram→GitHub** POST /repos/:owner/:repo/pulls. ([Redis Vector Library][8]) ## /verify/run (POST) Body: { "repo":"org/app", "pr":123 } * Triggers **AWS preview** build → on success, **NodeZero verify** targeted checks → **HoneyHive** eval.run with traces; returns pass/fail and links. ([Amazon Web Services, Inc.][9]) ## /postmortem/slide (POST) Body: { "call_url": "...", "pr":123, "job_id":"..." } * **Gladia** transcribe (async) → **LlamaIndex** timeline → **Airia** generates slide & returns artifact URL. ([Gladia][10]) --- # MCP configs (examples) ### horizon3-nodezero/mcp.json
json
{
  "name": "nodezero",
  "description": "Bridge to NodeZero pentest/verify",
  "tools": [
    {"name":"startAssessment","inputSchema":{"type":"object","properties":{"targetUrl":{"type":"string"}}}},
    {"name":"getFindings","inputSchema":{"type":"object","properties":{"jobId":{"type":"string"}}}},
    {"name":"verifyFinding","inputSchema":{"type":"object","properties":{"findingId":{"type":"string"},"targetUrl":{"type":"string"}}}}
  ]
}
(Per Horizon3’s NodeZero MCP design—safe, structured access to NodeZero GraphQL for “find-fix-verify”.) ([Horizon3][2]) ### gram-github/mcp.json Expose curated GitHub endpoints (create branch, commit files, open PR, label, status) through **Gram**. ([Speakeasy][11]) ### brightdata-web/mcp.json Search → Navigate → Extract tools for CVE intel scraping; free tier available for dev. ([Bright Data][12]) ### honeyhive/mcp.json createEvalRun, getRun, setGateStatus to gate merges based on eval metrics (traces visible). ([HoneyHive][13]) --- # data plane * **RedisVL**: tickets index with fields {id, title, body, cwe?, component?} + vector embedding; use built-in vectorizers. ([Redis Vector Library][3]) * Optional long-horizon: Postgres/pgvector later—out of scope for 3-min demo. --- # CI/CD ## .github/workflows/verify-and-gate.yml * **Jobs** 1. build_preview: deploy PR branch to **AWS** as preview (Lambda URL or ECS Copilot). ([Amazon Web Services, Inc.][4]) 2. nodezero_verify: call /verify/run → targeted checks for the affected service. ([Horizon3.ai][7]) 3. honeyhive_gate: push traces + metrics; if pass, label PR “verified-secure”. ([HoneyHive][13]) ## .github/workflows/create-pr.yml * On POST /pr/create: add failing **Qodo** tests, patch proposal; open PR via **Gram/GitHub**. ([Qodo Merge][14]) --- # minimal code stubs (illustrative) ### services/api/routes/pentest.py
python
# pseudo-python
@router.post("/pentest/start")
def start(target_url: str):
    job = mcp("nodezero").call("startAssessment", {"targetUrl": target_url})
    return {"job_id": job["id"]}

@router.get("/pentest/result")
def result(job_id: str):
    f = mcp("nodezero").call("getFindings", {"jobId": job_id})
    finding = pick_exploitable(f)
    return finding
(NodeZero surfaces *exploitable* findings with proof & impact.) ([Horizon3.ai][7]) ### services/workers/repro\_test\_gen.py
python
tickets = redisvl.similarity_search(query=finding['cwe']+" "+finding['service'], k=5)
prompt = assemble_test_prompt(finding, tickets)
qodo.create_tests_and_patch(repo, branch, prompt)   # via PR-Agent or Merge API
(Qodo/PR-Agent supports automated test generation tied to PR diffs.) ([Qodo Merge][15]) ### services/api/routes/pr.py
python
pr = gram.github.create_pr(owner, repo, head=branch, base="main",
                           title=f"Fix: {finding['cwe']}",
                           body=render_body(finding, tickets))
(GitHub REST POST /repos/:owner/:repo/pulls). ([GitHub Docs][16]) --- # optional background intel worker workers/cve_watcher.py * Poll **OSV/GHSA/NVD** (and optionally **Bright Data** + **Apify** scrapes) for packages used in the repo; attach advisories to the PR as comments. ([Google GitHub][17]) --- # presentation assets (3-min) ## demo flow (docs/demo-script.md) 1. **Overview slide (auto from Airia)** — “Find → Fix → Verify → Postmortem,” with target metric: “\~8 min to verified fix” (slide generated by Airia flow). ([Airia][18]) 2. **Click “Pentest preview”** — UI calls /pentest/start → /pentest/result shows one critical exploitable finding (NodeZero). ([Horizon3.ai][7]) 3. **Click “Create PR”** — UI calls /pr/create; Qodo adds failing test + patch; PR opens via Gram/GitHub. ([Qodo Merge][14]) 4. **Auto Verify** — GH Action builds preview on **AWS**; /verify/run re-tests just that vuln; **HoneyHive** gate turns green and shows traces. ([Amazon Web Services, Inc.][9]) 5. **Postmortem** — Upload sample audio; Gladia → LlamaIndex → Airia outputs a single timeline slide with links to the HoneyHive run and NodeZero proof-of-fix. ([Gladia][10]) **Pro tips for stage:** keep logs visible (HoneyHive traces), show PR diff with tests, and paste the NodeZero “proof of fix” URL into the slide notes. ([HoneyHive][13]) --- # acceptance criteria (judge-ready) * ✅ **Idea**: closed-loop, agent-orchestrated SecDevOps that *proves* fixes (NodeZero MCP) and produces exec-level collateral (Airia). ([Horizon3.ai][19]) * ✅ **Technical**: real pentest control via MCP; CI preview on **AWS**; PR with AI-generated tests; semantic ticket grounding; eval gate with traces. ([Amazon Web Services, Inc.][9]) * ✅ **Tool Use**: (at minimum in demo) Horizon3, Qodo, Gram/GitHub, HoneyHive, Stytch, RedisVL, Gladia, LlamaIndex, Airia, AWS. * ✅ **Presentation**: one overview slide + 3 live clicks; visible logs and auditable proof. --- # security & guardrails * **Stytch passkeys** for sensitive actions (run pentest, merge). ([Stytch][1]) * **Scoped MCP tools** only (NodeZero blog details a constrained API-native runtime). ([Horizon3.ai][20]) * **Secrets** via CI OIDC and AWS Parameter Store; no secrets in repo. * **Read-only default** on Gram GitHub MCP; only PR branch write. --- # quickstart
bash
# 1) bootstrap
cp .env.example .env && $EDITOR .env
docker compose -f infra/redis/docker-compose.yml up -d   # Redis Stack for RedisVL

# 2) seed RAG
python -m venv .venv && source .venv/bin/activate
pip install redisvl llama-index
python services/rag/index_tickets.py                    # builds RedisVL index :contentReference[oaicite:51]{index=51}

# 3) run API
pip install fastapi uvicorn requests
uvicorn services.api.app:app --reload

# 4) connect MCP servers (per tool readme)
#    - horizon3-nodezero (use H3 token/org) :contentReference[oaicite:52]{index=52}
#    - gram-github (connect your GitHub App) :contentReference[oaicite:53]{index=53}
#    - honeyhive (project & dataset)        :contentReference[oaicite:54]{index=54}
#    - etc.
--- # stretch modules (toggleable) * **CVE watcher** (OSV/GHSA/NVD + Bright Data + Apify) highlights related vulnerabilities in affected packages with links & severity. ([Google GitHub][17]) * **Exploit PoC sandbox** — synthesize targeted PoCs from advisories and run in isolated preview env on **AWS**. (Use the same preview infra.) ([Amazon Web Services, Inc.][9]) --- # what we will actually show (copy/paste into README) **Three clicks**: Pentest → Create PR → Verify & Gate. Then open the auto-made postmortem slide. That’s it. --- if you want, I can now generate the initial repo files (README.md, env example, GitHub Actions, and stub FastAPI routes) so you can clone and run locally. [1]: https://stytch.com/docs/guides/passkeys/overview?utm_source=chatgpt.com "Passkeys overview | Stytch Consumer authentication" [2]: https://docs.horizon3.ai/downloads/mcp/?utm_source=chatgpt.com "NodeZero ® MCP Server" [3]: https://docs.redisvl.com/?utm_source=chatgpt.com "Redis Vector Library (RedisVL) — RedisVL" [4]: https://aws.amazon.com/blogs/compute/previewing-environments-using-containerized-aws-lambda-functions/?utm_source=chatgpt.com "Previewing environments using containerized ..." [5]: https://docs.gladia.io/?utm_source=chatgpt.com "Welcome to Gladia - Gladia" [6]: https://stytch.com/docs/api/webauthn-authenticate-start?utm_source=chatgpt.com "Start WebAuthn authentication - Stytch" [7]: https://horizon3.ai/nodezero/?utm_source=chatgpt.com "The NodeZero Platform" [8]: https://docs.redisvl.com/en/latest/user_guide/04_vectorizers.html?utm_source=chatgpt.com "Vectorizers" [9]: https://aws.amazon.com/blogs/containers/build-preview-environments-for-amazon-ecs-applications-with-aws-copilot/?utm_source=chatgpt.com "Build preview environments for Amazon ECS applications ..." [10]: https://www.gladia.io/product/async-transcription?utm_source=chatgpt.com "The Complete Speech-to-Text API" [11]: https://www.speakeasy.com/product/gram?utm_source=chatgpt.com "Gram: Create, curate, and host MCP servers - Speakeasy" [12]: https://brightdata.com/ai/mcp-server?utm_source=chatgpt.com "The Web MCP by Bright Data - Start with a Free Plan" [13]: https://www.honeyhive.ai/evaluation?utm_source=chatgpt.com "LLM Evaluation & Benchmarking" [14]: https://qodo-merge-docs.qodo.ai/tools/?utm_source=chatgpt.com "Tools - Qodo Merge (and open-source PR-Agent)" [15]: https://qodo-merge-docs.qodo.ai/tools/test/?utm_source=chatgpt.com "💎 Generate Tests - Qodo Merge (and open-source PR-Agent)" [16]: https://docs.github.com/en/rest/pulls?utm_source=chatgpt.com "REST API endpoints for pull requests" [17]: https://google.github.io/osv.dev/api/?utm_source=chatgpt.com "API | OSV - Google" [18]: https://airia.com/ai-platform/?utm_source=chatgpt.com "Airia AI Platform | Build, Deploy & Scale Enterprise AI" [19]: https://horizon3.ai/news/press-release/horizon3-ai-introduces-mcp-server-to-accelerate-remediation-and-close-the-find-fix-verify-loop/?utm_source=chatgpt.com "Horizon3.ai Introduces MCP Server to Accelerate ..." [20]: https://horizon3.ai/intelligence/blogs/securing-the-nodezero-mcp-server-building-a-safe-agent-ready-runtime-for-enterprises/?utm_source=chatgpt.com "Securing the NodeZero® MCP Server"