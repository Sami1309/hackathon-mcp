Goal (what it does, plainly)

Kicks off a NodeZero pentest on a preview URL, uses RedisVL to mine support tickets into a prioritized list of likely-broken pages and failure modes, opens a GitHub PR with failing tests + a minimal patch, re-verifies the fix on an ephemeral preview in AWS, gates merge via HoneyHive, and exports a single postmortem slide. 
explore.airia.com
+5
Horizon3
+5
Redis
+5

Architecture (thin, demo-ready)

Frontend: the static page above.

Backend API (FastAPI/Express):

/auth/* (Stytch passkeys)

/tickets/prioritize (RedisVL)

/pentest/* (NodeZero MCP)

/pr/* (GitHub + Qodo)

/verify/run (AWS preview + NodeZero verify + HoneyHive)

/postmortem/slide (Gladia → LlamaIndex → Airia)

Keep each client as a small typed wrapper; everything async with idempotent retries. 
explore.airia.com
+8
Stytch
+8
Horizon3
+8

Minimal service contracts

POST /tickets/prioritize

Body: { "tickets": [{ "id": "...", "title": "...", "body": "..." }], "topk": 200 }

Process: embed tickets → build RedisVL index (if not exists) → similarity search + hierarchical clustering → aggregate per site_path → return ranked list with signals

Return: { "priorities": [{ "path": "/checkout", "failure": "timeout/502", "score": 0.91, "signals": {...}, "related_paths": [...] }...] } 
Redis

POST /pentest/start → NodeZero MCP startAssessment with preview URL; return job_id. 
Horizon3

GET /pentest/result?job_id=... → exploitable finding (id, cwe, service, evidence). 
Horizon3

POST /pr/create → Qodo generate tests/patch, GitHub POST /repos/:owner/:repo/pulls. 
Qodo Merge
+1

POST /verify/run → build preview (ECS Copilot or containerized Lambda URL), run NodeZero verify on that URL, post HoneyHive eval/gate. 
Amazon Web Services, Inc.
+2
Amazon Web Services, Inc.
+2

POST /postmortem/slide → Gladia transcript → LlamaIndex extract timeline → Airia document-generation (PPTX) with links to proof-of-fix and trace. 
Gladia
+2
LlamaIndex Docs
+2

RedisVL prioritization algorithm (simple & fast)

Embed each ticket (title+body) with the built-in vectorizers; store {id, text, route_hint?}.

Search & cluster: run KNN for each ticket; build similarity graph; Louvain/connected components to form “issue families.”

Route inference: extract probable site_path from text (/checkout, /search, etc.), or use route hints if present.

Rank by a composite: (#tickets in family, recency, severity terms like “crash/500/timeout”, and overlap with pentest services).

Emit a prioritized table: path, likely_failure, score, signals, related_paths.
This keeps the logic clear and demo-ready while showcasing RedisVL’s vector search. 
Redis

CI preview + verify (choose one)

ECS Copilot: each PR → deploys service to a per-branch environment with its own URL; tear down on close/merge. 
Amazon Web Services, Inc.

Containerized Lambda URL: ultra-fast ephemeral URL per PR; near zero idle cost. 
Amazon Web Services, Inc.

“Single-slide” postmortem

Inputs: NodeZero verify result (proof-of-fix URL), HoneyHive run link (trace id), PR URL, brief timeline from transcript/logs.

Flow: Gladia (transcribe) → LlamaIndex (extract owners/dates/events) → Airia document generation (one PPTX slide). 
Gladia
+2
LlamaIndex Docs
+2

Example .env (short)
STYTCH_PROJECT_ID=...
STYTCH_SECRET=...
H3_API_TOKEN=...
H3_ORG_ID=...
GITHUB_APP_ID=...
GITHUB_INSTALLATION_ID=...
GITHUB_PRIVATE_KEY=...
HONEYHIVE_API_KEY=...
QODO_API_KEY=...
REDIS_URL=redis://localhost:6379
GLADIA_API_KEY=...
AWS_REGION=us-east-1

Suggested build order (90-minute target)

Tickets → priorities (/tickets/prioritize) with RedisVL only (local Redis Stack). 
Redis

Pentest stubs (/pentest/*) hitting NodeZero MCP in dev. 
Horizon3

PR create (GitHub REST) + tests (Qodo). 
GitHub Docs
+1

Verify (pick ECS Copilot or Lambda URL) + HoneyHive gate. 
Amazon Web Services, Inc.
+1

Slide export (Gladia → LlamaIndex → Airia). 
Gladia
+2
LlamaIndex Docs
+2

Acceptance criteria

Prioritization table appears from pasted tickets with route-level grouping. (RedisVL) 
Redis

Find-Fix-Verify demo completes with a PR link, verify proof-of-fix, and HoneyHive gate = passed. 
Horizon3
+2
GitHub Docs
+2

Export returns a one-slide PPTX with PR URL, NodeZero proof, and HoneyHive trace. (Gladia/LlamaIndex/Airia) 
Gladia
+2
LlamaIndex Docs
+2

If you want, I can also split the mock page into separate CSS/JS files and scaffold tiny server stubs for each endpoint so you can run it locally.