// Node >=18 ESM. No external deps. Supports mock and real modes.
// Usage: import functions and wire into your API. See demo_run.mjs.

const hasFetch = typeof fetch === 'function';
const fs = await import('node:fs');

export function isMockMode() {
  return process.env.MOCK === '1' || process.argv.includes('--mock');
}

function readJson(localPath) {
  const p = new URL(`../${localPath}`, import.meta.url);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function readText(localPath) {
  const p = new URL(`../${localPath}`, import.meta.url);
  return fs.readFileSync(p, 'utf8');
}

// Node fs helper is available via top-level import above

async function httpGet(url, headers = {}) {
  if (!hasFetch) throw new Error('fetch not available');
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

async function httpPost(url, body, headers = {}) {
  if (!hasFetch) throw new Error('fetch not available');
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`POST ${url} -> ${res.status}`);
  return res.json();
}

// 1) Run Apify Actor (e.g., google-search-scraper) and return { runId, datasetId }
export async function runGoogleSearchActor({ query, maxPages = 1, saveHtml = true } = {}) {
  if (isMockMode()) {
    const items = readJson('sample/google_search_results.json');
    return { runId: 'mock-run', datasetId: 'mock-dataset', items };
  }
  const token = process.env.APIFY_TOKEN;
  if (!token) throw new Error('APIFY_TOKEN not set');
  const actorId = 'apify/google-search-scraper';
  const input = { queries: [query], maxPagesPerQuery: maxPages, saveHtml };
  const run = await httpPost(`https://api.apify.com/v2/acts/${actorId}/runs?token=${token}`, input);
  return { runId: run.data.id, datasetId: run.data.defaultDatasetId };
}

// 2) Fetch dataset items for a run
export async function fetchDatasetItems(datasetId) {
  if (isMockMode()) return readJson('sample/google_search_results.json');
  const token = process.env.APIFY_TOKEN;
  if (!token) throw new Error('APIFY_TOKEN not set');
  const url = `https://api.apify.com/v2/datasets/${datasetId}/items?token=${token}&clean=true`;
  return httpGet(url);
}

// 3) Normalize various sources to unified schema
export function normalizeSearchItems(items = []) {
  return items.map((it) => ({
    cve: extractCve((it.title || '') + ' ' + (it.snippet || '')),
    title: it.title || it.snippet || 'Advisory',
    source: 'search',
    url: it.url || it.link,
    published: it.publishedAt || null,
    cvss: null,
    kev: null,
    epss: null,
    poc_public: null,
    products: null,
    notes: it.snippet || null,
    raw_store_key: it.pageKey || null,
  }));
}

export function extractCve(text = '') {
  const m = text.toUpperCase().match(/CVE-\d{4}-\d{4,7}/);
  return m ? m[0] : null;
}

// 4) Load KEV/NVD/EPSS/ExploitDB samples (or fetch real)
export async function loadSignals() {
  if (isMockMode()) {
    return {
      kev: readJson('sample/kev.json'),
      nvd: readJson('sample/nvd_sample.json'),
      epss: readJson('sample/epss_sample.json'),
      exploitdb: readJson('sample/exploitdb_sample.json'),
    };
  }
  // Real fetchers (minimal; extend as needed)
  const kev = await httpGet('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  // NVD rate limits; consider API key if needed. Example for one CVE is omitted here.
  const epss = await httpGet('https://api.first.org/data/v1/epss?limit=2000');
  // Exploit-DB has HTML pages; recommend collecting via Apify Actor. Omitted here.
  return { kev, nvd: { CVE_Items: [] }, epss, exploitdb: { cves: [] } };
}

// 5) Enrich records
export function enrichWithKEV(records, kev) {
  const kevSet = new Set((kev?.vulnerabilities || kev?.cves || []).map((r) => r.cveID || r.cve || r.id));
  return records.map((r) => ({ ...r, kev: r.cve ? kevSet.has(r.cve) : false }));
}

export function enrichWithNVD(records, nvd) {
  const byCve = new Map();
  (nvd?.CVE_Items || []).forEach((item) => {
    const id = item.cve?.CVE_data_meta?.ID;
    const cvss = item.impact?.baseMetricV3?.cvssV3?.baseScore ?? item.impact?.baseMetricV2?.cvssV2?.baseScore ?? null;
    const cpes = (item.configurations?.nodes || [])
      .flatMap((n) => n.cpe_match || [])
      .filter((x) => x?.cpe23Uri)
      .map((x) => x.cpe23Uri);
    if (id) byCve.set(id, { cvss, cpes });
  });
  return records.map((r) => {
    if (!r.cve || !byCve.has(r.cve)) return r;
    const info = byCve.get(r.cve);
    return { ...r, cvss: r.cvss ?? info.cvss ?? null, products: r.products ?? (info.cpes?.length ? info.cpes : null) };
  });
}

export function enrichWithEPSS(records, epss) {
  const map = new Map();
  const rows = epss?.data || epss?.scores || [];
  rows.forEach((row) => {
    const id = row.cve || row.CVE;
    if (id) map.set(id, { score: Number(row.epss ?? row.score ?? 0), percentile: Number(row.percentile ?? 0), asOf: row.date || epss?.timestamp || null });
  });
  return records.map((r) => ({ ...r, epss: r.cve && map.has(r.cve) ? map.get(r.cve) : r.epss ?? null }));
}

export function enrichWithExploitDb(records, exploitdb) {
  const set = new Set((exploitdb?.cves || []).map((x) => x.toUpperCase()));
  return records.map((r) => ({ ...r, poc_public: r.cve ? set.has(r.cve) : r.poc_public ?? false }));
}

// 6) Rank findings
export function rankFindings(records, { inScopeCpes = [] } = {}) {
  const inScope = new Set(inScopeCpes);
  const score = (r) => {
    const kevBoost = r.kev ? 100 : 0;
    const epssScore = r.epss?.score ?? 0;
    const pocBoost = r.poc_public ? 10 : 0;
    const cpeBoost = (r.products || []).some((cpe) => inScope.has(cpe)) ? 5 : 0;
    return kevBoost + epssScore * 100 + pocBoost + cpeBoost;
  };
  return [...records]
    .map((r) => ({ ...r, _rank: score(r) }))
    .sort((a, b) => b._rank - a._rank)
    .map(({ _rank, ...rest }) => rest);
}

// 7) High-level convenience: process and rank
export async function processAndRank({ query = 'site:vendor.com (advisory OR CVE) 2025', maxPages = 1, inScopeCpes = [] } = {}) {
  const run = await runGoogleSearchActor({ query, maxPages });
  const items = run.items || (await fetchDatasetItems(run.datasetId));
  const base = normalizeSearchItems(items);
  const { kev, nvd, epss, exploitdb } = await loadSignals();
  const step1 = enrichWithKEV(base, kev);
  const step2 = enrichWithNVD(step1, nvd);
  const step3 = enrichWithEPSS(step2, epss);
  const step4 = enrichWithExploitDb(step3, exploitdb);
  return rankFindings(step4, { inScopeCpes });
}

// 8) Dataset write helpers (local JSONL for mock/demo)
export async function writeJsonl(filePath, records = []) {
  const fs = await import('node:fs/promises');
  const body = records.map((r) => JSON.stringify(r)).join('\n') + (records.length ? '\n' : '');
  const p = new URL(`../${filePath}`, import.meta.url);
  await fs.writeFile(p, body, 'utf8');
}

export async function writeJson(filePath, obj) {
  const fs = await import('node:fs/promises');
  const p = new URL(`../${filePath}`, import.meta.url);
  await fs.writeFile(p, JSON.stringify(obj, null, 2), 'utf8');
}
