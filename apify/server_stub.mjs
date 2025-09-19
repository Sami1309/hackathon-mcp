#!/usr/bin/env node
// Minimal HTTP stub to expose the pipeline to the app
import http from 'node:http';
import { processAndRank } from './lib/pipeline.mjs';

const port = process.env.SIGNALS_PORT ? Number(process.env.SIGNALS_PORT) : 8788;

function json(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true });

  if (req.method === 'POST' && url.pathname === '/signals/collect') {
    const body = await readBody(req);
    try {
      if (body.mock === true) process.env.MOCK = '1';
      const items = await processAndRank({ query: body.query || undefined, maxPages: body.maxPages || 1, inScopeCpes: body.inScopeCpes || [] });
      return json(res, 200, { ok: true, count: items.length, items });
    } catch (e) {
      return json(res, 500, { ok: false, error: String(e?.message || e) });
    }
  }

  json(res, 404, { ok: false, error: 'not found' });
});

server.listen(port, () => console.log(`[signals] listening on http://localhost:${port} (POST /signals/collect)`));

