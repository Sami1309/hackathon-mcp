#!/usr/bin/env node
// Minimal webhook receiver for Apify run completion
import http from 'node:http';

const port = process.env.PORT ? Number(process.env.PORT) : 8787;

function json(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'POST' && url.pathname === '/apify/webhook') {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      try {
        const evt = JSON.parse(raw || '{}');
        console.log('[webhook] actor run completed:', {
          actorId: evt.actId,
          runId: evt.id,
          datasetId: evt.defaultDatasetId,
          status: evt.status,
        });
        json(res, 200, { ok: true });
      } catch (e) {
        json(res, 400, { ok: false, error: String(e) });
      }
    });
    return;
  }
  json(res, 404, { ok: false, error: 'not found' });
});

server.listen(port, () => console.log(`[webhook] listening on http://localhost:${port}/apify/webhook`));

