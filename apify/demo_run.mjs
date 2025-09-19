#!/usr/bin/env node
// Demo runner for the Apify Signals → Summaries pipeline
import { isMockMode, processAndRank, writeJson, writeJsonl } from './lib/pipeline.mjs';

const mock = process.argv.includes('--mock') || process.env.MOCK === '1';

(async () => {
  try {
    const results = await processAndRank({
      query: 'site:vendor.com (advisory OR CVE) 2025',
      maxPages: 1,
      inScopeCpes: [
        'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'
      ],
    });
    await writeJson('mock_output.json', { mode: mock ? 'mock' : 'real', count: results.length, items: results.slice(0, 20) });
    await writeJsonl('mock_dataset.jsonl', results);
    console.log(`[ok] Wrote apify/mock_output.json and apify/mock_dataset.jsonl (${results.length} records)`);
  } catch (err) {
    console.error('[error]', err.stack || err.message || err);
    process.exit(1);
  }
})();

