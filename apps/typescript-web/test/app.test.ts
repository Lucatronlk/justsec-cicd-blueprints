import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { createApp } from '../src/app';

test('serves page, API, health, and safe errors', async () => {
  const server = createApp();
  server.listen(0, '127.0.0.1');
  try {
    await once(server, 'listening');
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;

    const page = await fetch(base);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type') ?? '', /text\/html/);
    assert.match(page.headers.get('content-security-policy') ?? '', /default-src 'none'/);
    assert.match(await page.text(), /TypeScript scan target/);

    const api = await fetch(`${base}/api/info?ignored=1`);
    assert.deepEqual(await api.json(), { name: 'typescript-web', status: 'ready' });

    const health = await fetch(`${base}/health`);
    assert.deepEqual(await health.json(), { status: 'ok' });

    const head = await fetch(`${base}/health`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), String(Buffer.byteLength('{"status":"ok"}\n')));
    assert.equal(await head.text(), '');

    const missing = await fetch(`${base}/unknown?token=not-echoed`);
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { error: 'not found' });

    const rejected = await fetch(`${base}/api/info`, { method: 'POST' });
    assert.equal(rejected.status, 405);
    assert.equal(rejected.headers.get('allow'), 'GET, HEAD');
    assert.deepEqual(await rejected.json(), { error: 'method not allowed' });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
