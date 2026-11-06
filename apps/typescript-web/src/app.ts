import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

const page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TypeScript scan target</title>
</head>
<body>
  <main>
    <h1>TypeScript scan target</h1>
    <p>Small HTTP service for local build and security scans.</p>
    <p>API: <a href="/api/info">/api/info</a> · Health: <a href="/health">/health</a></p>
  </main>
</body>
</html>`;

function respond(res: ServerResponse, status: number, contentType: string, body: string, head = false): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; style-src 'none'; frame-ancestors 'none'",
    'referrer-policy': 'no-referrer',
  });
  res.end(head ? undefined : body);
}

export function createApp() {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    // Use only URL path; never reflect query strings or headers in response or logs.
    const path = req.url?.split('?', 1)[0];
    const method = req.method;
    let status = 200;
    const head = method === 'HEAD';

    if (method !== 'GET' && method !== 'HEAD') {
      status = 405;
      res.setHeader('allow', 'GET, HEAD');
      respond(res, status, 'application/json; charset=utf-8', '{"error":"method not allowed"}\n');
    } else if (path === '/') {
      respond(res, status, 'text/html; charset=utf-8', page, head);
    } else if (path === '/api/info') {
      respond(res, status, 'application/json; charset=utf-8', '{"name":"typescript-web","status":"ready"}\n', head);
    } else if (path === '/health') {
      respond(res, status, 'application/json; charset=utf-8', '{"status":"ok"}\n', head);
    } else {
      status = 404;
      respond(res, status, 'application/json; charset=utf-8', '{"error":"not found"}\n', head);
    }
    // No user input is recorded; deployer should collect stdout with retention controls.
    console.info(JSON.stringify({ event: 'request', method, path: path === '/' || path === '/api/info' || path === '/health' ? path : 'other', status }));
  });
}
