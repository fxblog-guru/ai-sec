// A deliberately weak local HTTP server, for exercising T1-T2 against something real.
// Binds to 127.0.0.1 only. PLANTED DEFECTS - do not copy into real code.
//
//   node mock/server.mjs 9970
//
// Defects: no security headers, cookie without Secure/HttpOnly/SameSite, wildcard
// CORS with credentials, a verbose error page, an open redirect, a slow endpoint,
// and an endpoint that 500s on demand so auto-stop can be exercised.
import { createServer } from 'node:http';

const port = Number(process.argv[2] ?? 9970);
let errorsRemaining = 0;

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);

  // wildcard CORS, and credentials allowed alongside it
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('X-Powered-By', 'Express 4.17.1');
  res.setHeader('Server', 'mock/0.0.0');
  // no CSP, no HSTS, no X-Content-Type-Options, no X-Frame-Options, no Referrer-Policy

  if (url.pathname === '/login') {
    // every cookie flag that matters is missing
    res.setHeader('Set-Cookie', 'session=abc123; Path=/');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (url.pathname === '/go') {
    res.writeHead(302, { Location: url.searchParams.get('next') ?? '/' });
    return res.end();
  }

  if (url.pathname === '/boom') {
    res.writeHead(500, { 'Content-Type': 'text/html' });
    return res.end(
      '<h1>TypeError: Cannot read property \'id\' of undefined</h1>' +
      '<pre>at getOrder (/var/app/src/db/orders.js:142:18)\n' +
      '  at /var/app/node_modules/express/lib/router/route.js:137:13</pre>',
    );
  }

  // flips to failing, so the auto-stop rules have something to fire on
  if (url.pathname === '/fail-for') {
    errorsRemaining = Number(url.searchParams.get('n') ?? 10);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ failing: errorsRemaining }));
  }
  if (errorsRemaining > 0) {
    errorsRemaining -= 1;
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    return res.end('unavailable');
  }

  if (url.pathname === '/slow') {
    return setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('eventually');
    }, Number(url.searchParams.get('ms') ?? 3000));
  }

  if (url.pathname === '/admin/settings') {
    // no authorization check at all
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ admin: true, secret_rotation: 'never' }));
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  return res.end('<!doctype html><title>mock</title><p>mock target</p>');
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`mock target on http://127.0.0.1:${port}\n`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}

export default server;
