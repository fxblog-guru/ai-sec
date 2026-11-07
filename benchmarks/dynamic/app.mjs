// A deliberately vulnerable application. It exists to be scanned.
//
// DO NOT DEPLOY THIS. It binds to 127.0.0.1 and refuses to bind anywhere else,
// on purpose: a benchmark target that can be reached from another machine is an
// invitation, and "it was only for testing" is how these end up on the internet.
//
// Every defect below is planted and recorded in ../dynamic-expected.json. One
// endpoint is deliberately CORRECT — /api/profile/:id checks ownership — because
// a benchmark made only of defects measures recall and nothing else. A scanner
// that reports everything scores full marks on it.
import { createServer } from 'node:http';

export const HOST = '127.0.0.1';

export const ACCOUNTS = [
  { name: 'alice', cookie: 'sid=session-for-alice', owns: ['/api/orders/1'] },
  { name: 'bob', cookie: 'sid=session-for-bob', owns: ['/api/orders/2'] },
];

const ORDERS = {
  1: { id: 1, owner: 'alice', total: '412.00', card_last4: '4242' },
  2: { id: 2, owner: 'bob', total: '96.50', card_last4: '1881' },
};

const PROFILES = {
  alice: { user: 'alice', email: 'alice@example.invalid' },
  bob: { user: 'bob', email: 'bob@example.invalid' },
};

/**
 * Whoever the cookie says, with no signature and no expiry.
 *
 * Forgeable, and not in the expected file: nothing here can observe it from
 * outside, and a benchmark that records defects no check could ever reach
 * measures the benchmark's imagination.
 */
function sessionUser(req) {
  const raw = req.headers.cookie ?? '';
  const m = /sid=session-for-([a-z]+)/.exec(raw);
  return m ? m[1] : null;
}

function handler(req, res) {
  const url = new URL(req.url, `http://${HOST}`);

  // D5: a wildcard origin together with credentials. D6: the framework banner.
  // Sent on every response, which is how both of these usually happen — one
  // line in a middleware nobody has read since.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('X-Powered-By', 'Express 4.17.1');
  // D1-D4: no Content-Security-Policy, no X-Content-Type-Options, no frame
  // protection, no Referrer-Policy. Nothing to see, which is the point.

  if (url.pathname === '/login') {
    const user = url.searchParams.get('user') ?? 'alice';
    // D7: no Secure, no HttpOnly, no SameSite.
    res.setHeader('Set-Cookie', `sid=session-for-${user}; Path=/`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, user }));
  }

  if (url.pathname === '/go') {
    // D8: the redirect target comes straight from the query string.
    const next = url.searchParams.get('next') ?? url.searchParams.get('url') ?? '/';
    res.writeHead(302, { Location: next });
    return res.end();
  }

  if (url.pathname === '/boom') {
    // D9: the stack trace reaches the browser.
    res.writeHead(500, { 'Content-Type': 'text/html' });
    return res.end(
      '<h1>Internal Server Error</h1><pre>TypeError: Cannot read properties of undefined\n'
      + '    at getOrder (/srv/shop/src/db/orders.js:142:18)\n'
      + '    at /srv/shop/node_modules/express/lib/router/route.js:149:13</pre>',
    );
  }

  if (url.pathname.startsWith('/api/orders/')) {
    const id = url.pathname.split('/').pop();
    const who = sessionUser(req);
    if (!who) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'sign in' }));
    }
    const order = ORDERS[id];
    if (!order) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'no such order' }));
    }
    // D10: authenticated, and that is all. The session is never compared to the
    // order's owner, so any signed-in user reads every order by its number.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(order));
  }

  if (url.pathname.startsWith('/api/profile/')) {
    const id = url.pathname.split('/').pop();
    const who = sessionUser(req);
    if (!who) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'sign in' }));
    }
    // Deliberately correct. The same shape as the orders handler, one line
    // longer. A check that cannot tell these two apart is not a check.
    if (who !== id) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'not yours' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(PROFILES[id] ?? {}));
  }

  if (url.pathname === '/api/inbox') {
    const who = sessionUser(req);
    if (!who) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'sign in' }));
    }
    // Also deliberately correct, and correct in the harder way: it answers 200
    // to everyone. The object it returns is the caller's own, so a check that
    // reads the status code and stops reports it, and a check that compares the
    // bodies does not. That difference is the whole point of comparing bodies.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ user: who, messages: [`hello ${who}`] }));
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  return res.end('<!doctype html><title>shop</title><p>ok</p>');
}

/**
 * Start on an ephemeral loopback port.
 *
 * The host is not a parameter. Making it one would mean somebody could pass
 * 0.0.0.0, and the comment at the top of this file would become decoration.
 */
export async function start() {
  const server = createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, HOST, resolve);
  });
  const { port } = server.address();
  return {
    origin: `http://${HOST}:${port}`,
    port,
    accounts: ACCOUNTS,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
