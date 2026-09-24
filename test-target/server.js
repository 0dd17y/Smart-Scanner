'use strict';

/**
 * test-target/server.js — an intentionally INSECURE local app used ONLY to demo and
 * verify Smart Scan safely. Do not deploy this. Runs on http://localhost:4000.
 *
 * Deliberate weaknesses: no security headers, reflected XSS, insecure session cookie,
 * exposed robots.txt / .env, fake SQL error on a bad quote, login form with default
 * creds and no rate limiting, open redirect, and SSTI-like reflection.
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.TARGET_PORT || 4000;

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

// A JWT deliberately signed with a weak secret ("secret") for the JWT check.
function b64url(b) {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jwtHs256(payload, secret) {
  const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64url(JSON.stringify(payload));
  const s = b64url(crypto.createHmac('sha256', secret).update(h + '.' + p).digest());
  return `${h}.${p}.${s}`;
}
const WEAK_JWT = jwtHs256({ user: 'admin', role: 'user' }, 'secret');

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://localhost:${PORT}`);
  const q = u.searchParams;

  // Insecure session cookie (no Secure/HttpOnly/SameSite), low entropy + weak JWT
  res.setHeader('Set-Cookie', ['SESSIONID=12345; Path=/', 'token=' + WEAK_JWT + '; Path=/']);

  // ---- Increment 3 vulnerable fixtures ----
  // Blind command injection (time-based) simulation: any param containing sleep/ping N
  const allVals = [...q.values()].join(' ');
  const sleepM = allVals.match(/sleep\s+(\d+)/i) || allVals.match(/ping\s+-[nc]\s+(\d+)/i);
  if (sleepM) {
    const secs = Math.min(parseInt(sleepM[1], 10) || 0, 4);
    return setTimeout(() => send(res, 200, '<p>done</p>'), secs * 1000);
  }
  // XXE: an XML body with a file:// external entity gets "resolved"
  if (req.method === 'POST' && /xml/i.test(req.headers['content-type'] || '')) {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      if (/file:\/\/\/etc\/passwd/.test(b)) {
        return send(res, 200, '<result>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin</result>');
      }
      return send(res, 200, '<result>ok</result>');
    });
    return;
  }
  // IDOR: any user record readable, content length grows with id, no auth
  if (u.pathname === '/api/user') {
    const id = parseInt(q.get('id') || '1', 10) || 1;
    const notes = 'x'.repeat(id * 30);
    return send(res, 200, JSON.stringify({ id, name: 'User ' + id, email: `user${id}@corp.example`, notes }),
      { 'Content-Type': 'application/json' });
  }
  // Spring-style actuator exposure
  if (u.pathname === '/actuator/env') {
    return send(res, 200, JSON.stringify({ propertySources: [{ name: 'systemProperties', properties: { 'db.password': { value: 'hunter2' } } }] }),
      { 'Content-Type': 'application/json' });
  }
  // Exposed VCS metadata
  if (u.pathname === '/.git/config') {
    return send(res, 200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:corp/portal.git\n',
      { 'Content-Type': 'text/plain' });
  }
  // GraphQL introspection enabled
  if (u.pathname === '/graphql') {
    return send(res, 200, JSON.stringify({ data: { __schema: { types: [{ name: 'Query' }, { name: 'User' }] } } }),
      { 'Content-Type': 'application/json' });
  }
  // OAuth open redirect (unvalidated redirect_uri)
  if (u.pathname === '/oauth/authorize') {
    const ru = q.get('redirect_uri') || '/';
    res.writeHead(302, { Location: ru });
    return res.end();
  }
  // Mass assignment: echoes back submitted fields (accepts privileged fields)
  if (u.pathname === '/profile' && req.method === 'POST') {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => send(res, 200, '<h1>Profile updated</h1><pre>' + b + '</pre>'));
    return;
  }

  // robots.txt exposure
  if (u.pathname === '/robots.txt') {
    return send(res, 200, 'User-agent: *\nDisallow: /admin\nDisallow: /secret-backup\n', {
      'Content-Type': 'text/plain',
    });
  }
  // .env exposure
  if (u.pathname === '/.env') {
    return send(res, 200, 'API_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2\n', {
      'Content-Type': 'text/plain',
    });
  }

  // Reflected XSS + fake SQL error + SSTI-ish reflection on /search
  if (u.pathname === '/search') {
    const term = q.get('q') || '';
    if (term.includes("'")) {
      return send(
        res,
        500,
        '<h1>Database Error</h1><pre>You have an error in your SQL syntax; check the manual near \'' +
          term +
          '\'</pre>'
      );
    }
    // naive template eval to simulate SSTI (evaluate {{7*7}})
    let rendered = term.replace(/\{\{\s*7\s*\*\s*7\s*\}\}/g, '49');
    return send(
      res,
      200,
      `<html><body><h1>Search</h1><p>Results for: ${rendered}</p>
       <form action="/search"><input name="q"><button>Go</button></form></body></html>`
    );
  }

  // Open redirect
  if (u.pathname === '/go') {
    const dest = q.get('url') || '/';
    res.writeHead(302, { Location: dest });
    return res.end();
  }

  // Login form (default creds, no rate limiting)
  if (u.pathname === '/login') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const p = new URLSearchParams(body);
        if (p.get('username') === 'admin' && p.get('password') === 'admin') {
          res.writeHead(302, { Location: '/dashboard' });
          return res.end();
        }
        return send(res, 200, '<h1>Login</h1><p>Invalid username or password.</p>' + loginForm());
      });
      return;
    }
    return send(res, 200, '<h1>Login</h1>' + loginForm());
  }

  if (u.pathname === '/dashboard') {
    return send(res, 200, '<h1>Dashboard</h1><p>Welcome, admin.</p>');
  }
  if (u.pathname === '/admin') {
    return send(res, 200, '<h1>Admin</h1><p>Admin panel.</p>');
  }

  // Home page links to the vulnerable endpoints so the crawler discovers them.
  if (u.pathname === '/') {
    // Host-header injection: reflect X-Forwarded-Host into an absolute link (unsafe).
    const xfh = req.headers['x-forwarded-host'] || req.headers['host'] || '';
    return send(
      res,
      200,
      `<html><head><link rel="canonical" href="https://${xfh}/"></head><body>
        <h1>Vulnerable Test Portal</h1>
        <ul>
          <li><a href="/search?q=hello">Search</a></li>
          <li><a href="/login">Login</a></li>
          <li><a href="/go?url=/dashboard">Continue</a></li>
          <li><a href="/admin">Admin</a></li>
          <li><a href="/api/user?id=1">My account</a></li>
          <li><a href="/oauth/authorize?response_type=code&client_id=web&redirect_uri=/dashboard">Connect</a></li>
        </ul>
        <form action="/profile" method="POST">
          <input name="name" value="Test User">
          <input name="email" value="test@corp.example">
          <button type="submit">Save profile</button>
        </form>
      </body></html>`
    );
  }

  return send(res, 404, '<h1>404 Not Found</h1>');
});

function loginForm() {
  return `<form action="/login" method="POST">
    <input name="username" placeholder="username">
    <input type="password" name="password" placeholder="password">
    <button type="submit">Sign in</button>
  </form>`;
}

server.listen(PORT, () => {
  /* eslint-disable no-console */
  console.log(`\n  [INSECURE TEST TARGET] http://localhost:${PORT}`);
  console.log('  For Smart Scan verification only. Do NOT expose this.\n');
});
