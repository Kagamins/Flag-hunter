/* صائد الأعلام — أدوات الويب (تحليل فقط): فاحص طلبات/استجابات HTTP، المقارن، توليد أمر curl.
   Browser: window.CTFW   Node: module.exports */
(function (root, factory) {
  const C = (typeof module === 'object' && module.exports) ? require('./core.js') : root.CTF;
  const W = factory(C);
  if (typeof module === 'object' && module.exports) module.exports = W; else root.CTFW = W;
})(typeof self !== 'undefined' ? self : this, function (C) {
  'use strict';
  const W = {};
  const safeDecode = s => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; } };
  const splitParams = q => q.split('&').filter(Boolean).map(kv => { const i = kv.indexOf('='); return i < 0 ? [safeDecode(kv), ''] : [safeDecode(kv.slice(0, i)), safeDecode(kv.slice(i + 1))]; });

  W.parseHttp = raw => {
    const text = raw.replace(/\r\n/g, '\n').replace(/^\s+/, '');
    const cut = text.indexOf('\n\n');
    const head = cut >= 0 ? text.slice(0, cut) : text, body = cut >= 0 ? text.slice(cut + 2) : '';
    const lines = head.split('\n'), first = (lines[0] || '').trim();
    const p = { kind: 'unknown', headers: [], query: [], cookies: [], setCookies: [], bodyParams: [], json: null, body, first };
    let m;
    if ((m = first.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/[\d.]+))?$/))) { p.kind = 'request'; p.method = m[1]; p.path = m[2]; p.version = m[3] || 'HTTP/1.1'; }
    else if ((m = first.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/))) { p.kind = 'response'; p.version = m[1]; p.status = +m[2]; p.reason = m[3]; }
    else { p.body = text; return p; }
    for (const l of lines.slice(1)) { const i = l.indexOf(':'); if (i > 0) p.headers.push([l.slice(0, i).trim(), l.slice(i + 1).trim()]); }
    const hv = n => (p.headers.find(h => h[0].toLowerCase() === n) || [])[1];
    p.host = hv('host');
    if (p.kind === 'request') {
      const qi = p.path.indexOf('?'); if (qi >= 0) p.query = splitParams(p.path.slice(qi + 1));
      const abs = /^https?:\/\//i.test(p.path);
      p.url = abs ? p.path : (p.host ? 'https://' + p.host + p.path : p.path);
    }
    for (const [k, v] of p.headers) {
      if (k.toLowerCase() === 'cookie') v.split(/;\s*/).filter(Boolean).forEach(c => { const i = c.indexOf('='); p.cookies.push(i < 0 ? [c, ''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()]); });
      if (k.toLowerCase() === 'set-cookie') { const parts = v.split(/;\s*/), nv = parts.shift(), i = nv.indexOf('='); const attrs = parts.map(a => a.toLowerCase()); p.setCookies.push({ name: nv.slice(0, i).trim(), value: nv.slice(i + 1).trim(), attrs: parts, httpOnly: attrs.includes('httponly'), secure: attrs.includes('secure') }); }
    }
    const ct = (hv('content-type') || '').toLowerCase(), b = body.trim();
    if (b) {
      if (/json/.test(ct) || /^[\[{]/.test(b)) { try { p.json = JSON.parse(b); } catch (e) { } }
      if (!p.json && (/x-www-form-urlencoded/.test(ct) || (p.kind === 'request' && /^[^=&\s]+=[^&\s]*(&[^=&\s]+=[^&\s]*)*$/.test(b)))) p.bodyParams = splitParams(b);
    }
    p.contentType = ct;
    return p;
  };

  W.flattenJson = (o, pre = '', out = []) => {
    if (out.length > 500) return out;
    if (o && typeof o === 'object') { for (const k of Object.keys(o)) W.flattenJson(o[k], pre ? pre + (Array.isArray(o) ? '[' + k + ']' : '.' + k) : k, out); }
    else out.push([pre || '(value)', String(o)]);
    return out;
  };

  // يحاول فك قيمة واحدة (كوكي، معامل...) ويعيد أفضل نتيجة مقروءة
  W.decodeValue = v => {
    if (!v || v.length < 3) return null;
    const jwt = C.jwtDecode(v);
    if (jwt) return { how: 'JWT', text: JSON.stringify(jwt.payload) };
    let cur = v, chain = [];
    const u = safeDecode(v); if (u !== v) { cur = u; chain.push('URL'); }
    if (cur.length >= 4) {
      const r = C.magic(cur, { depth: 4, maxNodes: 300, top: 3 });
      const best = r.outputs.find(o => o.score >= 60 || (/^[\[{]/.test(o.s) && (() => { try { JSON.parse(o.s); return true; } catch (e) { return false; } })()));
      const TR = /^(Reverse|ROT\d+|ROT47|Atbash)$/;
      const real = ch => ch.some(x => !TR.test(x)); // a pure ROT/reverse of plain text is noise
      const fl = r.flags.find(f => real(f.chain) || /ctf|flag/i.test(f.flag.slice(0, 8)));
      if (fl) return { how: [...chain, ...fl.chain].join(' → '), text: fl.flag };
      if (best && real(best.chain) && (C.textScore(best.s) > C.textScore(cur) || /^[\[{]/.test(best.s))) return { how: [...chain, ...best.chain].join(' → '), text: best.s };
    }
    return chain.length ? { how: chain.join(' → '), text: cur } : null;
  };

  // ملاحظات على الترويسات المهمة (للتعلّم)
  W.headerNote = (k, v) => {
    const n = k.toLowerCase();
    if (/flag|secret|hint|debug/i.test(k)) return ['good', 'ترويسة غير معتادة — اقرأها جيداً!'];
    if (n === 'server' || n === 'x-powered-by' || n === 'x-aspnet-version' || n === 'x-generator') return ['', 'تكشف البرنامج أو إصداره'];
    if (n === 'authorization') return ['warn', 'بيانات دخول — قد تكون Base64 أو JWT'];
    if (n === 'location') return ['', 'إعادة توجيه — تابع العنوان'];
    if (n === 'set-cookie') return ['warn', 'الخادم يضع كوكي — افحص قيمتها'];
    if (n === 'access-control-allow-origin' && v.trim() === '*') return ['', 'يسمح لأي موقع بالقراءة (CORS)'];
    if (n === 'x-forwarded-for' || n === 'x-real-ip') return ['', 'يحدد عنوان IP للمرسل'];
    if (n === 'referer') return ['', 'الصفحة السابقة'];
    if (n === 'user-agent') return ['', 'هوية المتصفح'];
    return null;
  };

  W.htmlFindings = html => {
    const f = { comments: [], hidden: [], scripts: [], links: [], forms: [], meta: [] };
    if (!/<[a-z!]/i.test(html)) return f;
    let m; const re = (r, fn) => { r.lastIndex = 0; while ((m = r.exec(html)) && f.comments.length + f.hidden.length + f.scripts.length + f.links.length < 600) fn(m); };
    re(/<!--([\s\S]*?)-->/g, m => { const t = m[1].trim(); if (t) f.comments.push(t); });
    const attr = (tag, a) => { const r = new RegExp(a + '\\s*=\\s*("([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i'); const x = tag.match(r); return x ? (x[2] ?? x[3] ?? x[4] ?? '') : null; };
    re(/<input\b[^>]*>/gi, m => { const t = m[0]; if (/type\s*=\s*["']?hidden/i.test(t)) f.hidden.push([attr(t, 'name') || '(بلا اسم)', attr(t, 'value') || '']); });
    re(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi, m => f.scripts.push(m[1]));
    re(/<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)/gi, m => { if (!/^(#|javascript:|mailto:)/i.test(m[1])) f.links.push(m[1]); });
    re(/<form\b[^>]*>/gi, m => f.forms.push((attr(m[0], 'method') || 'GET').toUpperCase() + ' ' + (attr(m[0], 'action') || '(نفس الصفحة)')));
    re(/<meta\b[^>]*>/gi, m => { const nm = attr(m[0], 'name') || attr(m[0], 'property'), c = attr(m[0], 'content'); if (nm && c) f.meta.push([nm, c]); });
    f.links = [...new Set(f.links)]; f.scripts = [...new Set(f.scripts)];
    return f;
  };

  const sq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
  W.toCurl = p => {
    if (p.kind !== 'request') return '';
    const parts = ['curl -i'];
    if (p.method !== 'GET') parts.push('-X ' + p.method);
    parts.push(sq(p.url));
    for (const [k, v] of p.headers) { const n = k.toLowerCase(); if (n === 'host' || n === 'content-length' || n === 'connection' || n === 'accept-encoding') continue; parts.push('-H ' + sq(k + ': ' + v)); }
    if (p.body && p.body.trim()) parts.push('--data-raw ' + sq(p.body.replace(/\n$/, '')));
    return parts.join(' \\\n  ');
  };

  /* المقارن: فرق سطري (LCS) مع إبراز الأحرف المختلفة */
  W.diffLines = (a, b, opts = {}) => {
    const norm = s => { let t = s; if (opts.ignoreWs) t = t.replace(/\s+/g, ' ').trim(); if (opts.ignoreCase) t = t.toLowerCase(); return t; };
    let A = a.split(/\r?\n/), B = b.split(/\r?\n/);
    const LIM = 2500; const trunc = A.length > LIM || B.length > LIM; A = A.slice(0, LIM); B = B.slice(0, LIM);
    const NA = A.map(norm), NB = B.map(norm), n = A.length, m = B.length;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = NA[i] === NB[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const ops = []; let i = 0, j = 0;
    while (i < n && j < m) { if (NA[i] === NB[j]) { ops.push({ t: 'same', a: A[i], b: B[j] }); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ t: 'del', a: A[i] }); i++; } else { ops.push({ t: 'add', b: B[j] }); j++; } }
    while (i < n) ops.push({ t: 'del', a: A[i++] }); while (j < m) ops.push({ t: 'add', b: B[j++] });
    // دمج حذف+إضافة متتاليين في "تغيير"
    const out = [];
    for (let k = 0; k < ops.length; k++) {
      if (ops[k].t === 'del') { let d = k; while (d < ops.length && ops[d].t === 'del') d++; let e = d; while (e < ops.length && ops[e].t === 'add') e++; const dels = ops.slice(k, d), adds = ops.slice(d, e); const pairs = Math.min(dels.length, adds.length); for (let q = 0; q < pairs; q++) out.push({ t: 'chg', a: dels[q].a, b: adds[q].b }); dels.slice(pairs).forEach(x => out.push(x)); adds.slice(pairs).forEach(x => out.push(x)); k = e - 1; }
      else out.push(ops[k]);
    }
    out.truncated = trunc;
    return out;
  };
  W.charDiff = (a, b) => { let s = 0; while (s < a.length && s < b.length && a[s] === b[s]) s++; let e = 0; while (e < a.length - s && e < b.length - s && a[a.length - 1 - e] === b[b.length - 1 - e]) e++; return { pre: a.slice(0, s), aMid: a.slice(s, a.length - e), bMid: b.slice(s, b.length - e), post: a.slice(a.length - e) }; };

  W.SAMPLE = [
    'GET /dashboard?view=profile&ref=aGludDogY2hlY2sgdGhlIGNvb2tpZQ%3D%3D HTTP/1.1',
    'Host: training.flag-hunter.local',
    'User-Agent: Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)',
    'Accept: text/html',
    'Cookie: theme=dark; role=Z3Vlc3Q%3D; session=' + C.E.base64url('{"alg":"none","typ":"JWT"}') + '.' + C.E.base64url('{"user":"student","admin":false,"note":"' + C.E.hex('flag{cookie_monster}') + '"}') + '.',
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  return W;
});
