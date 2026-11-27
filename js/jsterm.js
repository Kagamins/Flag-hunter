/* صائد الأعلام — جافاسكربت ← أوامر الطرفية.
   فكرتان:
   1) التقاط الطلبات: نشغّل كود الموقع داخل عامل معزول حيث fetch/XHR/axios/$.ajax/sendBeacon
      مستبدلة بمسجّلات — لا يخرج أي طلب فعلي للشبكة — ثم نحوّل كل طلب إلى أمر curl/wget/httpie.
   2) تغليف الكود كأمر node لتشغيله في الطرفية.
   كل المعالجة محلية داخل متصفحك. Browser: window.CTFT   Node: module.exports */
(function (root, factory) {
  const T = factory();
  if (typeof module === 'object' && module.exports) module.exports = T; else root.CTFT = T;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const T = {};

  /* ---------- أدوات نصية ---------- */
  // تغليف بعلامات اقتباس مفردة آمنة لصدفة POSIX
  T.shSingle = v => "'" + String(v == null ? '' : v).replace(/'/g, "'\\''") + "'";
  T.resolveUrl = (u, base) => {
    u = String(u == null ? '' : u);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u) || u.startsWith('//')) return u.startsWith('//') ? 'https:' + u : u;
    if (base) { try { return new URL(u, base).href; } catch (e) { } }
    return u;
  };

  /* ---------- النواة: تشغيل الكود والتقاط الطلبات (لا تعتمد على خارجها) ---------- */
  function captureCore(code, base) {
    base = base || '';
    const requests = [], logs = [];
    let error = null;
    const norm = h => {
      const out = {}; if (!h) return out;
      try {
        if (typeof h.forEach === 'function' && !Array.isArray(h)) { h.forEach((v, k) => { out[k] = String(v); }); return out; }
        if (Array.isArray(h)) { for (const p of h) if (p && p.length >= 2) out[p[0]] = String(p[1]); return out; }
        if (typeof h === 'object') { for (const k in h) if (Object.prototype.hasOwnProperty.call(h, k)) out[k] = String(h[k]); }
      } catch (e) { }
      return out;
    };
    const body2s = b => {
      if (b == null) return null;
      if (typeof b === 'string') return b;
      try {
        if (typeof URLSearchParams !== 'undefined' && b instanceof URLSearchParams) return b.toString();
        if (typeof ArrayBuffer !== 'undefined' && (b instanceof ArrayBuffer || ArrayBuffer.isView(b))) return '[بيانات ثنائية]';
        if (typeof b === 'object') return JSON.stringify(b);
      } catch (e) { }
      return String(b);
    };
    const rec = (m, u, h, b) => requests.push({ method: String(m || 'GET').toUpperCase(), url: String(u == null ? '' : u), headers: norm(h), body: b == null ? null : body2s(b) });
    const resp = () => ({ ok: true, status: 200, statusText: 'OK', url: '', redirected: false, type: 'basic', bodyUsed: false, headers: { get: () => null, has: () => false, forEach: () => { } }, clone() { return resp(); }, text: () => Promise.resolve(''), json: () => Promise.resolve({}), blob: () => Promise.resolve(null), arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)), formData: () => Promise.resolve(null) });
    const fakeFetch = (input, init) => {
      init = init || {}; let url, method = 'GET', headers = init.headers, body = init.body;
      if (input && typeof input === 'object' && typeof input !== 'string' && input.url !== undefined) { url = input.url; method = input.method || method; if (!headers) headers = input.headers; } else url = input;
      if (init.method) method = init.method;
      rec(method, url, headers, body); return Promise.resolve(resp());
    };
    function FakeXHR() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = ''; this._l = {}; }
    FakeXHR.prototype.open = function (m, u) { this._m = m; this._u = u; this.readyState = 1; };
    FakeXHR.prototype.setRequestHeader = function (k, v) { this._h[k] = v; };
    FakeXHR.prototype.send = function (b) {
      rec(this._m, this._u, this._h, b); this.readyState = 4; this.status = 200;
      try { if (typeof this.onreadystatechange === 'function') this.onreadystatechange(); } catch (e) { }
      try { if (typeof this.onload === 'function') this.onload(); } catch (e) { }
      for (const fn of (this._l.load || [])) { try { fn(); } catch (e) { } }
    };
    FakeXHR.prototype.abort = function () { }; FakeXHR.prototype.getAllResponseHeaders = function () { return ''; }; FakeXHR.prototype.getResponseHeader = function () { return null; };
    FakeXHR.prototype.addEventListener = function (e, f) { (this._l[e] = this._l[e] || []).push(f); }; FakeXHR.prototype.removeEventListener = function () { };
    function axios(cfg) { cfg = (typeof cfg === 'string') ? { url: cfg } : (cfg || {}); rec(cfg.method || 'GET', cfg.url || cfg.baseURL || '', cfg.headers, cfg.data); return Promise.resolve({ data: {}, status: 200, statusText: 'OK', headers: {}, config: cfg }); }
    ['get', 'delete', 'head', 'options'].forEach(m => { axios[m] = (u, c) => axios(Object.assign({ url: u, method: m }, c || {})); });
    ['post', 'put', 'patch'].forEach(m => { axios[m] = (u, d, c) => axios(Object.assign({ url: u, method: m, data: d }, c || {})); });
    axios.create = () => axios; axios.request = axios; axios.all = Promise.all.bind(Promise);
    const jqAjax = (a, b) => { const cfg = (typeof a === 'string') ? Object.assign({ url: a }, b || {}) : (a || {}); rec(cfg.type || cfg.method || 'GET', cfg.url, cfg.headers, cfg.data); const p = Promise.resolve({}); p.done = f => { try { f && f({}); } catch (e) { } return p; }; p.fail = () => p; p.always = f => { try { f && f({}); } catch (e) { } return p; }; return p; };
    const jq = function () { return jq; };
    jq.ajax = jqAjax; jq.get = (u, d) => jqAjax({ url: u, method: 'GET', data: typeof d === 'function' ? undefined : d }); jq.post = (u, d) => jqAjax({ url: u, method: 'POST', data: typeof d === 'function' ? undefined : d }); jq.getJSON = (u, d) => jqAjax({ url: u, method: 'GET', data: typeof d === 'function' ? undefined : d });
    const con = { log: (...a) => logs.push(a.map(x => { try { return typeof x === 'object' ? JSON.stringify(x) : String(x); } catch (e) { return String(x); } }).join(' ')) };
    con.info = con.warn = con.error = con.debug = con.log;
    const nav = { userAgent: 'Mozilla/5.0 (CTF)', sendBeacon: (u, d) => { rec('POST', u, { 'Content-Type': 'text/plain;charset=UTF-8' }, d); return true; }, language: 'en', platform: 'Linux' };
    let loc; try { if (base) { const x = new URL(base); loc = { href: x.href, origin: x.origin, protocol: x.protocol, host: x.host, hostname: x.hostname, port: x.port, pathname: x.pathname, search: '', hash: '', toString: () => x.href }; } } catch (e) { }
    if (!loc) loc = { href: base || 'http://localhost/', origin: '', protocol: 'http:', host: '', hostname: '', port: '', pathname: '/', search: '', hash: '', toString: () => (base || 'http://localhost/') };
    const noop = () => { };
    const mkEl = () => ({ style: {}, dataset: {}, setAttribute: noop, getAttribute: () => null, appendChild: noop, removeChild: noop, append: noop, remove: noop, addEventListener: noop, removeEventListener: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false }, querySelector: () => null, querySelectorAll: () => [], click: noop, submit: function () { if (this.action) rec(this.method || 'GET', this.action, {}, null); }, value: '', textContent: '', innerHTML: '' });
    const doc = { cookie: '', createElement: mkEl, createElementNS: mkEl, getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], addEventListener: noop, removeEventListener: noop, body: mkEl(), head: mkEl(), documentElement: mkEl(), location: loc, write: noop, writeln: noop };
    const win = {};
    Object.assign(win, { fetch: fakeFetch, XMLHttpRequest: FakeXHR, axios, location: loc, navigator: nav, document: doc, console: con, atob: (typeof atob !== 'undefined' ? atob : s => Buffer.from(s, 'base64').toString('binary')), btoa: (typeof btoa !== 'undefined' ? btoa : s => Buffer.from(s, 'binary').toString('base64')), setTimeout: () => 0, setInterval: () => 0, clearTimeout: noop, clearInterval: noop, requestAnimationFrame: () => 0, alert: noop, confirm: () => false, prompt: () => null, localStorage: { getItem: () => null, setItem: noop, removeItem: noop, clear: noop }, URL: (typeof URL !== 'undefined' ? URL : null), URLSearchParams: (typeof URLSearchParams !== 'undefined' ? URLSearchParams : null) });
    win.sessionStorage = win.localStorage; win.window = win; win.self = win; win.globalThis = win; win.top = win; win.parent = win; win.frames = win;
    try {
      const run = new Function('fetch', 'XMLHttpRequest', 'axios', 'window', 'self', 'globalThis', 'document', 'navigator', 'location', 'console', '$', 'jQuery', 'localStorage', 'sessionStorage', 'setTimeout', 'setInterval', 'atob', 'btoa', 'URLSearchParams', code);
      run(fakeFetch, FakeXHR, axios, win, win, win, doc, nav, loc, con, jq, jq, win.localStorage, win.sessionStorage, win.setTimeout, win.setInterval, win.atob, win.btoa, win.URLSearchParams);
    } catch (e) { error = String((e && e.message) || e); }
    return { requests, logs, error };
  }
  T._captureCore = captureCore;

  /* ---------- تشغيل داخل عامل معزول مع مهلة ---------- */
  let workerURL = null;
  function getWorkerURL() {
    if (workerURL) return workerURL;
    const src = 'const captureCore = ' + captureCore.toString() + ';\nself.onmessage = e => { try { self.postMessage(captureCore(e.data.code, e.data.base)); } catch (err) { self.postMessage({ requests: [], logs: [], error: String(err && err.message || err) }); } };';
    workerURL = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
    return workerURL;
  }
  // يعيد Promise بـ {requests, logs, error, via}
  T.capture = (code, base, timeout = 4000) => new Promise(resolve => {
    const c = String(code || '');
    if (!c.trim()) { resolve({ requests: [], logs: [], error: 'ألصق كود جافاسكربت أولاً.' }); return; }
    let w;
    try { w = new Worker(getWorkerURL()); } catch (e) { const r = captureCore(c, base); r.via = 'page'; resolve(r); return; }
    const timer = setTimeout(() => { w.terminate(); resolve({ requests: [], logs: [], error: 'انتهت المهلة (' + timeout / 1000 + ' ثوانٍ) — قد يحوي الكود حلقة لا نهائية.', via: 'worker' }); }, timeout);
    w.onmessage = e => { clearTimeout(timer); w.terminate(); resolve(Object.assign(e.data, { via: 'worker' })); };
    w.onerror = e => { clearTimeout(timer); w.terminate(); e.preventDefault && e.preventDefault(); const r = captureCore(c, base); r.via = 'page'; resolve(r); };
    w.postMessage({ code: c, base: base || '' });
  });

  /* ---------- تحويل طلب ملتقَط إلى أوامر ---------- */
  T.reqToCurl = (req, base) => {
    const q = T.shSingle, url = T.resolveUrl(req.url, base);
    let s = 'curl ' + q(url);
    if (req.method && req.method !== 'GET') s += ' \\\n  -X ' + req.method;
    for (const k in req.headers) s += ' \\\n  -H ' + q(k + ': ' + req.headers[k]);
    if (req.body != null && req.body !== '') s += ' \\\n  --data-raw ' + q(req.body);
    return s;
  };
  T.reqToWget = (req, base) => {
    const q = T.shSingle, url = T.resolveUrl(req.url, base);
    let s = 'wget -qO -';
    if (req.method && req.method !== 'GET') s += ' \\\n  --method=' + req.method;
    for (const k in req.headers) s += ' \\\n  --header=' + q(k + ': ' + req.headers[k]);
    if (req.body != null && req.body !== '') s += ' \\\n  --body-data=' + q(req.body);
    return s + ' \\\n  ' + q(url);
  };
  T.reqToHttpie = (req, base) => {
    const q = T.shSingle, url = T.resolveUrl(req.url, base);
    let s = 'http ' + (req.method || 'GET') + ' ' + q(url);
    for (const k in req.headers) s += ' ' + q(k + ':' + req.headers[k]);
    if (req.body != null && req.body !== '') s += ' --raw=' + q(req.body);
    return s;
  };
  T.FORMATS = { curl: T.reqToCurl, wget: T.reqToWget, httpie: T.reqToHttpie };

  /* ---------- تغليف الكود كأمر node ---------- */
  T.toNodeCmd = (src, mode) => {
    src = String(src || '').replace(/\r\n/g, '\n');
    if (mode === 'heredoc') {
      let d = 'JSEOF'; while (src.split('\n').indexOf(d) !== -1) d += 'X';
      return "node <<'" + d + "'\n" + src + '\n' + d;
    }
    return 'node -e ' + T.shSingle(src);
  };

  T.SAMPLE = `// مثال: كود شبكة منسوخ من موقع — اضغط «استخرج الأوامر»\nfetch("/api/login", {\n  method: "POST",\n  headers: { "Content-Type": "application/json", "X-CSRF": "abc123" },\n  body: JSON.stringify({ user: "admin", pass: "letmein" })\n});\n\nconst x = new XMLHttpRequest();\nx.open("GET", "/api/flag?id=42");\nx.setRequestHeader("Authorization", "Bearer TOKEN");\nx.send();`;

  return T;
});
