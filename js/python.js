/* صائد الأعلام — محرك بايثون حقيقي في المتصفح (Pyodide) لعكس سكربتات التشفير.
   يعمل داخل Web Worker معزول. الملف المرفوع متاح في بايثون كـ data (bytes) و data_hex (str).
   يحمّل Pyodide محلياً من ./pyodide/ (يعمل بدون إنترنت بعد أول تحميل)، ومع فشل ذلك يجرّب CDN.
   Browser: window.CTFP */
(function (root) {
  'use strict';
  const P = {};
  const LOCAL = (typeof location !== 'undefined') ? new URL('pyodide/', location.href).href : '';
  const CDN = 'https://cdn.jsdelivr.net/pyodide/v0.26.4/full/';
  let worker = null, ready = null, busy = false;

  function makeWorker() {
    const body = `
let py = null;
async function ensure(base) {
  if (py) return;
  const mod = await import(base + 'pyodide.mjs');
  py = await mod.loadPyodide({ indexURL: base });
}
self.onmessage = async (e) => {
  const m = e.data;
  if (m.type === 'init') {
    try { await ensure(m.base); self.postMessage({ type: 'ready' }); }
    catch (err) { self.postMessage({ type: 'initerror', error: String(err && err.message || err) }); }
    return;
  }
  if (m.type === 'run') {
    let out = '', err = '';
    try {
      py.setStdout({ batched: s => { out += s + '\\n'; } });
      py.setStderr({ batched: s => { err += s + '\\n'; } });
      py.globals.set('_fb', py.toPy(m.bytes || new Uint8Array()));
      await py.runPythonAsync('data = bytes(_fb)\\ndata_hex = data.hex()\\ntry:\\n import builtins as _b\\nexcept: pass');
      let res = await py.runPythonAsync(m.code);
      if (res && typeof res.toString === 'function' && typeof res.destroy === 'function') { const s = res.toString(); res.destroy(); res = s; }
      self.postMessage({ type: 'done', stdout: out, stderr: err, result: (res === undefined || res === null) ? null : String(res) });
    } catch (ex) {
      const msg = String(ex && ex.message || ex);
      self.postMessage({ type: 'done', stdout: out, stderr: err + msg });
    }
  }
};`;
    return new Worker(URL.createObjectURL(new Blob([body], { type: 'text/javascript' })), { type: 'module' });
  }

  // يضمن تحميل المحرك؛ يجرّب المحلي ثم CDN. onStage('local'|'cdn')
  P.init = (onStage) => {
    if (ready) return ready;
    ready = new Promise((resolve, reject) => {
      worker = makeWorker();
      let stage = 'local';
      worker.onmessage = e => {
        if (e.data.type === 'ready') { resolve(true); }
        else if (e.data.type === 'initerror') {
          if (stage === 'local' && CDN) { stage = 'cdn'; onStage && onStage('cdn'); worker.postMessage({ type: 'init', base: CDN }); }
          else { ready = null; try { worker.terminate(); } catch (e2) { } worker = null; reject(new Error(e.data.error || 'init failed')); }
        }
      };
      worker.onerror = ev => { ev.preventDefault && ev.preventDefault(); if (stage === 'local' && CDN) { stage = 'cdn'; onStage && onStage('cdn'); worker.postMessage({ type: 'init', base: CDN }); } else { ready = null; reject(new Error('worker error')); } };
      onStage && onStage('local');
      worker.postMessage({ type: 'init', base: LOCAL });
    });
    return ready;
  };

  // يشغّل الكود. يعيد {stdout, stderr, result} أو {error}. مهلة تنهي العامل (ويُعاد التحميل لاحقاً).
  P.run = (code, bytes, timeout = 20000) => new Promise(resolve => {
    if (busy) { resolve({ error: 'التشغيل جارٍ بالفعل' }); return; }
    if (!worker || !ready) { resolve({ error: 'المحرك غير محمّل' }); return; }
    busy = true;
    const prev = worker.onmessage;
    const timer = setTimeout(() => {
      try { worker.terminate(); } catch (e) { } worker = null; ready = null; busy = false;
      resolve({ error: 'انتهت المهلة (' + timeout / 1000 + ' ثانية) — غالباً حلقة لا نهائية. أُعيد ضبط المحرك.' });
    }, timeout);
    worker.onmessage = e => {
      if (e.data.type !== 'done') return;
      clearTimeout(timer); busy = false; worker.onmessage = prev; resolve(e.data);
    };
    worker.postMessage({ type: 'run', code, bytes });
  });
  P.loaded = () => !!(worker && ready);
  P.reset = () => { if (worker) { try { worker.terminate(); } catch (e) { } } worker = null; ready = null; busy = false; };

  P.TEMPLATE = `# المتغيّرات الجاهزة:
#   data     = بايتات الملف المرفوع (نوع bytes)
#   data_hex = نفس البايتات كنص hex
# اكتب فكّ التشفير هنا واطبع النتيجة بـ print()

print("الطول:", len(data), "بايت")
print("أول البايتات:", data[:32])
# مثال: لو كان التشفير XOR بالمفتاح 0x42
# print(bytes(b ^ 0x42 for b in data))
`;

  P.SNIPPETS = {
    'XOR بمفتاح بايت واحد': `key = 0x42  # غيّر المفتاح\nout = bytes(b ^ key for b in data)\nprint(out)`,
    'XOR بمفتاح متكرر': `key = b"secret"  # غيّر المفتاح\nout = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))\nprint(out)`,
    'تخمين XOR بايت واحد (0-255)': `for key in range(256):\n    out = bytes(b ^ key for b in data)\n    if b"flag{" in out or b"CTF{" in out:\n        print(key, out)`,
    'عكس الجمع/الطرح mod 256': `n = 5  # كان التشفير: byte + n ؛ العكس: - n\nout = bytes((b - n) % 256 for b in data)\nprint(out)`,
    'عكس تدوير البتات': `r = 3  # عدد البتات التي دُوّرت لليسار أثناء التشفير\nout = bytes(((b >> r) | (b << (8 - r))) & 0xFF for b in data)\nprint(out)`,
    'عكس ترتيب البايتات': `print(data[::-1])`,
    'فك base64 / hex': `import base64\nprint(base64.b64decode(data))\n# أو إن كان hex:\n# print(bytes.fromhex(data.decode()))`,
    'رقم ← بايتات (نمط RSA)': `n = int(data_hex, 16)  # أو ألصق c هنا\nh = format(n, "x")\nif len(h) % 2: h = "0" + h\nprint(bytes.fromhex(h))`,
    'AES (يحتاج إنترنت أول مرة)': `import micropip\nawait micropip.install("pycryptodome")\nfrom Crypto.Cipher import AES\nkey = b"0123456789abcdef"  # 16 بايت\niv  = b"\\x00" * 16\nc = AES.new(key, AES.MODE_CBC, iv)\nprint(c.decrypt(data))`,
    'جرّب كل إزاحات قيصر على البايتات': `for s in range(256):\n    out = bytes((b + s) % 256 for b in data)\n    if b"flag{" in out:\n        print(s, out)`,
  };
  root.CTFP = P;
})(typeof self !== 'undefined' ? self : this);
