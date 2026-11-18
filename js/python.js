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
  P.AUTO = "# === \u0627\u0639\u0643\u0633 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b ===\n_CAND = [\"encrypt\",\"enc\",\"encode\",\"cipher\",\"scramble\",\"obfuscate\",\"encrypt_flag\",\"transform\",\"crypt\",\"do_encrypt\",\"xor_encrypt\",\"encipher\"]\n_fn=None; _fnname=None\nfor _n in _CAND:\n    _f=globals().get(_n)\n    if callable(_f): _fn=_f; _fnname=_n; break\nprint(\"=== \u0627\u0639\u0643\u0633 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b (Auto-Reverse) ===\")\nif _fn is None:\n    print(\"\u0644\u0645 \u0623\u062c\u062f \u062f\u0627\u0644\u0629 \u062a\u0634\u0641\u064a\u0631. \u0639\u0631\u0651\u0641 \u062f\u0627\u0644\u0629 \u0645\u062b\u0644:  def encrypt(data: bytes) -> bytes  (\u0623\u0644\u0635\u0642 \u0627\u0644\u0633\u0643\u0631\u0628\u062a \u0627\u0644\u0645\u064f\u0639\u0637\u0649) \u062b\u0645 \u0627\u0636\u063a\u0637 \u0627\u0639\u0643\u0633 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b.\")\nelse:\n    print(\"\u0627\u0644\u062f\u0627\u0644\u0629 \u0627\u0644\u0645\u0633\u062a\u062e\u062f\u0645\u0629: \" + _fnname + \"()\")\n    def _call(bs):\n        bs=bytes(bs)\n        try: r=_fn(bs)\n        except TypeError: r=_fn(bs.decode(\"latin-1\"))\n        if isinstance(r,str): r=r.encode(\"latin-1\",\"ignore\")\n        return bytes(r)\n    try: C=bytes(data)\n    except Exception: C=b\"\"\n    L=len(C)\n    if L==0:\n        print(\"\u0627\u0631\u0641\u0639 \u0627\u0644\u0645\u0644\u0641 \u0627\u0644\u0645\u0634\u0641\u0651\u0631 \u0623\u0648\u0644\u0627\u064b \u2014 \u064a\u0635\u0628\u062d \u0645\u062a\u0627\u062d\u0627\u064b \u0641\u064a \u0628\u0627\u064a\u062b\u0648\u0646 \u0643\u0640 data.\")\n    else:\n        _ok=True\n        try: _call(bytes(max(1,L)))\n        except Exception as _e:\n            _ok=False\n            print(\"\u062a\u0639\u0630\u0651\u0631 \u0627\u0633\u062a\u062f\u0639\u0627\u0621 \u0627\u0644\u062f\u0627\u0644\u0629 \u0628\u0628\u0627\u064a\u062a\u0627\u062a \u0641\u0642\u0637 \u2014 \u063a\u0627\u0644\u0628\u0627\u064b \u062a\u062d\u062a\u0627\u062c \u0645\u0641\u062a\u0627\u062d\u0627\u064b \u0623\u0648 \u0648\u0633\u0627\u0626\u0637 \u0625\u0636\u0627\u0641\u064a\u0629 (\" + str(_e)[:90] + \").\")\n            print(\"\u0625\u0646 \u0643\u0627\u0646 \u0627\u0644\u0645\u0641\u062a\u0627\u062d \u0645\u0639\u0631\u0648\u0641\u0627\u064b\u060c \u0627\u0643\u062a\u0628 \u0641\u0643\u0651 \u0627\u0644\u062a\u0634\u0641\u064a\u0631 \u064a\u062f\u0648\u064a\u0627\u064b \u0645\u0633\u062a\u062e\u062f\u0645\u0627\u064b \u0627\u0644\u0645\u0641\u062a\u0627\u062d.\")\n        if _ok:\n            Lin=None\n            for _cand in [L]+list(range(1,L+9)):\n                try:\n                    if len(_call(bytes(_cand)))==L: Lin=_cand; break\n                except Exception: pass\n            if Lin is None:\n                print(\"\u0644\u0627 \u0623\u0633\u062a\u0637\u064a\u0639 \u0645\u0637\u0627\u0628\u0642\u0629 \u0637\u0648\u0644 \u0627\u0644\u0645\u062e\u0631\u062c\u0627\u062a \u0645\u0639 \u0627\u0644\u0645\u0644\u0641 \u2014 \u0642\u062f \u064a\u0643\u0648\u0646 \u062a\u0631\u0645\u064a\u0632\u0627\u064b \u0623\u0648 \u062d\u0634\u0648\u0627\u064b \u0623\u0648 \u0628\u0645\u0641\u062a\u0627\u062d. \u0627\u0641\u0639\u0644\u0647\u0627 \u064a\u062f\u0648\u064a\u0627\u064b.\")\n            else:\n                base=_call(bytes(Lin)); perm=[None]*Lin; _bad=False\n                for i in range(Lin):\n                    p=bytearray(Lin); p[i]=1\n                    c=_call(bytes(p)); diff=[j for j in range(L) if c[j]!=base[j]]\n                    if not diff:\n                        p[i]=0xFF; c=_call(bytes(p)); diff=[j for j in range(L) if c[j]!=base[j]]\n                    if len(diff)==1: perm[i]=diff[0]\n                    elif len(diff)==0: perm[i]=None\n                    else: _bad=True; break\n                if _bad:\n                    print(\"\u0627\u0646\u062a\u0634\u0627\u0631 (diffusion): \u062a\u063a\u064a\u064a\u0631 \u0628\u0627\u064a\u062a \u0648\u0627\u062d\u062f \u0641\u064a \u0627\u0644\u0645\u062f\u062e\u0644 \u064a\u063a\u064a\u0651\u0631 \u0639\u062f\u0629 \u0628\u0627\u064a\u062a\u0627\u062a \u0641\u064a \u0627\u0644\u0646\u0627\u062a\u062c.\")\n                    print(\"\u0647\u0630\u0627 \u0646\u0645\u0637 \u062a\u0634\u0641\u064a\u0631 \u0643\u062a\u0644\u064a (\u0645\u062b\u0644 AES/CBC) \u0623\u0648 \u0628\u0645\u0641\u062a\u0627\u062d \u0623\u0648 \u062f\u0627\u0644\u0629 \u0647\u0627\u0634 \u2014 \u0644\u0627 \u064a\u0645\u0643\u0646 \u0639\u0643\u0633\u0647 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b. \u062d\u0644\u0651\u0644\u0647 \u064a\u062f\u0648\u064a\u0627\u064b.\")\n                else:\n                    _used=[j for j in perm if j is not None]\n                    if len(set(_used))!=len(_used):\n                        print(\"\u0645\u0648\u0636\u0639\u0627\u0646 \u0641\u064a \u0627\u0644\u0645\u062f\u062e\u0644 \u064a\u0624\u062b\u0631\u0627\u0646 \u0639\u0644\u0649 \u0646\u0641\u0633 \u0645\u0648\u0636\u0639 \u0627\u0644\u0645\u062e\u0631\u062c \u2014 \u062e\u0627\u0631\u062c \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0642\u0627\u0628\u0644 \u0644\u0644\u0639\u0643\u0633 \u062a\u0644\u0642\u0627\u0626\u064a\u0627\u064b.\")\n                    else:\n                        def _tab(i):\n                            t=[0]*256\n                            for b in range(256):\n                                p=bytearray(Lin); p[i]=b; t[b]=_call(bytes(p))[perm[i]]\n                            return t\n                        _ref=next((i for i in range(Lin) if perm[i] is not None), None)\n                        if _ref is None:\n                            print(\"\u0627\u0644\u0645\u062e\u0631\u062c\u0627\u062a \u0644\u0627 \u062a\u0639\u062a\u0645\u062f \u0639\u0644\u0649 \u0627\u0644\u0645\u062f\u062e\u0644\u0627\u062a \u2014 \u0644\u0627 \u0634\u064a\u0621 \u0644\u0639\u0643\u0633\u0647.\")\n                        else:\n                            rec=bytearray(Lin); _lossy=False; _toobig=False\n                            f0=_tab(_ref); _isg=len(set(f0))==256\n                            if _isg:\n                                for i in [x for x in range(Lin) if perm[x] is not None][:6]:\n                                    for v in (1,0x55,0xAA,0xFF):\n                                        p=bytearray(Lin); p[i]=v\n                                        if _call(bytes(p))[perm[i]]!=f0[v]: _isg=False; break\n                                    if not _isg: break\n                            if _isg:\n                                inv={f0[b]:b for b in range(256)}\n                                for i in range(Lin): rec[i]= 0 if perm[i] is None else inv[C[perm[i]]]\n                            else:\n                                if Lin*256>4000000:\n                                    _toobig=True\n                                else:\n                                    for i in range(Lin):\n                                        if perm[i] is None: rec[i]=0; continue\n                                        t=_tab(i)\n                                        if len(set(t))!=256: _lossy=True; break\n                                        rec[i]={t[b]:b for b in range(256)}[C[perm[i]]]\n                            if _toobig:\n                                print(\"\u0627\u0644\u0645\u0644\u0641 \u0643\u0628\u064a\u0631 \u0639\u0644\u0649 \u0627\u0644\u0639\u0643\u0633 \u0644\u0643\u0644 \u0645\u0648\u0636\u0639. \u062c\u0631\u0651\u0628 \u0645\u0642\u0637\u0639\u0627\u064b \u0623\u0642\u0635\u0631 \u0623\u0648 \u0627\u0641\u0639\u0644\u0647\u0627 \u064a\u062f\u0648\u064a\u0627\u064b.\")\n                            elif _lossy:\n                                print(\"\u062f\u0627\u0644\u0629 \u0627\u0644\u062a\u062d\u0648\u064a\u0644 \u062a\u0641\u0642\u062f \u0645\u0639\u0644\u0648\u0645\u0627\u062a (\u063a\u064a\u0631 \u0639\u0643\u0648\u0633\u0629) \u2014 \u0644\u0627 \u064a\u0645\u0643\u0646 \u0627\u0633\u062a\u0631\u062c\u0627\u0639 \u0627\u0644\u0623\u0635\u0644 \u0628\u0627\u0644\u0643\u0627\u0645\u0644.\")\n                            else:\n                                R=bytes(rec)\n                                try: _m=_call(R)==C\n                                except Exception: _m=False\n                                print(\"----------------\")\n                                try: print(\"\u0627\u0644\u0623\u0635\u0644 (\u0646\u0635): \" + R.decode())\n                                except Exception: print(\"\u0627\u0644\u0623\u0635\u0644 (hex): \" + R.hex())\n                                print(\"\u0627\u0644\u0623\u0635\u0644 (bytes): \" + repr(R))\n                                print(\"\u0627\u0644\u0646\u0645\u0637: \" + (\"\u0646\u0641\u0633 \u0627\u0644\u0639\u0645\u0644\u064a\u0629 \u0644\u0643\u0644 \u0628\u0627\u064a\u062a\" if _isg else \"\u0639\u0645\u0644\u064a\u0629 \u0644\u0643\u0644 \u0645\u0648\u0636\u0639\"))\n                                print(\"\u062a\u062d\u0642\u0651\u0642 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u062a\u0634\u0641\u064a\u0631: \" + (\"\u2705 \u0645\u0637\u0627\u0628\u0642 \u2014 \u0646\u062c\u062d \u0627\u0644\u0639\u0643\u0633\" if _m else \"\u26a0\ufe0f \u063a\u064a\u0631 \u0645\u0637\u0627\u0628\u0642 \u2014 \u0642\u062f \u064a\u0643\u0648\u0646 \u062c\u0632\u0626\u064a\u0627\u064b \u0623\u0648 \u062e\u0627\u0631\u062c \u0627\u0644\u0646\u0637\u0627\u0642\"))\n";
  root.CTFP = P;
})(typeof self !== 'undefined' ? self : this);
