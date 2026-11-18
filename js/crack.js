/* صائد الأعلام — كاسر الهاش (Hash cracker).
   تنبيه مهم: الهاش دالة باتجاه واحد ولا يمكن "فكّه". نحن فقط نجرّب مدخلات حتى نجد
   ما يعطي نفس البصمة — ينجح فقط إذا كان الأصل قصيراً أو كلمة شائعة.
   MD5 و SHA-1 و SHA-256 منفّذة بشكل متزامن للسرعة، وتعمل داخل Web Worker.
   Browser: window.CTFK   Node: module.exports */
(function (root, factory) {
  const K = factory();
  if (typeof module === 'object' && module.exports) module.exports = K; else root.CTFK = K;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const K = {};

  /* ---------- بصمات متزامنة: Uint8Array -> hex ---------- */
  function hashImpls() {
    const hx = x => (x >>> 0).toString(16).padStart(8, '0');
    function pad(bytes) {
      const ml = bytes.length, withPad = (((ml + 8) >> 6) + 1) << 6, b = new Uint8Array(withPad);
      b.set(bytes); b[ml] = 0x80;
      const bits = ml * 8, dv = new DataView(b.buffer);
      dv.setUint32(withPad - 8, Math.floor(bits / 0x100000000)); dv.setUint32(withPad - 4, bits >>> 0);
      return b;
    }
    // MD5
    const MK = new Int32Array(64); for (let i = 0; i < 64; i++) MK[i] = (Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
    const MS = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    function md5(bytes) {
      const len = bytes.length, nb = ((len + 8) >> 6) + 1, w = new Int32Array(nb * 16);
      for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
      w[len >> 2] |= 0x80 << ((len % 4) * 8); w[nb * 16 - 2] = len * 8;
      let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
      for (let blk = 0; blk < nb; blk++) {
        let A = a0, B = b0, Cc = c0, Dd = d0;
        for (let i = 0; i < 64; i++) {
          let f, g;
          if (i < 16) { f = (B & Cc) | (~B & Dd); g = i; } else if (i < 32) { f = (Dd & B) | (~Dd & Cc); g = (5 * i + 1) & 15; }
          else if (i < 48) { f = B ^ Cc ^ Dd; g = (3 * i + 5) & 15; } else { f = Cc ^ (B | ~Dd); g = (7 * i) & 15; }
          f = (f + A + MK[i] + w[blk * 16 + g]) | 0; A = Dd; Dd = Cc; Cc = B;
          B = (B + ((f << MS[i]) | (f >>> (32 - MS[i])))) | 0;
        }
        a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + Cc) | 0; d0 = (d0 + Dd) | 0;
      }
      const le = x => hx(((x & 255) << 24) | ((x >>> 8 & 255) << 16) | ((x >>> 16 & 255) << 8) | (x >>> 24 & 255));
      return le(a0) + le(b0) + le(c0) + le(d0);
    }
    // SHA-1
    function sha1(bytes) {
      const b = pad(bytes), dv = new DataView(b.buffer), w = new Int32Array(80);
      let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
      for (let off = 0; off < b.length; off += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
        for (let i = 16; i < 80; i++) { const v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = (v << 1) | (v >>> 31); }
        let a = h0, bb = h1, c = h2, d = h3, e = h4;
        for (let i = 0; i < 80; i++) {
          let f, k;
          if (i < 20) { f = (bb & c) | (~bb & d); k = 0x5A827999; }
          else if (i < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
          else if (i < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
          else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
          const t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
          e = d; d = c; c = (bb << 30) | (bb >>> 2); bb = a; a = t;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
      }
      return hx(h0) + hx(h1) + hx(h2) + hx(h3) + hx(h4);
    }
    // SHA-256
    const SK = new Int32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
    function sha256(bytes) {
      const b = pad(bytes), dv = new DataView(b.buffer), w = new Int32Array(64);
      let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
      for (let off = 0; off < b.length; off += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
        for (let i = 16; i < 64; i++) {
          const x = w[i - 15], y = w[i - 2];
          const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
          const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        let a = h0, bb = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
          const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
          const ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + SK[i] + w[i]) | 0;
          const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
          const maj = (a & bb) ^ (a & c) ^ (bb & c), t2 = (S0 + maj) | 0;
          h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
      }
      return hx(h0) + hx(h1) + hx(h2) + hx(h3) + hx(h4) + hx(h5) + hx(h6) + hx(h7);
    }
    return { MD5: md5, 'SHA-1': sha1, 'SHA-256': sha256 };
  }
  const IMPL = hashImpls();
  K.hash = (algo, bytes) => IMPL[algo](bytes);
  K.ALGOS = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' };
  K.algoFor = h => K.ALGOS[(h || '').trim().length];
  K.CHARSETS = {
    digits: '0123456789',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'lower+digits': 'abcdefghijklmnopqrstuvwxyz0123456789',
    alpha: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    hex: '0123456789abcdef',
    printable: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+",
  };
  K.bruteCount = (n, min, max) => { let t = 0; for (let L = min; L <= max; L++) t += Math.pow(n, L); return t; };

  // قائمة كلمات شائعة مدمجة (مختصرة) — كلمات مرور شائعة + كلمات متكررة في CTF
  K.COMMON = ('123456 password 123456789 12345678 12345 qwerty abc123 111111 1234567 123123 admin letmein welcome monkey 1234 dragon 1234567890 football iloveyou 123321 root pass test guest info administrator user login changeme secret sunshine princess qwerty123 superman batman trustno1 hello whatever shadow master michael jennifer hunter 000000 666666 7777777 121212 654321 passw0rd password1 qwertyuiop baseball soccer hockey killer george asshole andrew charlie michelle love jordan jessica pepper daniel access 696969 maggie 555555 flower hannah thomas tigger robert ginger buster soccer1 batman1 ferrari cookie summer ashley bailey passion nicole chelsea biteme matthew 112233 123654 1q2w3e 1qaz2wsx qazwsx zaq12wsx google chrome firefox linux ubuntu python javascript hacker cyber security flag ctf capture the_flag hidden secret_key backdoor exploit payload shell reverse pwned gg easy medium hard noob leet 1337 h4ck3r p4ssw0rd adminadmin toor kali root123 test123 demo sample example default temp qwerty1 asdf asdfgh zxcvbn vim nano bash').split(' ');

  /* ---------- Worker ---------- */
  function workerBody() {
    const IMPL = (HASHIMPLS)();
    const CS = CHARSETS_JSON;
    function* mutate(w) {
      yield w; const l = w.toLowerCase(), u = w.toUpperCase(), cap = w ? w[0].toUpperCase() + w.slice(1).toLowerCase() : w;
      const leet = w.replace(/[aAeEiIoOsS]/g, c => ({ a: '4', A: '4', e: '3', E: '3', i: '1', I: '1', o: '0', O: '0', s: '5', S: '5' }[c]));
      const base = [...new Set([l, u, cap, leet, w.split('').reverse().join('')])];
      for (const x of base) { yield x; for (let d = 0; d < 1000; d++) yield x + d; for (const y of ['!', '@', '#', '123', '1234']) yield x + y; }
    }
    const utf8 = s => { const a = []; for (let i = 0; i < s.length; i++) { const c = s.codePointAt(i); if (c < 128) a.push(c); else if (c < 2048) a.push(192 | c >> 6, 128 | c & 63); else { a.push(224 | c >> 12, 128 | c >> 6 & 63, 128 | c & 63); } if (c > 0xffff) i++; } return Uint8Array.from(a); };
    self.onmessage = e => {
      const o = e.data, algo = o.algo, target = o.target, fn = IMPL[algo];
      let tried = 0, found = null; const t0 = Date.now(); let last = t0;
      const tick = () => { const now = Date.now(); if (now - last > 250) { self.postMessage({ type: 'progress', tried, ms: now - t0 }); last = now; } };
      if (o.mode === 'dict') {
        const words = o.words, total = words.length;
        outer: for (let i = 0; i < words.length; i++) {
          const gen = o.mutate ? mutate(words[i]) : [words[i]];
          for (const cand of gen) { tried++; if (fn(utf8(cand)) === target) { found = cand; break outer; } if ((tried & 8191) === 0) tick(); }
        }
      } else {
        const cs = CS[o.charset] || o.charset, n = cs.length, csb = Uint8Array.from(cs, c => c.charCodeAt(0));
        for (let L = o.minLen; L <= o.maxLen && !found; L++) {
          const buf = new Uint8Array(L), idx = new Int32Array(L); buf.fill(csb[0]);
          for (; ;) {
            tried++; if (fn(buf) === target) { found = ''; for (let i = 0; i < L; i++) found += cs[idx[i]]; break; }
            if ((tried & 16383) === 0) tick();
            let pos = L - 1; for (; pos >= 0; pos--) { if (++idx[pos] < n) { buf[pos] = csb[idx[pos]]; break; } idx[pos] = 0; buf[pos] = csb[0]; }
            if (pos < 0) break;
          }
        }
      }
      self.postMessage({ type: 'done', found, tried, ms: Date.now() - t0 });
    };
  }

  let workerURL = null;
  function getWorkerURL() {
    if (workerURL) return workerURL;
    const body = '(' + workerBody.toString()
      .replace('(HASHIMPLS)', '(' + hashImpls.toString() + ')')
      .replace('CHARSETS_JSON', JSON.stringify(K.CHARSETS)) + ')();';
    workerURL = URL.createObjectURL(new Blob([body], { type: 'text/javascript' }));
    return workerURL;
  }

  K.crack = (opts, onProgress) => {
    const target = (opts.target || '').trim().toLowerCase(), algo = opts.algo || K.algoFor(target);
    if (!algo) return Promise.resolve({ error: 'طول الهاش غير مدعوم. المدعوم: MD5 (32) و SHA-1 (40) و SHA-256 (64).' });
    if (!/^[0-9a-f]+$/.test(target)) return Promise.resolve({ error: 'الهاش يجب أن يكون hex.' });
    return new Promise(resolve => {
      let w; try { w = new Worker(getWorkerURL()); } catch (e) { resolve({ error: 'تعذّر تشغيل العامل: ' + e.message }); return; }
      K._w = w;
      w.onmessage = e => {
        if (e.data.type === 'progress') { onProgress && onProgress(e.data); return; }
        w.terminate(); K._w = null; resolve(Object.assign({ algo }, e.data));
      };
      w.onerror = e => { w.terminate(); K._w = null; resolve({ error: 'خطأ في العامل: ' + (e.message || '') }); };
      w.postMessage({ mode: opts.mode, algo, target, words: opts.words || [], mutate: !!opts.mutate, charset: opts.charset || 'lower+digits', minLen: opts.minLen || 1, maxLen: opts.maxLen || 4 });
    });
  };
  K.stop = () => { if (K._w) { K._w.terminate(); K._w = null; return true; } return false; };
  return K;
});
