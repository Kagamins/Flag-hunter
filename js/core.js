/* CTF Toolkit — core logic (no DOM).
   Browser: window.CTF   Node: module.exports
   Encodings, auto-decoder ("magic"), flag search, classical ciphers, XOR,
   hash identification/computation, number conversion. */
(function (root, factory) {
  const C = factory();
  if (typeof module === 'object' && module.exports) module.exports = C;
  else root.CTF = C;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const C = {};

  /* ---------------- byte / string helpers ---------------- */
  const te = new TextEncoder();
  C.utf8 = s => te.encode(s);
  C.latin1Bytes = s => { const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i) & 255; return a; };
  C.latin1 = b => { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return s; };
  C.bytesToText = b => { try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (e) { return C.latin1(b); } };
  C.toHex = (b, sep = '') => Array.from(b, x => x.toString(16).padStart(2, '0')).join(sep);
  C.fromHex = h => {
    h = h.replace(/0x|\\x/gi, '').replace(/[\s:,]/g, '');
    if (!h.length || h.length % 2 || !/^[0-9a-f]+$/i.test(h)) return null;
    const a = new Uint8Array(h.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  };
  C.reverse = s => Array.from(s).reverse().join('');
  C.preview = (s, n = 160) => (s.length > n ? s.slice(0, n) + '…' : s);

  C.printableRatio = s => {
    if (!s || !s.length) return 0;
    let p = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || (c >= 0x100 && c !== 0xFFFD && !(c >= 0xD800 && c <= 0xDFFF) && !(c >= 0xE000 && c <= 0xF8FF))) p++;
    }
    return p / s.length;
  };

  const FREQ = { a: 8.167, b: 1.492, c: 2.782, d: 4.253, e: 12.702, f: 2.228, g: 2.015, h: 6.094, i: 6.966, j: 0.153, k: 0.772, l: 4.025, m: 2.406, n: 6.749, o: 7.507, p: 1.929, q: 0.095, r: 5.987, s: 6.327, t: 9.056, u: 2.758, v: 0.978, w: 2.36, x: 0.15, y: 1.974, z: 0.074 };
  C.FREQ = FREQ;
  const FREQV = Object.values(FREQ);
  C.chi = s => {
    const cnt = new Array(26).fill(0); let n = 0;
    for (let i = 0; i < s.length; i++) { let c = s.charCodeAt(i) | 32; if (c >= 97 && c <= 122) { cnt[c - 97]++; n++; } }
    if (!n) return 1e9;
    let x = 0; const keys = Object.keys(FREQ);
    for (let i = 0; i < 26; i++) { const e = n * FREQ[keys[i]] / 100; x += (cnt[i] - e) * (cnt[i] - e) / e; }
    return x / n; // normalised so short & long texts compare
  };
  C.ioc = s => {
    const cnt = new Array(26).fill(0); let n = 0;
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i) | 32; if (c >= 97 && c <= 122) { cnt[c - 97]++; n++; } }
    if (n < 2) return 0;
    let x = 0; for (const k of cnt) x += k * (k - 1);
    return x / (n * (n - 1));
  };
  const WORDS = /\b(the|and|flag|ctf|you|is|of|to|in|key|password|secret|this|that|with|for|are|was|here|your|not|have)\b/gi;
  C.textScore = s => {
    if (!s) return 0;
    const p = C.printableRatio(s);
    const al = (s.match(/[A-Za-z0-9 ]/g) || []).length / s.length;
    const words = (s.match(WORDS) || []).length;
    let sc = p * 50 + al * 30 + Math.min(words * 5, 20);
    if (C.findFlags(s, true).length) sc += 60;
    return Math.round(sc);
  };

  /* ---------------- flag format ---------------- */
  C.settings = { prefix: '', regex: '', caseInsensitive: true };
  C.escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  C.looseFlagRe = () => {
    const st = C.settings, fl = 'g' + (st.caseInsensitive ? 'i' : '');
    if (st.regex) { try { return new RegExp(st.regex, fl); } catch (e) { /* fall through */ } }
    if (st.prefix) return new RegExp(C.escapeRe(st.prefix) + '\\{[\\x20-\\x7a\\x7c\\x7e\\u00a0-\\uffff]{0,300}\\}', fl);
    return /[A-Za-z0-9_\-]{2,30}\{[\x20-\x7a\x7c\x7e]{1,300}\}/g;
  };
  // stricter version used after blind transforms (ROT-n etc.) so we don't report 25 garbage rotations
  C.strictFlagRe = () => {
    const st = C.settings;
    if (st.regex || st.prefix) return C.looseFlagRe();
    return /(?:flag|flg|ctf|key|htb|thm|[a-z0-9_]{1,15}ctf|ctf[a-z0-9_]{0,10})\{[\x20-\x7a\x7c\x7e]{1,300}\}/gi;
  };
  C.findFlags = (s, strict) => {
    if (!s) return [];
    const re = strict ? C.strictFlagRe() : C.looseFlagRe();
    const out = new Set(); let m; re.lastIndex = 0;
    while ((m = re.exec(s)) && out.size < 200) { if (!m[0].length) { re.lastIndex++; continue; } out.add(m[0]); }
    return [...out];
  };

  /* ---------------- simple transforms ---------------- */
  C.rot = (s, n) => s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26 + 26) % 26 + b); });
  C.rot47 = s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94));
  C.atbash = s => s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b)); });
  C.rotDigits = (s, n) => s.replace(/[0-9]/g, d => String((+d + n) % 10));

  /* ---------------- decoders (string -> string | null) ---------------- */
  const D = {};
  const padB64 = t => t + '==='.slice((t.length + 3) % 4);
  D.base64 = s => {
    const t = s.replace(/\s+/g, '');
    if (t.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(t)) return null;
    const u = t.replace(/=+$/, ''); if (u.length % 4 === 1) return null;
    try { return C.bytesToText(C.latin1Bytes(atob(padB64(u)))); } catch (e) { return null; }
  };
  D.base64url = s => {
    const t = s.replace(/\s+/g, '');
    if (t.length < 4 || !/^[A-Za-z0-9_-]+={0,2}$/.test(t) || !/[-_]/.test(t)) return null;
    return D.base64(t.replace(/-/g, '+').replace(/_/g, '/'));
  };
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  D.base32 = s => {
    const o = s.replace(/\s+/g, '');
    if (/[a-z]/.test(o) && /[A-Z]/.test(o)) return null;
    const t = o.toUpperCase();
    if (t.length < 8 || !/^[A-Z2-7]+=*$/.test(t)) return null;
    let bits = 0, val = 0; const out = [];
    for (const ch of t.replace(/=+$/, '')) {
      val = ((val << 5) | B32.indexOf(ch)) & 0xFFF; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return C.bytesToText(Uint8Array.from(out));
  };
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  D.base58 = s => {
    const t = s.trim();
    if (t.length < 4 || t.length > 4000 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(t)) return null;
    let n = 0n; for (const ch of t) n = n * 58n + BigInt(B58.indexOf(ch));
    let bytes = n > 0n ? Array.from(C.bigToBytes(n)) : [];
    for (const ch of t) { if (ch === '1') bytes.unshift(0); else break; }
    return C.bytesToText(Uint8Array.from(bytes));
  };
  D.base85 = s => {
    let t = s.replace(/\s+/g, '');
    if (t.startsWith('<~')) t = t.slice(2);
    if (t.endsWith('~>')) t = t.slice(0, -2);
    if (t.length < 5 || !/^[!-uz]+$/.test(t)) return null;
    const out = []; let i = 0;
    while (i < t.length) {
      if (t[i] === 'z') { out.push(0, 0, 0, 0); i++; continue; }
      let chunk = t.slice(i, i + 5); i += 5;
      if (chunk.includes('z')) return null;
      const padN = 5 - chunk.length; chunk += 'u'.repeat(padN);
      let v = 0; for (const ch of chunk) v = v * 85 + (ch.charCodeAt(0) - 33);
      if (v > 0xFFFFFFFF) return null;
      out.push(...[(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].slice(0, 4 - padN));
    }
    return C.bytesToText(Uint8Array.from(out));
  };
  D.hex = s => {
    const t = s.replace(/0x|\\x/gi, '').replace(/[\s:,]/g, '');
    if (t.length < 4) return null;
    const b = C.fromHex(t); return b ? C.bytesToText(b) : null;
  };
  D.binary = s => {
    const g = s.trim().split(/[\s,]+/);
    if (g.length > 1 && g.every(x => /^[01]{7,8}$/.test(x))) return C.bytesToText(Uint8Array.from(g.map(x => parseInt(x, 2))));
    const bits = s.replace(/\s+/g, '');
    if (bits.length < 8 || bits.length % 8 || !/^[01]+$/.test(bits)) return null;
    const out = new Uint8Array(bits.length / 8);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.substr(i * 8, 8), 2);
    return C.bytesToText(out);
  };
  D.octal = s => {
    const g = s.replace(/\\/g, ' ').trim().split(/[\s,]+/);
    if (g.length < 2 || !g.every(x => /^[0-7]{1,3}$/.test(x)) || !g.some(x => x.length === 3)) return null;
    const v = g.map(x => parseInt(x, 8)); if (v.some(x => x > 255)) return null;
    return C.bytesToText(Uint8Array.from(v));
  };
  D.decimal = s => {
    const g = s.trim().split(/[\s,;]+/);
    if (g.length < 2 || !g.every(x => /^\d{1,5}$/.test(x))) return null;
    const v = g.map(Number); if (v.some(x => x > 0xFFFF)) return null;
    if (v.every(x => x < 256)) return C.bytesToText(Uint8Array.from(v));
    return String.fromCharCode(...v);
  };
  D.url = s => {
    if (!/%[0-9a-f]{2}/i.test(s)) return null;
    try { return decodeURIComponent(s.replace(/\+/g, ' ')); }
    catch (e) { return C.bytesToText(C.latin1Bytes(s.replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))))); }
  };
  const NAMED = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ', lbrace: '{', rbrace: '}', lcub: '{', rcub: '}', lowbar: '_', sol: '/', colon: ':', period: '.', comma: ',', excl: '!', quest: '?', num: '#', dollar: '$', percnt: '%', equals: '=', plus: '+', hyphen: '-', lpar: '(', rpar: ')' };
  D.html = s => {
    if (!/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(s)) return null;
    return s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
      .replace(/&([a-z]+);/gi, (m, n) => NAMED[n.toLowerCase()] ?? m);
  };
  const MORSE = { '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!', '-....-': '-', '-..-.': '/', '.--.-.': '@', '-.--.': '(', '-.--.-': ')', '---...': ':', '-...-': '=', '.-.-.': '+', '..--.-': '_', '.----.': "'", '.-..-.': '"', '-.-.-.': ';', '.-...': '&', '...-..-': '$' };
  C.MORSE = MORSE;
  D.morse = s => {
    const t = s.trim().replace(/[·•∙]/g, '.').replace(/[_−–—]/g, '-');
    if (!/^[.\-\s\/|\\]+$/.test(t) || !/[.-]/.test(t)) return null;
    return t.split(/\s*[\/|\\]\s*|\s{3,}/).map(w => w.trim().split(/\s+/).map(c => MORSE[c] || (c ? '?' : '')).join('')).join(' ').trim();
  };
  D.unicode = s => {
    if (!/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}|\\u\{[0-9a-f]+\}|U\+[0-9a-f]{4}/i.test(s)) return null;
    return s.replace(/\\u\{([0-9a-f]+)\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/U\+([0-9a-f]{4,6})\s?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
  };
  D.qp = s => {
    if (!/=[0-9A-F]{2}/.test(s)) return null;
    const t = s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return C.bytesToText(C.latin1Bytes(t));
  };
  C.D = D;

  /* ---------------- encoders ---------------- */
  const E = {};
  E.base64 = s => btoa(C.latin1(C.utf8(s)));
  E.base64url = s => E.base64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  E.base32 = s => {
    const b = C.utf8(s); let bits = 0, val = 0, out = '';
    for (const x of b) { val = ((val << 8) | x) & 0xFFFF; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    while (out.length % 8) out += '=';
    return out;
  };
  E.base58 = s => {
    const b = C.utf8(s); let n = 0n; for (const x of b) n = n * 256n + BigInt(x);
    let out = ''; while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const x of b) { if (x === 0) out = '1' + out; else break; }
    return out;
  };
  E.hex = s => C.toHex(C.utf8(s));
  E.binary = s => Array.from(C.utf8(s), b => b.toString(2).padStart(8, '0')).join(' ');
  E.octal = s => Array.from(C.utf8(s), b => b.toString(8).padStart(3, '0')).join(' ');
  E.decimal = s => Array.from(C.utf8(s)).join(' ');
  E.url = s => Array.from(C.utf8(s), b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
  E.html = s => Array.from(s, c => '&#' + c.codePointAt(0) + ';').join('');
  E.unicode = s => Array.from(s, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
  const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
  E.morse = s => s.toUpperCase().split(/\s+/).map(w => Array.from(w, c => MORSE_REV[c] || '?').join(' ')).join(' / ');
  C.E = E;

  /* ---------------- auto decoder ("magic") ---------------- */
  C.DECODERS = [
    ['Base64', D.base64], ['Base64URL', D.base64url], ['Base32', D.base32], ['Base58', D.base58], ['Base85', D.base85],
    ['Hex', D.hex], ['Binary', D.binary], ['Octal', D.octal], ['Decimal', D.decimal], ['URL', D.url],
    ['HTML entities', D.html], ['Morse', D.morse], ['Unicode escapes', D.unicode], ['Quoted-printable', D.qp],
  ];
  C.TRANSFORMS = [['Reverse', C.reverse], ['ROT13', s => C.rot(s, 13)], ['ROT47', C.rot47], ['Atbash', C.atbash]];
  const TNAMES = new Set(C.TRANSFORMS.map(t => t[0]));
  const tryDec = (fn, s) => { try { const o = fn(s); return o != null && o !== s && o.length && C.printableRatio(o) >= 0.9 ? o : null; } catch (e) { return null; } };

  C.magic = (input, opts = {}) => {
    const maxDepth = opts.depth ?? 6, maxNodes = opts.maxNodes ?? 2500;
    const seen = new Set([input]); const queue = [{ s: input, chain: [] }];
    const flags = [], outputs = []; let n = 0;
    const addFlags = (s, chain, strict) => C.findFlags(s, strict).forEach(f => flags.push({ flag: f, chain }));
    while (queue.length && n < maxNodes) {
      const node = queue.shift(); n++;
      if (node.chain.length) { addFlags(node.s, node.chain, false); outputs.push({ s: node.s, chain: node.chain, score: C.textScore(node.s) }); }
      if (node.s.length < 200000) {
        for (let k = 1; k < 26; k++) addFlags(C.rot(node.s, k), [...node.chain, 'ROT' + k], true);
        addFlags(C.rot47(node.s), [...node.chain, 'ROT47'], true);
        addFlags(C.atbash(node.s), [...node.chain, 'Atbash'], true);
        addFlags(C.reverse(node.s), [...node.chain, 'Reverse'], true);
      }
      if (node.chain.length >= maxDepth) continue;
      for (const [name, fn] of C.DECODERS) {
        const out = tryDec(fn, node.s);
        if (out == null || seen.has(out)) continue;
        seen.add(out); queue.push({ s: out, chain: [...node.chain, name] });
      }
      const last = node.chain[node.chain.length - 1];
      if (!TNAMES.has(last)) {
        for (const [name, fn] of C.TRANSFORMS) {
          const out = fn(node.s);
          if (out === node.s || seen.has(out)) continue;
          if (!C.DECODERS.some(([, f]) => tryDec(f, out) != null)) continue; // only expand if it unlocks a decoder
          seen.add(out); queue.push({ s: out, chain: [...node.chain, name] });
        }
      }
    }
    const fmap = new Map();
    for (const f of flags) if (!fmap.has(f.flag) || fmap.get(f.flag).chain.length > f.chain.length) fmap.set(f.flag, f);
    outputs.sort((a, b) => b.score - a.score || a.chain.length - b.chain.length);
    return { flags: [...fmap.values()], outputs: outputs.slice(0, opts.top || 12), nodes: n };
  };

  /* ---------------- deep flag search ---------------- */
  C.TOKEN_RES = [
    /[A-Za-z0-9+\/_\-]{12,}={0,2}/g,
    /(?:[01]{7,8}[\s,]*){4,}/g,
    /(?:\b\d{2,3}\b[\s,]+){4,}\b\d{2,3}\b/g,
    /(?:[.\-]{1,7}(?:\s+|\s*\/\s*)){4,}[.\-]{1,7}/g,
    /(?:%[0-9a-fA-F]{2}){3,}/g,
    /(?:\\x[0-9a-fA-F]{2}){3,}/g,
    /(?:&#x?[0-9a-fA-F]+;){3,}/g,
    /(?:[0-9a-fA-F]{2}[\s:]){4,}[0-9a-fA-F]{2}/g,
  ];
  C.encodedPrefixHints = text => {
    const prefixes = C.settings.prefix ? [C.settings.prefix] : ['flag', 'FLAG', 'ctf', 'CTF'];
    const hints = [];
    for (const p of prefixes) {
      const pb = p + '{'; const forms = [['Hex', C.toHex(C.utf8(pb)), true]];
      for (let k = 0; k < 3; k++) {
        const b = btoa('\0'.repeat(k) + C.latin1(C.utf8(pb))); const L = k + C.utf8(pb).length;
        const sig = b.slice(Math.ceil(k * 8 / 6), Math.floor(L * 8 / 6));
        if (sig.length >= 4) forms.push(['Base64', sig, false]);
      }
      forms.push(['Base32', E.base32(pb).replace(/=+$/, '').slice(0, Math.floor(C.utf8(pb).length * 8 / 5)), false]);
      forms.push(['ROT13', C.rot(pb, 13), false], ['Reversed', C.reverse(pb), false], ['Decimal', E.decimal(pb), false], ['Binary', E.binary(pb), false], ['Binary (no spaces)', E.binary(pb).replace(/ /g, ''), false]);
      for (const [name, sig, ci] of forms) {
        const idx = ci ? text.toLowerCase().indexOf(sig.toLowerCase()) : text.indexOf(sig);
        if (idx >= 0) hints.push({ encoding: name, prefix: p, offset: idx, sig });
      }
    }
    return hints;
  };
  C.deepFlagSearch = (text, opts = {}) => {
    const res = []; const seen = new Set();
    const add = (flag, method) => { if (seen.has(flag)) return; seen.add(flag); res.push({ flag, method }); };
    C.findFlags(text).forEach(f => add(f, 'نص مباشر'));
    if (text.length < 5e6) { const j = text.replace(/\s+/g, ''); if (j !== text) C.findFlags(j).forEach(f => { if (![...seen].some(x => f.includes(x.replace(/\s+/g, '')))) add(f, 'بعد حذف المسافات'); }); }
    if (text.length < 3e6) {
      for (let k = 1; k < 26; k++) C.findFlags(C.rot(text, k), true).forEach(f => add(f, 'ROT' + k + ' (قيصر)'));
      C.findFlags(C.rot47(text), true).forEach(f => add(f, 'ROT47'));
      C.findFlags(C.atbash(text), true).forEach(f => add(f, 'Atbash'));
      const rv = C.reverse(text);
      C.findFlags(rv).forEach(f => add(f, 'نص معكوس'));
      for (let k = 1; k < 26; k++) C.findFlags(C.rot(rv, k), true).forEach(f => add(f, 'معكوس + ROT' + k));
    }
    let count = 0; const maxT = opts.maxTokens || 400; const tokSeen = new Set();
    for (const re of C.TOKEN_RES) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(text)) && count < maxT) {
        const t = m[0].trim();
        if (t.length > 20000 || tokSeen.has(t)) continue;
        tokSeen.add(t); count++;
        C.magic(t, { depth: 5, maxNodes: 200 }).flags.forEach(f => add(f.flag, 'مقطع @' + m.index + ': ' + (f.chain.join(' → ') || 'مباشر')));
      }
    }
    if (text.trim().length <= 4000) C.magic(text.trim(), { depth: 6, maxNodes: 1200 }).flags.forEach(f => add(f.flag, f.chain.join(' → ') || 'مباشر'));
    // drop garbled near-duplicates produced by long transform chains (keep the simpler, earlier find)
    for (let i = res.length - 1; i > 0; i--) {
      const f = res[i].flag;
      const near = g => { const a = g.flag, L = Math.max(a.length, f.length); let p = 0; while (p < a.length && p < f.length && a[p] === f[p]) p++; let q = 0; while (q < a.length - p && q < f.length - p && a[a.length - 1 - q] === f[f.length - 1 - q]) q++; return (p + q) / L >= 0.7; };
      if (res.slice(0, i).some(near)) res.splice(i, 1);
    }
    const sre = C.strictFlagRe();
    res.forEach(r => { sre.lastIndex = 0; r.likely = sre.test(r.flag); });
    res.sort((a, b) => b.likely - a.likely);
    return { flags: res, hints: C.encodedPrefixHints(text) };
  };

  /* ---------------- identification ---------------- */
  C.identify = raw => {
    const s = raw.trim(), out = [];
    if (!s) return out;
    const one = !/\s/.test(s);
    const jwt = C.jwtDecode(s);
    if (jwt) out.push({ kind: 'رمز JWT', detail: 'الخوارزمية: ' + (jwt.header.alg || '?') + ' — المحتوى: ' + C.preview(JSON.stringify(jwt.payload), 120), tool: 'hash' });
    if (one && !jwt) C.identifyHash(s).forEach(h => out.push({ kind: 'هاش محتمل: ' + h.name, detail: h.note || '', tool: 'hash' }));
    for (const [name, fn] of C.DECODERS) { const o = tryDec(fn, s); if (o != null) out.push({ kind: 'يُفك كـ ' + name, detail: C.preview(o), tool: 'decode' }); }
    if (/^\d{6,}$/.test(s)) { const t = C.bytesToText(C.bigToBytes(BigInt(s))); if (C.printableRatio(t) > 0.9) out.push({ kind: 'رقم كبير ← نص', detail: C.preview(t), tool: 'hash' }); }
    if (/^[+\-<>\[\].,\s]+$/.test(s) && /[\[\]]/.test(s) && /[+\-]/.test(s)) { const r = C.brainfuck(s); out.push({ kind: 'برنامج Brainfuck', detail: C.preview(r.out || r.error || ''), tool: 'decode' }); }
    if (/^[ABab\s]+$/.test(s) && s.replace(/\s/g, '').length >= 10) out.push({ kind: 'شيفرة Bacon؟', detail: C.preview(C.bacon(s).std26), tool: 'cipher' });
    const letters = s.replace(/[^a-z]/gi, ''), dense = s.replace(/\s/g, '');
    if (letters.length >= 20 && letters.length / dense.length > 0.7 && !out.some(o => /يُفك كـ (Base|Hex)/.test(o.kind) && C.textScore(o.detail) > 80)) {
      const ic = C.ioc(letters);
      if (ic > 0.055) out.push({ kind: 'شيفرة حروف: استبدال أحادي أو تبديل مواقع', detail: 'مؤشر التطابق ' + ic.toFixed(3) + ' (الإنجليزية ≈ 0.066). جرّب قيصر / Atbash / Affine / السياج المتعرج أو حلّ الاستبدال.', tool: 'cipher' });
      else out.push({ kind: 'شيفرة حروف: متعددة الأبجدية أو عشوائية', detail: 'مؤشر التطابق ' + ic.toFixed(3) + ' (العشوائي ≈ 0.038). جرّب الحل التلقائي لـ Vigenère.', tool: 'cipher' });
    }
    return out;
  };

  /* ---------------- classical ciphers ---------------- */
  C.caesarAll = s => {
    const r = [];
    for (let k = 1; k < 26; k++) { const t = C.rot(s, k); r.push({ label: 'ROT' + k + ' (إزاحة للخلف ' + (26 - k) + ')', text: t, chi: C.chi(t), flags: C.findFlags(t, true) }); }
    return r.sort((a, b) => (b.flags.length - a.flags.length) || a.chi - b.chi);
  };
  C.vigenere = (s, key, decrypt = true) => {
    const k = key.toLowerCase().replace(/[^a-z]/g, ''); if (!k) return s;
    let j = 0;
    return s.replace(/[a-z]/gi, c => {
      const b = c <= 'Z' ? 65 : 97, sh = k.charCodeAt(j++ % k.length) - 97;
      return String.fromCharCode((c.charCodeAt(0) - b + (decrypt ? 26 - sh : sh)) % 26 + b);
    });
  };
  C.beaufort = (s, key) => {
    const k = key.toLowerCase().replace(/[^a-z]/g, ''); if (!k) return s;
    let j = 0;
    return s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97, sh = k.charCodeAt(j++ % k.length) - 97; return String.fromCharCode((sh - (c.charCodeAt(0) - b) + 26) % 26 + b); });
  };
  const reduceRepeat = k => { for (let L = 1; L <= k.length / 2; L++) if (k.length % L === 0 && k.slice(0, L).repeat(k.length / L) === k) return k.slice(0, L); return k; };
  C.vigenereSolve = (s, maxLen = 20) => {
    const L = s.toLowerCase().replace(/[^a-z]/g, '');
    if (L.length < 6) return [];
    const cands = [];
    for (let kl = 1; kl <= Math.min(maxLen, Math.floor(L.length / 2)); kl++) {
      let tot = 0; for (let c = 0; c < kl; c++) { let col = ''; for (let i = c; i < L.length; i += kl) col += L[i]; tot += C.ioc(col); }
      cands.push({ kl, ioc: tot / kl });
    }
    cands.sort((a, b) => b.ioc - a.ioc);
    const results = [], seenKeys = new Set();
    for (const { kl } of cands.slice(0, 6)) {
      let key = '';
      for (let c = 0; c < kl; c++) {
        let col = ''; for (let i = c; i < L.length; i += kl) col += L[i];
        const cnt = new Array(26).fill(0); for (const ch of col) cnt[ch.charCodeAt(0) - 97]++;
        let best = 0, bestDot = -1;
        for (let sh = 0; sh < 26; sh++) { let dot = 0; for (let i = 0; i < 26; i++) dot += cnt[(i + sh) % 26] * FREQV[i]; if (dot > bestDot) { bestDot = dot; best = sh; } }
        key += String.fromCharCode(97 + best);
      }
      key = reduceRepeat(key);
      if (seenKeys.has(key)) continue; seenKeys.add(key);
      const text = C.vigenere(s, key, true);
      results.push({ label: 'Vigenère بالمفتاح "' + key + '"', key, text, chi: C.chi(text) + key.length * 0.002, flags: C.findFlags(text, true) });
    }
    return results.sort((a, b) => (b.flags.length - a.flags.length) || a.chi - b.chi);
  };
  const AFF_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
  const modInv = a => { for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x; return 1; };
  C.affineDecrypt = (s, a, b) => { const ai = modInv(a); return s.replace(/[a-z]/gi, c => { const base = c <= 'Z' ? 65 : 97; return String.fromCharCode(((ai * (c.charCodeAt(0) - base - b)) % 26 + 26) % 26 + base); }); };
  C.affineAll = s => {
    const r = [];
    for (const a of AFF_A) for (let b = 0; b < 26; b++) { if (a === 1) continue; const t = C.affineDecrypt(s, a, b); r.push({ label: 'Affine a=' + a + ', b=' + b, text: t, chi: C.chi(t), flags: C.findFlags(t, true) }); }
    return r.sort((x, y) => (y.flags.length - x.flags.length) || x.chi - y.chi).slice(0, 10);
  };
  C.railDecrypt = (s, r, offset = 0) => {
    const chars = Array.from(s), n = chars.length; if (r < 2 || r >= n + offset) return s;
    const cycle = 2 * (r - 1), pat = new Array(n);
    for (let i = 0; i < n; i++) { const p = (i + offset) % cycle; pat[i] = p < r ? p : cycle - p; }
    const order = []; for (let rr = 0; rr < r; rr++) for (let i = 0; i < n; i++) if (pat[i] === rr) order.push(i);
    const out = new Array(n); for (let k = 0; k < n; k++) out[order[k]] = chars[k];
    return out.join('');
  };
  C.railEncrypt = (s, r) => { const chars = Array.from(s), n = chars.length; if (r < 2) return s; const cycle = 2 * (r - 1); const rows = Array.from({ length: r }, () => []); for (let i = 0; i < n; i++) { const p = i % cycle; rows[p < r ? p : cycle - p].push(chars[i]); } return rows.map(x => x.join('')).join(''); };
  C.railAll = s => {
    const r = [], n = Array.from(s).length;
    for (let rails = 2; rails <= Math.min(15, n - 1); rails++) for (let off = 0; off < 2 * (rails - 1); off++) { const t = C.railDecrypt(s, rails, off); r.push({ label: 'السياج المتعرج ' + rails + ' صفوف' + (off ? '، إزاحة ' + off : ''), text: t, chi: C.chi(t) + (/\b(the|and|flag)\b/i.test(t) ? -0.5 : 0), flags: C.findFlags(t, true) }); }
    return r.sort((a, b) => (b.flags.length - a.flags.length) || a.chi - b.chi).slice(0, 8);
  };
  C.bacon = s => {
    let t;
    if (/^[abAB01\s\/,|.\-]+$/.test(s)) t = s.replace(/[^abAB01]/g, '').toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B');
    else t = s.replace(/[^a-zA-Z]/g, '').replace(/[a-zA-Z]/g, c => (c === c.toLowerCase() ? 'A' : 'B'));
    const A26 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', A24 = 'ABCDEFGHIKLMNOPQRSTUWXYZ';
    const dec = (bits, alpha) => { let o = ''; for (let i = 0; i + 5 <= bits.length; i += 5) { const v = parseInt(bits.substr(i, 5).replace(/A/g, '0').replace(/B/g, '1'), 2); o += alpha[v] || '?'; } return o; };
    const inv = t.replace(/[AB]/g, c => (c === 'A' ? 'B' : 'A'));
    return { std26: dec(t, A26), std24: dec(t, A24), inv26: dec(inv, A26), inv24: dec(inv, A24) };
  };
  C.freq = s => {
    const cnt = {}; for (let i = 0; i < 26; i++) cnt[String.fromCharCode(65 + i)] = 0;
    let n = 0; for (const ch of s.toUpperCase()) if (cnt[ch] !== undefined) { cnt[ch]++; n++; }
    return { counts: cnt, total: n, ioc: C.ioc(s) };
  };
  C.substitute = (s, map) => s.replace(/[a-z]/gi, c => { const u = c.toUpperCase(), m = map[u]; if (!m) return c === u ? '_' : '_'; return c === u ? m.toUpperCase() : m.toLowerCase(); });
  C.brainfuck = (code, input = '') => {
    const p = code.replace(/[^+\-<>\[\].,]/g, ''), jump = {}, st = [];
    for (let i = 0; i < p.length; i++) { if (p[i] === '[') st.push(i); else if (p[i] === ']') { if (!st.length) return { error: 'Unmatched ]' }; const j = st.pop(); jump[i] = j; jump[j] = i; } }
    if (st.length) return { error: 'Unmatched [' };
    const tape = new Uint8Array(30000); let ptr = 0, ip = 0, steps = 0, out = '', inp = 0;
    while (ip < p.length) {
      if (++steps > 5e6) return { out, error: 'Step limit reached' };
      switch (p[ip]) {
        case '+': tape[ptr]++; break; case '-': tape[ptr]--; break;
        case '>': ptr = (ptr + 1) % 30000; break; case '<': ptr = (ptr + 29999) % 30000; break;
        case '.': out += String.fromCharCode(tape[ptr]); break;
        case ',': tape[ptr] = inp < input.length ? input.charCodeAt(inp++) : 0; break;
        case '[': if (!tape[ptr]) ip = jump[ip]; break; case ']': if (tape[ptr]) ip = jump[ip]; break;
      }
      ip++;
    }
    return { out };
  };

  /* ---------------- XOR ---------------- */
  C.parseBytesInput = (s, mode = 'auto') => {
    const t = s.trim();
    if (mode === 'hex' || (mode === 'auto' && /^(0x|\\x)?[0-9a-f\s:,x\\]+$/i.test(t) && C.fromHex(t))) { const b = C.fromHex(t); if (b) return { bytes: b, as: 'hex' }; }
    if (mode === 'base64' || (mode === 'auto' && t.length >= 8 && /^[A-Za-z0-9+/\s]+={0,2}$/.test(t) && /[A-Z]/.test(t) && /[a-z]/.test(t))) { try { return { bytes: C.latin1Bytes(atob(padB64(t.replace(/\s+/g, '').replace(/=+$/, '')))), as: 'base64' }; } catch (e) { } }
    if (mode === 'decimal' || (mode === 'auto' && /^\d{1,3}([\s,]+\d{1,3})+$/.test(t))) return { bytes: Uint8Array.from(t.split(/[\s,]+/).map(Number)), as: 'decimal' };
    return { bytes: C.utf8(s), as: 'text' };
  };
  C.xor = (data, key) => { const o = new Uint8Array(data.length); if (!key.length) return o.set(data), o; for (let i = 0; i < data.length; i++) o[i] = data[i] ^ key[i % key.length]; return o; };
  C.xorBrute = bytes => {
    const r = [];
    for (let k = 0; k < 256; k++) { const t = C.latin1(C.xor(bytes, [k])); r.push({ label: 'المفتاح 0x' + k.toString(16).padStart(2, '0') + (k >= 32 && k < 127 ? " ('" + String.fromCharCode(k) + "')" : ''), key: k, text: t, score: C.textScore(t), flags: C.findFlags(t) }); }
    return r.sort((a, b) => (b.flags.length - a.flags.length) || b.score - a.score).slice(0, 10);
  };
  C.xorKnownPlain = (bytes, known, offset = 0) => {
    const kb = C.utf8(known), frag = [];
    for (let i = 0; i < kb.length && offset + i < bytes.length; i++) frag.push(bytes[offset + i] ^ kb[i]);
    const tries = [];
    for (let L = 1; L <= frag.length; L++) {
      const key = new Array(L);
      for (let i = 0; i < L; i++) key[(offset + i) % L] = frag[i];
      const t = C.latin1(C.xor(bytes, key));
      tries.push({ key: Uint8Array.from(key), text: t, score: C.textScore(t), flags: C.findFlags(t) });
    }
    tries.sort((a, b) => (b.flags.length - a.flags.length) || b.score - a.score);
    return { fragment: Uint8Array.from(frag), tries };
  };

  /* ---------------- hashing ---------------- */
  const MD5K = new Uint32Array(64); for (let i = 0; i < 64; i++) MD5K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  const MD5S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  C.md5 = bytes => {
    if (typeof bytes === 'string') bytes = C.utf8(bytes);
    const len = bytes.length, nb = ((len + 8) >>> 6) + 1, w = new Uint32Array(nb * 16);
    for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
    w[len >> 2] |= 0x80 << ((len % 4) * 8);
    w[nb * 16 - 2] = (len * 8) >>> 0; w[nb * 16 - 1] = Math.floor(len * 8 / 4294967296);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let blk = 0; blk < nb; blk++) {
      let A = a0, B = b0, Cc = c0, Dd = d0;
      for (let i = 0; i < 64; i++) {
        let Fv, g;
        if (i < 16) { Fv = (B & Cc) | (~B & Dd); g = i; } else if (i < 32) { Fv = (Dd & B) | (~Dd & Cc); g = (5 * i + 1) % 16; }
        else if (i < 48) { Fv = B ^ Cc ^ Dd; g = (3 * i + 5) % 16; } else { Fv = Cc ^ (B | ~Dd); g = (7 * i) % 16; }
        Fv = (Fv + A + MD5K[i] + w[blk * 16 + g]) >>> 0;
        A = Dd; Dd = Cc; Cc = B; B = (B + ((Fv << MD5S[i]) | (Fv >>> (32 - MD5S[i])))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + Cc) >>> 0; d0 = (d0 + Dd) >>> 0;
    }
    return [a0, b0, c0, d0].map(x => C.toHex([x & 255, (x >>> 8) & 255, (x >>> 16) & 255, (x >>> 24) & 255])).join('');
  };
  const CRC_T = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; CRC_T[n] = c >>> 0; }
  C.crc32 = (bytes, start = 0, end = bytes.length) => { let c = 0xFFFFFFFF; for (let i = start; i < end; i++) c = CRC_T[(c ^ bytes[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
  C.sha = async (algo, bytes) => { if (typeof bytes === 'string') bytes = C.utf8(bytes); const d = await crypto.subtle.digest(algo, bytes); return C.toHex(new Uint8Array(d)); };
  C.allHashes = async bytes => {
    if (typeof bytes === 'string') bytes = C.utf8(bytes);
    const [s1, s256, s384, s512] = await Promise.all(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].map(a => C.sha(a, bytes)));
    return { MD5: C.md5(bytes), 'SHA-1': s1, 'SHA-256': s256, 'SHA-384': s384, 'SHA-512': s512, CRC32: C.crc32(bytes).toString(16).padStart(8, '0') };
  };
  C.identifyHash = h => {
    h = h.trim(); const r = [];
    const pre = [
      [/^\$2[abxy]?\$\d{2}\$[.\/A-Za-z0-9]{53}$/, 'bcrypt', 'بطيء ومملّح — جرّب قائمة كلمات قصيرة فقط.'],
      [/^\$1\$/, 'MD5-crypt (Unix $1$)'], [/^\$apr1\$/, 'Apache MD5 (apr1)'], [/^\$5\$/, 'SHA-256-crypt ($5$)'],
      [/^\$6\$/, 'SHA-512-crypt ($6$، ملف shadow في لينكس)'], [/^\$y\$/, 'yescrypt ($y$, modern Linux shadow)'],
      [/^\$argon2(id|i|d)\$/, 'Argon2'], [/^\$[PH]\$/, 'phpass (WordPress / phpBB)'],
      [/^\{SSHA\}/i, 'Salted SHA-1 (LDAP)'], [/^\{SHA\}/i, 'SHA-1, Base64 (LDAP)'],
      [/^pbkdf2_sha256\$/, 'Django PBKDF2-SHA256'], [/^sha1\$/, 'Django salted SHA-1'],
      [/^\*[0-9A-F]{40}$/i, 'هاش كلمة سر MySQL 4.1+'], [/^[a-f0-9]{32}:[a-f0-9]{32}$/i, 'زوج LM:NTLM (صيغة pwdump)'],
      [/^\$krb5/, 'هاش تذكرة Kerberos'], [/^[a-f0-9]{32}:[^:]+$/i, 'MD5 مع ملح (hash:salt)'], [/^[a-f0-9]{40}:[^:]+$/i, 'SHA-1 مع ملح (hash:salt)'],
    ];
    for (const [re, name, note] of pre) if (re.test(h)) r.push({ name, note: note || '' });
    if (r.length) return r;
    if (/^[a-f0-9]+$/i.test(h) && h.length % 2 === 0) {
      const byLen = { 8: ['CRC32', 'Adler-32', 'FNV-1 32'], 16: ['MySQL 3.x (old_password)', 'CRC64', 'Half MD5'], 32: ['MD5', 'NTLM', 'MD4', 'LM'], 40: ['SHA-1', 'RIPEMD-160', 'MySQL5 (without *)'], 56: ['SHA-224', 'SHA3-224'], 64: ['SHA-256', 'SHA3-256', 'BLAKE2s-256', 'Keccak-256'], 96: ['SHA-384', 'SHA3-384'], 128: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'] };
      (byLen[h.length] || []).forEach((n, i) => r.push({ name: n, note: i === 0 ? 'الأرجح' : '' }));
      if (!r.length) r.push({ name: 'Hex غير معروف (' + h.length / 2 + ' بايت)', note: 'ليس طول هاش قياسي — ربما بيانات مرمّزة بـ Hex، جرّب فك الترميز.' });
    } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(h) && !/^\d+$/.test(h)) {
      try { const n = atob(padB64(h.replace(/=+$/, ''))).length; const m = { 16: 'MD5', 20: 'SHA-1', 28: 'SHA-224', 32: 'SHA-256', 48: 'SHA-384', 64: 'SHA-512' }[n]; if (m) r.push({ name: 'هاش ' + m + ' مرمّز بـ Base64', note: 'فك Base64 إلى Hex ثم عامله كـ ' + m }); } catch (e) { }
    }
    return r;
  };
  C.jwtDecode = s => {
    const p = s.trim().split('.');
    if (p.length !== 3 || !p.every(x => /^[A-Za-z0-9_-]*$/.test(x)) || !p[0] || !p[1]) return null;
    try {
      const dec = x => { const t = x.replace(/-/g, '+').replace(/_/g, '/'); return C.bytesToText(C.latin1Bytes(atob(padB64(t)))); };
      const header = JSON.parse(dec(p[0])), payload = JSON.parse(dec(p[1]));
      if (typeof header !== 'object' || header === null) return null;
      return { header, payload, signature: p[2] };
    } catch (e) { return null; }
  };

  /* ---------------- numbers ---------------- */
  C.bigToBytes = n => { if (n < 0n) n = -n; let h = n.toString(16); if (h.length % 2) h = '0' + h; return C.fromHex(h) || new Uint8Array([0]); };
  C.parseBig = (s, base) => {
    let t = s.trim().replace(/[\s_,]/g, ''), neg = false;
    if (!t) return null;
    if (t[0] === '-') { neg = true; t = t.slice(1); }
    if (!base || base === 'auto') {
      if (/^0x/i.test(t)) { base = 16; t = t.slice(2); } else if (/^0b/i.test(t)) { base = 2; t = t.slice(2); } else if (/^0o/i.test(t)) { base = 8; t = t.slice(2); }
      else if (/^\d+$/.test(t)) base = 10; else if (/^[0-9a-f]+$/i.test(t)) base = 16; else return null;
    }
    base = +base; if (base === 16) t = t.replace(/^0x/i, ''); if (base === 2) t = t.replace(/^0b/i, '');
    const digits = '0123456789abcdefghijklmnopqrstuvwxyz', B = BigInt(base); let n = 0n;
    if (!t) return null;
    for (const ch of t.toLowerCase()) { const d = digits.indexOf(ch); if (d < 0 || d >= base) return null; n = n * B + BigInt(d); }
    return neg ? -n : n;
  };
  C.numberViews = n => {
    const bytes = C.bigToBytes(n), le = bytes.slice().reverse();
    return [
      ['عشري', n.toString(10)], ['Hex', '0x' + n.toString(16)], ['ثُماني', '0o' + n.toString(8)], ['ثنائي', n.toString(2)], ['Base36', n.toString(36)],
      ['البايتات (big-endian)', C.toHex(bytes, ' ')], ['البايتات (little-endian)', C.toHex(le, ' ')],
      ['كنص (big-endian)', C.bytesToText(bytes)], ['كنص (little-endian)', C.bytesToText(le)],
      ['عدد البتات', String(n === 0n ? 0 : (n < 0n ? -n : n).toString(2).length)],
    ];
  };
  C.textCodes = s => Array.from(s).map(ch => { const b = C.utf8(ch); return { ch, dec: Array.from(b).join(' '), hex: C.toHex(b, ' '), bin: Array.from(b, x => x.toString(2).padStart(8, '0')).join(' '), oct: Array.from(b, x => x.toString(8).padStart(3, '0')).join(' '), cp: 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') }; });


  /* ---------------- RSA math (textbook) ---------------- */
  C.modpow = (b, e, m) => { let r = 1n; b %= m; if (b < 0n) b += m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
  C.egcd = (a, b) => { let [x0, x1, y0, y1] = [1n, 0n, 0n, 1n]; while (b) { const q = a / b; [a, b] = [b, a % b]; [x0, x1] = [x1, x0 - q * x1]; [y0, y1] = [y1, y0 - q * y1]; } return [a, x0, y0]; };
  C.modinv = (a, m) => { const [g, x] = C.egcd(((a % m) + m) % m, m); if (g !== 1n) return null; return ((x % m) + m) % m; };
  C.iroot = (n, k) => { if (n < 2n) return n; let lo = 0n, hi = 1n << (BigInt(n.toString(2).length) / k + 1n); while (lo < hi) { const mid = (lo + hi + 1n) / 2n; if (mid ** k <= n) lo = mid; else hi = mid - 1n; } return lo; };

  return C;
});
