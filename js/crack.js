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
    // SHA-512 (64-bit عبر زوجي 32-بت [hi,lo])
    const K512 = [[0x428a2f98,0xd728ae22],[0x71374491,0x23ef65cd],[0xb5c0fbcf,0xec4d3b2f],[0xe9b5dba5,0x8189dbbc],[0x3956c25b,0xf348b538],[0x59f111f1,0xb605d019],[0x923f82a4,0xaf194f9b],[0xab1c5ed5,0xda6d8118],[0xd807aa98,0xa3030242],[0x12835b01,0x45706fbe],[0x243185be,0x4ee4b28c],[0x550c7dc3,0xd5ffb4e2],[0x72be5d74,0xf27b896f],[0x80deb1fe,0x3b1696b1],[0x9bdc06a7,0x25c71235],[0xc19bf174,0xcf692694],[0xe49b69c1,0x9ef14ad2],[0xefbe4786,0x384f25e3],[0x0fc19dc6,0x8b8cd5b5],[0x240ca1cc,0x77ac9c65],[0x2de92c6f,0x592b0275],[0x4a7484aa,0x6ea6e483],[0x5cb0a9dc,0xbd41fbd4],[0x76f988da,0x831153b5],[0x983e5152,0xee66dfab],[0xa831c66d,0x2db43210],[0xb00327c8,0x98fb213f],[0xbf597fc7,0xbeef0ee4],[0xc6e00bf3,0x3da88fc2],[0xd5a79147,0x930aa725],[0x06ca6351,0xe003826f],[0x14292967,0x0a0e6e70],[0x27b70a85,0x46d22ffc],[0x2e1b2138,0x5c26c926],[0x4d2c6dfc,0x5ac42aed],[0x53380d13,0x9d95b3df],[0x650a7354,0x8baf63de],[0x766a0abb,0x3c77b2a8],[0x81c2c92e,0x47edaee6],[0x92722c85,0x1482353b],[0xa2bfe8a1,0x4cf10364],[0xa81a664b,0xbc423001],[0xc24b8b70,0xd0f89791],[0xc76c51a3,0x0654be30],[0xd192e819,0xd6ef5218],[0xd6990624,0x5565a910],[0xf40e3585,0x5771202a],[0x106aa070,0x32bbd1b8],[0x19a4c116,0xb8d2d0c8],[0x1e376c08,0x5141ab53],[0x2748774c,0xdf8eeb99],[0x34b0bcb5,0xe19b48a8],[0x391c0cb3,0xc5c95a63],[0x4ed8aa4a,0xe3418acb],[0x5b9cca4f,0x7763e373],[0x682e6ff3,0xd6b2b8a3],[0x748f82ee,0x5defb2fc],[0x78a5636f,0x43172f60],[0x84c87814,0xa1f0ab72],[0x8cc70208,0x1a6439ec],[0x90befffa,0x23631e28],[0xa4506ceb,0xde82bde9],[0xbef9a3f7,0xb2c67915],[0xc67178f2,0xe372532b],[0xca273ece,0xea26619c],[0xd186b8c7,0x21c0c207],[0xeada7dd6,0xcde0eb1e],[0xf57d4f7f,0xee6ed178],[0x06f067aa,0x72176fba],[0x0a637dc5,0xa2c898a6],[0x113f9804,0xbef90dae],[0x1b710b35,0x131c471b],[0x28db77f5,0x23047d84],[0x32caab7b,0x40c72493],[0x3c9ebe0a,0x15c9bebc],[0x431d67c4,0x9c100d4c],[0x4cc5d4be,0xcb3e42b6],[0x597f299c,0xfc657e2a],[0x5fcb6fab,0x3ad6faec],[0x6c44198c,0x4a475817]];
    const a64 = (x,y)=>{ const lo=(x[1]>>>0)+(y[1]>>>0); const hi=(x[0]>>>0)+(y[0]>>>0)+(lo>0xffffffff?1:0); return [hi>>>0,lo>>>0]; };
    const r64 = (x,n)=>{ let hi,lo; if(n===32)return [x[1]>>>0,x[0]>>>0]; if(n<32){hi=((x[0]>>>n)|(x[1]<<(32-n)))>>>0;lo=((x[1]>>>n)|(x[0]<<(32-n)))>>>0;}else{const m=n-32;hi=((x[1]>>>m)|(x[0]<<(32-m)))>>>0;lo=((x[0]>>>m)|(x[1]<<(32-m)))>>>0;} return [hi,lo]; };
    const sr64 = (x,n)=>{ let hi,lo; if(n<32){hi=(x[0]>>>n)>>>0;lo=((x[1]>>>n)|(x[0]<<(32-n)))>>>0;}else{hi=0;lo=(x[0]>>>(n-32))>>>0;} return [hi,lo]; };
    const x64 = (a,b)=>[(a[0]^b[0])>>>0,(a[1]^b[1])>>>0];
    function sha512(bytes) {
      const ml = bytes.length, withPad = (((ml + 16) >> 7) + 1) << 7, b = new Uint8Array(withPad);
      b.set(bytes); b[ml] = 0x80; const dv = new DataView(b.buffer), bits = ml * 8;
      dv.setUint32(withPad - 8, Math.floor(bits / 0x100000000)); dv.setUint32(withPad - 4, bits >>> 0);
      let h = [[0x6a09e667,0xf3bcc908],[0xbb67ae85,0x84caa73b],[0x3c6ef372,0xfe94f82b],[0xa54ff53a,0x5f1d36f1],[0x510e527f,0xade682d1],[0x9b05688c,0x2b3e6c1f],[0x1f83d9ab,0xfb41bd6b],[0x5be0cd19,0x137e2179]].map(p=>p.slice());
      const w = new Array(80);
      for (let off = 0; off < withPad; off += 128) {
        for (let i = 0; i < 16; i++) w[i] = [dv.getUint32(off+i*8)>>>0, dv.getUint32(off+i*8+4)>>>0];
        for (let i = 16; i < 80; i++) {
          const s0 = x64(x64(r64(w[i-15],1),r64(w[i-15],8)),sr64(w[i-15],7));
          const s1 = x64(x64(r64(w[i-2],19),r64(w[i-2],61)),sr64(w[i-2],6));
          w[i] = a64(a64(a64(w[i-16],s0),w[i-7]),s1);
        }
        let A=h[0].slice(),B=h[1].slice(),Cc=h[2].slice(),D=h[3].slice(),E=h[4].slice(),Ff=h[5].slice(),Gg=h[6].slice(),Hh=h[7].slice();
        for (let i = 0; i < 80; i++) {
          const S1 = x64(x64(r64(E,14),r64(E,18)),r64(E,41));
          const ch = [((E[0]&Ff[0])^(~E[0]&Gg[0]))>>>0,((E[1]&Ff[1])^(~E[1]&Gg[1]))>>>0];
          const t1 = a64(a64(a64(a64(Hh,S1),ch),K512[i]),w[i]);
          const S0 = x64(x64(r64(A,28),r64(A,34)),r64(A,39));
          const maj = [((A[0]&B[0])^(A[0]&Cc[0])^(B[0]&Cc[0]))>>>0,((A[1]&B[1])^(A[1]&Cc[1])^(B[1]&Cc[1]))>>>0];
          const t2 = a64(S0,maj);
          Hh=Gg; Gg=Ff; Ff=E; E=a64(D,t1); D=Cc; Cc=B; B=A; A=a64(t1,t2);
        }
        h[0]=a64(h[0],A);h[1]=a64(h[1],B);h[2]=a64(h[2],Cc);h[3]=a64(h[3],D);h[4]=a64(h[4],E);h[5]=a64(h[5],Ff);h[6]=a64(h[6],Gg);h[7]=a64(h[7],Hh);
      }
      return h.map(p => hx(p[0]) + hx(p[1])).join('');
    }
    return { MD5: md5, 'SHA-1': sha1, 'SHA-256': sha256, 'SHA-512': sha512 };
  }
  const IMPL = hashImpls();
  K.hash = (algo, bytes) => IMPL[algo](bytes);
  K.ALGOS = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' };
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

  // قائمة موسّعة للبحث الجماعي (نمط CrackStation): الشائعة + أسماء/كلمات/أنماط متكرّرة في التحديات
  K.BIGLIST = [...new Set(K.COMMON.concat(('abc abcd abcde abcdef aaa aaaa aaaaa 11111 22222 00000 999999 123 1111 2222 passwd pass123 Password Password1 Password123 admin123 administrator1 welcome1 welcome123 qwerty12 qazwsxedc 1qazxsw2 zxcvbnm asdfghjkl 0987654321 abc12345 a1b2c3 123abc secret123 letmein1 iloveyou1 princess1 sunshine1 monkey123 dragon123 master123 ninja samurai hunter2 hunter123 freedom whatever1 computer internet server network database oracle postgres mysql root toor system public private administrator guest nobody operator manager support service backup default1 changeit keystore jenkins docker kubernetes nginx apache tomcat redis mongodb elastic kibana grafana prometheus terraform ansible vault consul gitlab github bitbucket jira confluence slack discord telegram signal whatsapp facebook instagram twitter youtube google amazon microsoft apple samsung huawei nokia xiaomi flag1 flag123 theflag getflag findme catchme youfoundme congrats congratulations winner solved done complete finish start begin level1 level2 stage1 round1 easypeasy toosimple weakpass nosecurity plaintext md5sum sha256sum rainbow collision preimage birthday salt pepper nonce token session cookie bearer jwt base encode decode cipher secret key public_key private_key passphrase mnemonic seed wallet bitcoin ethereum satoshi vitalik mallory alice bob carol dave eve trent oscar victor peggy chuck walter craig arthur merlin').split(' ')))];

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
      const o = e.data;
      let tried = 0; const t0 = Date.now(); let last = t0;
      const tick = (ex) => { const now = Date.now(); if (now - last > 250) { self.postMessage(Object.assign({ type: 'progress', tried, ms: now - t0 }, ex || {})); last = now; } };
      // بحث جماعي: عدّة أهداف دفعة واحدة مقابل القائمة وتحويراتها
      if (o.mode === 'many') {
        const needed = o.algos, sets = {}; let remaining = 0;
        for (const a of needed) { sets[a] = new Set(o.targets[a]); remaining += sets[a].size; }
        const found = {};
        outer: for (let i = 0; i < o.words.length; i++) {
          const gen = o.mutate ? mutate(o.words[i]) : [o.words[i]];
          for (const cand of gen) {
            const bytes = utf8(cand); tried++;
            for (const a of needed) {
              const s = sets[a]; if (!s.size) continue;
              const h = IMPL[a](bytes);
              if (s.has(h)) { found[h] = { plain: cand, algo: a }; s.delete(h); if (!--remaining) break outer; }
            }
            if ((tried & 4095) === 0) tick({ found: Object.keys(found).length, remaining });
          }
        }
        self.postMessage({ type: 'manydone', found, tried, ms: Date.now() - t0 });
        return;
      }
      const algo = o.algo, target = o.target, fn = IMPL[algo];
      let found = null;
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
  // بحث جماعي عن عدّة هاشات دفعة واحدة (نمط CrackStation)
  K.crackMany = (opts, onProgress) => {
    const items = (opts.hashes || []).map(r => {
      const raw = (r || '').trim(), h = raw.toLowerCase();
      const algo = /^[0-9a-f]+$/.test(h) ? K.algoFor(h) : null;
      return { raw, h, algo };
    }).filter(x => x.h);
    const targets = {}, algos = [];
    for (const it of items) {
      if (!it.algo) continue;
      if (!targets[it.algo]) { targets[it.algo] = new Set(); algos.push(it.algo); }
      targets[it.algo].add(it.h);
    }
    const words = [...new Set([...(opts.words || []), ...(opts.useCommon !== false ? K.BIGLIST : [])])];
    if (!algos.length) return Promise.resolve({ items, found: {}, tried: 0, ms: 0, unsupported: true });
    if (!words.length) return Promise.resolve({ items, error: 'لا توجد كلمات للبحث — فعّل القائمة المدمجة أو أضف كلمات.' });
    const targetsArr = {}; for (const a of algos) targetsArr[a] = [...targets[a]];
    return new Promise(resolve => {
      let w; try { w = new Worker(getWorkerURL()); } catch (e) { resolve({ items, error: 'تعذّر تشغيل العامل: ' + e.message }); return; }
      K._w = w;
      w.onmessage = e => {
        if (e.data.type === 'progress') { onProgress && onProgress(e.data); return; }
        w.terminate(); K._w = null; resolve(Object.assign({ items }, e.data));
      };
      w.onerror = e => { w.terminate(); K._w = null; resolve({ items, error: 'خطأ في العامل: ' + (e.message || '') }); };
      w.postMessage({ mode: 'many', algos, targets: targetsArr, words, mutate: !!opts.mutate });
    });
  };
  K.stop = () => { if (K._w) { K._w.terminate(); K._w = null; return true; } return false; };
  return K;
});
