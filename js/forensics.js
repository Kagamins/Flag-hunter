/* CTF Toolkit — file forensics (no DOM).
   Browser: window.CTFF   Node: module.exports
   Magic bytes, embedded-file scan, trailing data, PNG/JPEG/ZIP parsing,
   EXIF, strings, entropy, LSB extraction, FFT. */
(function (root, factory) {
  const C = (typeof module === 'object' && module.exports) ? require('./core.js') : root.CTF;
  const F = factory(C);
  if (typeof module === 'object' && module.exports) module.exports = F;
  else root.CTFF = F;
})(typeof self !== 'undefined' ? self : this, function (C) {
  'use strict';
  const F = {};
  const asc = s => Array.from(s, c => c.charCodeAt(0));
  const hx = h => C.fromHex(h);
  const eq = (b, pos, pat) => { if (pos < 0 || pos + pat.length > b.length) return false; for (let i = 0; i < pat.length; i++) if (b[pos + i] !== pat[i]) return false; return true; };
  const u32be = (b, p) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
  const u16le = (b, p) => b[p] | (b[p + 1] << 8);
  const u32le = (b, p) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
  F.u32be = u32be;

  /* ---------------- signatures ----------------
     pat: bytes at `off` from start; embed: include in embedded scan; test: extra check */
  F.SIGS = [
    { name: 'صورة PNG', ext: 'png', pat: hx('89504E470D0A1A0A'), embed: true },
    { name: 'صورة JPEG', ext: 'jpg', pat: hx('FFD8FF'), embed: true, test: (b, p) => b[p + 3] >= 0xC0 },
    { name: 'صورة GIF', ext: 'gif', pat: asc('GIF8'), embed: true, test: (b, p) => (b[p + 4] === 0x37 || b[p + 4] === 0x39) && b[p + 5] === 0x61 },
    { name: 'صورة BMP', ext: 'bmp', pat: asc('BM'), test: (b, p) => u32le(b, p + 2) === b.length - p || u32le(b, p + 14) === 40 },
    { name: 'صورة TIFF', ext: 'tif', pat: hx('49492A00') }, { name: 'صورة TIFF', ext: 'tif', pat: hx('4D4D002A') },
    { name: 'صورة WebP', ext: 'webp', pat: asc('RIFF'), embed: true, test: (b, p) => eq(b, p + 8, asc('WEBP')) },
    { name: 'صوت WAV', ext: 'wav', pat: asc('RIFF'), embed: true, test: (b, p) => eq(b, p + 8, asc('WAVE')) },
    { name: 'فيديو AVI', ext: 'avi', pat: asc('RIFF'), embed: true, test: (b, p) => eq(b, p + 8, asc('AVI ')) },
    { name: 'أيقونة ICO', ext: 'ico', pat: hx('00000100'), test: (b, p) => b[p + 4] > 0 && b[p + 5] === 0 && p === 0 },
    { name: 'ملف فوتوشوب PSD', ext: 'psd', pat: asc('8BPS'), embed: true },
    { name: 'مستند PDF', ext: 'pdf', pat: asc('%PDF-'), embed: true },
    { name: 'أرشيف ZIP (أو docx/xlsx/jar/apk)', ext: 'zip', pat: hx('504B0304'), embed: true },
    { name: 'أرشيف ZIP فارغ', ext: 'zip', pat: hx('504B0506') },
    { name: 'أرشيف RAR', ext: 'rar', pat: hx('526172211A07'), embed: true },
    { name: 'أرشيف 7-Zip', ext: '7z', pat: hx('377ABCAF271C'), embed: true },
    { name: 'ملف مضغوط GZIP', ext: 'gz', pat: hx('1F8B08'), embed: true },
    { name: 'ملف مضغوط BZIP2', ext: 'bz2', pat: asc('BZh'), embed: true, test: (b, p) => b[p + 3] >= 0x31 && b[p + 3] <= 0x39 && eq(b, p + 4, hx('314159265359')) },
    { name: 'ملف مضغوط XZ', ext: 'xz', pat: hx('FD377A585A00'), embed: true },
    { name: 'ملف مضغوط Zstandard', ext: 'zst', pat: hx('28B52FFD'), embed: true },
    { name: 'ملف مضغوط LZ4', ext: 'lz4', pat: hx('04224D18'), embed: true },
    { name: 'تيار zlib مضغوط', ext: 'zlib', pat: [0x78], test: (b, p) => p === 0 && [0x01, 0x5E, 0x9C, 0xDA].includes(b[1]) },
    { name: 'أرشيف TAR', ext: 'tar', pat: asc('ustar'), off: 257, embed: true },
    { name: 'صورة قرص ISO', ext: 'iso', pat: asc('CD001'), off: 32769 },
    { name: 'برنامج ELF (لينكس)', ext: 'elf', pat: hx('7F454C46'), embed: true },
    { name: 'برنامج ويندوز (.exe/.dll)', ext: 'exe', pat: asc('MZ'), embed: true, test: (b, p) => { const o = u32le(b, p + 0x3C); return o > 0 && o < 4096 && eq(b, p + o, hx('50450000')); } },
    { name: 'برنامج Mach-O (ماك)', ext: 'macho', pat: hx('CFFAEDFE'), embed: true }, { name: 'برنامج Mach-O (ماك)', ext: 'macho', pat: hx('FEEDFACF'), embed: true },
    { name: 'ملف Java class', ext: 'class', pat: hx('CAFEBABE'), embed: true },
    { name: 'ملف أندرويد DEX', ext: 'dex', pat: asc('dex\n'), embed: true },
    { name: 'WebAssembly', ext: 'wasm', pat: hx('0061736D'), embed: true },
    { name: 'ملف أوفيس قديم (doc/xls/ppt)', ext: 'doc', pat: hx('D0CF11E0A1B11AE1'), embed: true },
    { name: 'قاعدة بيانات SQLite', ext: 'sqlite', pat: asc('SQLite format 3\0'), embed: true },
    { name: 'التقاط شبكة PCAP', ext: 'pcap', pat: hx('D4C3B2A1'), embed: true }, { name: 'التقاط شبكة PCAP', ext: 'pcap', pat: hx('A1B2C3D4'), embed: true },
    { name: 'التقاط شبكة PCAPNG', ext: 'pcapng', pat: hx('0A0D0D0A'), test: (b, p) => eq(b, p + 8, hx('4D3C2B1A')) || eq(b, p + 8, hx('1A2B3C4D')) },
    { name: 'قاعدة كلمات سر KeePass', ext: 'kdbx', pat: hx('03D9A29A'), embed: true },
    { name: 'وسائط OGG', ext: 'ogg', pat: asc('OggS'), embed: true },
    { name: 'صوت FLAC', ext: 'flac', pat: asc('fLaC'), embed: true },
    { name: 'صوت MP3', ext: 'mp3', pat: asc('ID3'), embed: true, test: (b, p) => b[p + 3] >= 2 && b[p + 3] <= 4 },
    { name: 'صوت MP3', ext: 'mp3', pat: [0xFF], test: (b, p) => p === 0 && (b[1] & 0xE0) === 0xE0 && (b[1] & 0x06) !== 0 },
    { name: 'فيديو MP4/MOV', ext: 'mp4', pat: asc('ftyp'), off: 4, embed: true },
    { name: 'موسيقى MIDI', ext: 'mid', pat: asc('MThd'), embed: true },
    { name: 'مفتاح/شهادة PEM', ext: 'pem', pat: asc('-----BEGIN '), embed: true },
    { name: 'مفتاح OpenSSH خاص', ext: 'key', pat: asc('openssh-key-v1'), embed: true },
    { name: 'سكربت (shebang)', ext: 'sh', pat: asc('#!'), test: (b, p) => p === 0 },
    { name: 'بايت كود بايثون (.pyc)', ext: 'pyc', pat: [0x0D, 0x0D, 0x0A], off: 2, test: (b, p) => p === 0 },
    { name: 'مستند RTF', ext: 'rtf', pat: asc('{\\rtf'), embed: true },
    { name: 'مستند XML/SVG', ext: 'xml', pat: asc('<?xml'), embed: true },
    { name: 'نص UTF-8', ext: 'txt', pat: hx('EFBBBF') }, { name: 'نص UTF-16 LE', ext: 'txt', pat: hx('FFFE'), test: (b, p) => p === 0 }, { name: 'نص UTF-16 BE', ext: 'txt', pat: hx('FEFF'), test: (b, p) => p === 0 },
  ];
  F.SIGS.forEach(s => { s.off = s.off || 0; });

  F.identify = b => {
    const hits = [];
    for (const s of F.SIGS) if (eq(b, s.off, s.pat) && (!s.test || s.test(b, 0))) hits.push(s);
    if (!hits.length) {
      const head = C.latin1(b.subarray(0, 4096));
      if (b.length && C.printableRatio(head) > 0.95) hits.push({ name: 'نص عادي', ext: 'txt' });
      else if (b.length) hits.push({ name: 'بيانات خام / غير معروفة', ext: 'bin' });
    }
    return hits;
  };

  F.scanEmbedded = (b, max = 300) => {
    const byFirst = new Map();
    for (const s of F.SIGS) if (s.embed) { const k = s.pat[0]; if (!byFirst.has(k)) byFirst.set(k, []); byFirst.get(k).push(s); }
    const out = [];
    for (let i = 0; i < b.length && out.length < max; i++) {
      const list = byFirst.get(b[i]); if (!list) continue;
      for (const s of list) {
        const start = i - s.off; if (start <= 0) continue;
        if (eq(b, i, s.pat) && (!s.test || s.test(b, start))) { out.push({ offset: start, name: s.name, ext: s.ext }); break; }
      }
    }
    return out;
  };

  /* ---------------- format-specific ends ---------------- */
  F.pngChunks = b => {
    if (!eq(b, 0, hx('89504E470D0A1A0A'))) return null;
    const chunks = []; let p = 8, ihdr = null;
    while (p + 12 <= b.length) {
      const len = u32be(b, p), type = C.latin1(b.subarray(p + 4, p + 8));
      if (!/^[A-Za-z]{4}$/.test(type) || p + 12 + len > b.length) { chunks.push({ type: '(corrupt)', off: p, len: b.length - p, crcOk: false }); break; }
      const crc = u32be(b, p + 8 + len), calc = C.crc32(b, p + 4, p + 8 + len);
      const ch = { type, off: p, len, crcOk: crc === calc, crc, calc };
      if (type === 'IHDR') ihdr = { width: u32be(b, p + 8), height: u32be(b, p + 12), bitDepth: b[p + 16], colorType: b[p + 17], interlace: b[p + 20] };
      chunks.push(ch); p += 12 + len;
      if (type === 'IEND') break;
    }
    return { chunks, ihdr, end: p };
  };
  // brute-force IHDR width/height so CRC matches (classic "image cut off" challenge)
  F.pngFixDims = b => {
    const pc = F.pngChunks(b); if (!pc || !pc.ihdr) return null;
    const ih = pc.chunks.find(c => c.type === 'IHDR'); if (ih.crcOk) return { ok: true };
    const base = ih.off + 4, buf = b.slice(base, base + 17), target = ih.crc;
    const setWH = (w, h) => { buf[4] = w >>> 24; buf[5] = (w >>> 16) & 255; buf[6] = (w >>> 8) & 255; buf[7] = w & 255; buf[8] = h >>> 24; buf[9] = (h >>> 16) & 255; buf[10] = (h >>> 8) & 255; buf[11] = h & 255; };
    const W = pc.ihdr.width, H = pc.ihdr.height; let found = null;
    for (let h = 1; h <= 10000 && !found; h++) { setWH(W, h); if (C.crc32(buf) === target) found = [W, h]; }
    for (let w = 1; w <= 10000 && !found; w++) { setWH(w, H); if (C.crc32(buf) === target) found = [w, H]; }
    for (let w = 1; w <= 2000 && !found; w++) for (let h = 1; h <= 2000; h++) { setWH(w, h); if (C.crc32(buf) === target) { found = [w, h]; break; } }
    if (!found) return { ok: false };
    const fixed = b.slice(); setWH(found[0], found[1]); fixed.set(buf, base);
    return { ok: false, width: found[0], height: found[1], fixed };
  };

  F.jpegInfo = b => {
    if (!(b[0] === 0xFF && b[1] === 0xD8)) return null;
    let p = 2; const segs = [], comments = []; let exif = null, end = -1;
    while (p + 4 <= b.length) {
      if (b[p] !== 0xFF) break;
      const m = b[p + 1];
      if (m === 0xD9) { end = p + 2; break; }
      if (m === 0xFF) { p++; continue; }
      if (m >= 0xD0 && m <= 0xD7 || m === 0x01) { p += 2; continue; }
      const len = (b[p + 2] << 8) | b[p + 3];
      segs.push({ marker: 'FF' + m.toString(16).toUpperCase(), off: p, len });
      if (m === 0xFE) comments.push(C.bytesToText(b.subarray(p + 4, p + 2 + len)));
      if (m === 0xE1 && eq(b, p + 4, asc('Exif\0\0')) && !exif) exif = { start: p + 10, end: p + 2 + len };
      p += 2 + len;
      if (m === 0xDA) { // entropy-coded data: scan to next real marker
        while (p + 1 < b.length) { if (b[p] === 0xFF && b[p + 1] !== 0 && !(b[p + 1] >= 0xD0 && b[p + 1] <= 0xD7)) break; p++; }
      }
    }
    return { segs, comments, exif, end };
  };
  F.zipEnd = b => {
    for (let p = b.length - 22; p >= Math.max(0, b.length - 65557); p--) if (b[p] === 0x50 && eq(b, p, hx('504B0506'))) return p + 22 + u16le(b, p + 20);
    return -1;
  };
  F.trailing = b => {
    const id = F.identify(b)[0]; if (!id) return null; let end = -1;
    if (id.ext === 'png') end = F.pngChunks(b).end;
    else if (id.ext === 'jpg') end = F.jpegInfo(b).end;
    else if (id.ext === 'zip') end = F.zipEnd(b);
    else if (id.ext === 'pdf') { const s = C.latin1(b.subarray(Math.max(0, b.length - 1e6))); const i = s.lastIndexOf('%%EOF'); if (i >= 0) { end = b.length - s.length + i + 5; while (end < b.length && (b[end] === 10 || b[end] === 13)) end++; } }
    else if (id.ext === 'gif') { const i = b.lastIndexOf(0x3B); if (i > 0) end = i + 1; }
    if (end < 0 || end >= b.length) return { type: id.name, end, extra: 0 };
    return { type: id.name, end, extra: b.length - end };
  };

  /* ---------------- ZIP ---------------- */
  F.zipEntries = b => {
    const out = []; let p = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (eq(b, i, hx('504B0506'))) { p = i; break; }
    if (p >= 0) {
      let cd = u32le(b, p + 16); const n = u16le(b, p + 10);
      for (let k = 0; k < n && eq(b, cd, hx('504B0102')); k++) {
        const flags = u16le(b, cd + 8), method = u16le(b, cd + 10), csize = u32le(b, cd + 20), size = u32le(b, cd + 24);
        const nl = u16le(b, cd + 28), el = u16le(b, cd + 30), cl = u16le(b, cd + 32), lho = u32le(b, cd + 42);
        const name = C.bytesToText(b.subarray(cd + 46, cd + 46 + nl)), comment = C.bytesToText(b.subarray(cd + 46 + nl + el, cd + 46 + nl + el + cl));
        const dataOff = lho + 30 + u16le(b, lho + 26) + u16le(b, lho + 28);
        out.push({ name, method, csize, size, encrypted: !!(flags & 1), comment, dataOff, crc: u32le(b, cd + 16) });
        cd += 46 + nl + el + cl;
      }
      const zc = C.bytesToText(b.subarray(p + 22, p + 22 + u16le(b, p + 20)));
      out.comment = zc;
    } else { // no central directory: walk local headers
      for (let i = 0; i + 30 < b.length; ) {
        if (!eq(b, i, hx('504B0304'))) { i++; continue; }
        const flags = u16le(b, i + 6), method = u16le(b, i + 8), csize = u32le(b, i + 18), size = u32le(b, i + 22), nl = u16le(b, i + 26), el = u16le(b, i + 28);
        const name = C.bytesToText(b.subarray(i + 30, i + 30 + nl));
        out.push({ name, method, csize, size, encrypted: !!(flags & 1), dataOff: i + 30 + nl + el });
        i += 30 + nl + el + Math.max(csize, 0) || i + 4;
      }
    }
    return out;
  };
  F.inflate = async (bytes, fmt = 'deflate') => {
    const ds = new DecompressionStream(fmt);
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    const chunks = []; const reader = stream.getReader(); let total = 0;
    try { for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); total += value.length; if (total > 64e6) break; } }
    catch (e) { if (!total) throw e; }
    const out = new Uint8Array(total); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  };
  F.zipRead = async (b, e) => {
    if (e.encrypted) throw new Error('محمي بكلمة سر');
    const data = b.subarray(e.dataOff, e.dataOff + e.csize);
    if (e.method === 0) return data;
    if (e.method === 8) return F.inflate(data, 'deflate-raw');
    throw new Error('طريقة الضغط ' + e.method + ' غير مدعومة');
  };

  /* ---------------- PNG text chunks & EXIF ---------------- */
  F.pngText = async b => {
    const pc = F.pngChunks(b); if (!pc) return [];
    const out = [];
    for (const ch of pc.chunks) {
      const d = b.subarray(ch.off + 8, ch.off + 8 + ch.len);
      try {
        if (ch.type === 'tEXt') { const z = d.indexOf(0); out.push([C.latin1(d.subarray(0, z)), C.latin1(d.subarray(z + 1))]); }
        else if (ch.type === 'zTXt') { const z = d.indexOf(0); out.push([C.latin1(d.subarray(0, z)), C.bytesToText(await F.inflate(d.subarray(z + 2)))]); }
        else if (ch.type === 'iTXt') {
          const z = d.indexOf(0), key = C.latin1(d.subarray(0, z)), comp = d[z + 1];
          let p = z + 3; p = d.indexOf(0, p) + 1; p = d.indexOf(0, p) + 1;
          const body = d.subarray(p); out.push([key, comp ? C.bytesToText(await F.inflate(body)) : C.bytesToText(body)]);
        }
      } catch (e) { out.push([ch.type, '(تعذّر الفك: ' + e.message + ')']); }
    }
    return out;
  };
  const TAGS = { 0x010E: 'ImageDescription', 0x010F: 'Make', 0x0110: 'Model', 0x0112: 'Orientation', 0x0131: 'Software', 0x0132: 'DateTime', 0x013B: 'Artist', 0x8298: 'Copyright', 0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized', 0x9286: 'UserComment', 0x927C: 'MakerNote', 0xA420: 'ImageUniqueID', 0xA430: 'CameraOwnerName', 0xA431: 'BodySerialNumber', 0xA434: 'LensModel', 0x9C9B: 'XPTitle', 0x9C9C: 'XPComment', 0x9C9D: 'XPAuthor', 0x9C9E: 'XPKeywords', 0x9C9F: 'XPSubject', 0xA002: 'PixelWidth', 0xA003: 'PixelHeight', 0x0100: 'ImageWidth', 0x0101: 'ImageLength', 0x8769: 'ExifIFD', 0x8825: 'GPSIFD', 0xA005: 'InteropIFD', 0x0201: 'ThumbnailOffset', 0x0202: 'ThumbnailLength', 0x011A: 'XResolution', 0x011B: 'YResolution', 0x0128: 'ResolutionUnit', 0x0213: 'YCbCrPositioning', 0x829A: 'ExposureTime', 0x829D: 'FNumber', 0x8827: 'ISO', 0x920A: 'FocalLength', 0xA001: 'ColorSpace', 0x9000: 'ExifVersion' };
  const GPSTAGS = { 0: 'GPSVersionID', 1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude', 5: 'GPSAltitudeRef', 6: 'GPSAltitude', 7: 'GPSTimeStamp', 0x12: 'GPSMapDatum', 0x1D: 'GPSDateStamp' };
  F.parseTiff = (b, start, end) => {
    const t = b.subarray(start, end); if (t.length < 8) return null;
    const le = t[0] === 0x49; if (!le && t[0] !== 0x4D) return null;
    const r16 = p => le ? t[p] | (t[p + 1] << 8) : (t[p] << 8) | t[p + 1];
    const r32 = p => (le ? (t[p] | (t[p + 1] << 8) | (t[p + 2] << 16) | (t[p + 3] << 24)) : ((t[p] << 24) | (t[p + 1] << 16) | (t[p + 2] << 8) | t[p + 3])) >>> 0;
    const SZ = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8];
    const out = [], gpsRaw = {}, seen = new Set();
    const readIFD = (off, names, isGps, depth) => {
      if (!off || off + 2 > t.length || seen.has(off) || depth > 4) return; seen.add(off);
      const n = r16(off);
      for (let i = 0; i < n && off + 2 + i * 12 + 12 <= t.length; i++) {
        const e = off + 2 + i * 12, tag = r16(e), type = r16(e + 2), cnt = r32(e + 4);
        const size = (SZ[type] || 1) * cnt, vp = size <= 4 ? e + 8 : r32(e + 8);
        if (vp + size > t.length) continue;
        let val;
        if (type === 2) val = C.latin1(t.subarray(vp, vp + cnt)).replace(/\0+$/, '');
        else if (type === 3) val = Array.from({ length: Math.min(cnt, 16) }, (_, k) => r16(vp + k * 2));
        else if (type === 4 || type === 9) val = Array.from({ length: Math.min(cnt, 16) }, (_, k) => r32(vp + k * 4));
        else if (type === 5 || type === 10) val = Array.from({ length: Math.min(cnt, 16) }, (_, k) => { const d = r32(vp + k * 8 + 4); return d ? r32(vp + k * 8) / d : 0; });
        else if (type === 1 || type === 7) { const raw = t.subarray(vp, vp + Math.min(cnt, 4096)); val = (tag >= 0x9C9B && tag <= 0x9C9F) ? new TextDecoder('utf-16le').decode(raw).replace(/\0+$/, '') : (tag === 0x9286 ? C.latin1(raw.subarray(8)).replace(/\0+$/, '') : (C.printableRatio(C.latin1(raw)) > 0.8 ? C.latin1(raw).replace(/\0+$/, '') : C.toHex(raw.subarray(0, 32), ' ') + (raw.length > 32 ? ' …' : ''))); }
        else continue;
        if (Array.isArray(val) && val.length === 1) val = val[0];
        const name = (isGps ? GPSTAGS : TAGS)[tag] || ('Tag 0x' + tag.toString(16).padStart(4, '0'));
        if (!isGps && (tag === 0x8769 || tag === 0xA005)) { readIFD(val, names, false, depth + 1); continue; }
        if (!isGps && tag === 0x8825) { readIFD(val, names, true, depth + 1); continue; }
        if (isGps) gpsRaw[name] = val;
        if (tag === 0x927C) continue; // MakerNote is noisy
        out.push([name, Array.isArray(val) ? val.map(v => typeof v === 'number' ? +v.toFixed(6) : v).join(', ') : String(val)]);
      }
      if (depth === 0) { const nxt = r32(off + 2 + n * 12); if (nxt && nxt < t.length) readIFD(nxt, names, false, depth + 1); }
    };
    readIFD(r32(4), null, false, 0);
    let gps = null;
    const dms = v => Array.isArray(v) ? v[0] + (v[1] || 0) / 60 + (v[2] || 0) / 3600 : v;
    if (gpsRaw.GPSLatitude != null && gpsRaw.GPSLongitude != null) {
      let lat = dms(gpsRaw.GPSLatitude), lon = dms(gpsRaw.GPSLongitude);
      if (gpsRaw.GPSLatitudeRef === 'S') lat = -lat; if (gpsRaw.GPSLongitudeRef === 'W') lon = -lon;
      gps = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
    }
    return { tags: out, gps };
  };
  F.exif = b => {
    const j = F.jpegInfo(b);
    if (j && j.exif) return F.parseTiff(b, j.exif.start, j.exif.end);
    const pc = F.pngChunks(b);
    if (pc) { const ex = pc.chunks.find(c => c.type === 'eXIf'); if (ex) return F.parseTiff(b, ex.off + 8, ex.off + 8 + ex.len); }
    const id = F.identify(b)[0];
    if (id && id.ext === 'tif') return F.parseTiff(b, 0, b.length);
    return null;
  };

  /* ---------------- strings / entropy ---------------- */
  F.strings = (b, min = 4, utf16 = true, max = 20000) => {
    const out = []; let cur = '', start = 0;
    for (let i = 0; i < b.length && out.length < max; i++) {
      const c = b[i];
      if ((c >= 32 && c < 127) || c === 9) { if (!cur) start = i; cur += String.fromCharCode(c); }
      else { if (cur.length >= min) out.push({ off: start, s: cur, enc: 'ascii' }); cur = ''; }
    }
    if (cur.length >= min && out.length < max) out.push({ off: start, s: cur, enc: 'ascii' });
    if (utf16) for (const par of [0, 1]) {
      cur = '';
      for (let i = par; i + 1 < b.length && out.length < max; i += 2) {
        const c = b[i], z = b[i + 1];
        if (z === 0 && ((c >= 32 && c < 127) || c === 9)) { if (!cur) start = i; cur += String.fromCharCode(c); }
        else { if (cur.length >= min) out.push({ off: start, s: cur, enc: 'utf16le' }); cur = ''; }
      }
      if (cur.length >= min) out.push({ off: start, s: cur, enc: 'utf16le' });
    }
    return out.sort((a, b2) => a.off - b2.off);
  };
  F.entropy = (b, s = 0, e = b.length) => {
    const n = e - s; if (n <= 0) return 0;
    const cnt = new Uint32Array(256); for (let i = s; i < e; i++) cnt[b[i]]++;
    let h = 0; for (const c of cnt) if (c) { const p = c / n; h -= p * Math.log2(p); }
    return h;
  };
  F.entropyBlocks = (b, blocks = 64) => {
    const size = Math.max(1, Math.ceil(b.length / blocks)), out = [];
    for (let s = 0; s < b.length; s += size) out.push({ off: s, h: F.entropy(b, s, Math.min(b.length, s + size)) });
    return out;
  };

  /* ---------------- image LSB ---------------- */
  // data: RGBA Uint8ClampedArray, w,h. channels e.g. 'RGB'. order 'row'|'col'. msbFirst packs bits MSB first.
  F.lsbExtract = (data, w, h, { channels = 'RGB', bit = 0, order = 'row', msbFirst = true, maxBytes = 1 << 20 } = {}) => {
    const idx = Array.from(channels, c => 'RGBA'.indexOf(c));
    const out = new Uint8Array(Math.min(maxBytes, Math.ceil(w * h * idx.length / 8)));
    let byte = 0, nb = 0, o = 0;
    const total = w * h;
    for (let k = 0; k < total && o < out.length; k++) {
      const x = order === 'row' ? k % w : Math.floor(k / h), y = order === 'row' ? Math.floor(k / w) : k % h;
      const p = (y * w + x) * 4;
      for (const ci of idx) {
        const v = (data[p + ci] >> bit) & 1;
        byte = msbFirst ? (byte << 1) | v : byte | (v << nb);
        if (++nb === 8) { out[o++] = byte & 255; byte = 0; nb = 0; if (o >= out.length) break; }
      }
    }
    return out.subarray(0, o);
  };
  F.lsbAutoCombos = () => {
    const r = [];
    for (const channels of ['RGB', 'RGBA', 'BGR', 'R', 'G', 'B', 'A']) for (const bit of [0, 1]) for (const msbFirst of [true, false]) for (const order of ['row', 'col']) r.push({ channels, bit, msbFirst, order });
    return r;
  };

  /* ---------------- FFT (for spectrograms) ---------------- */
  F.fft = (re, im) => {
    const n = re.length;
    for (let i = 1, j = 0; i < n; i++) { let bit = n >> 1; for (; j & bit; bit >>= 1) j ^= bit; j ^= bit; if (i < j) { [re[i], re[j]] = [re[j], re[i]];[im[i], im[j]] = [im[j], im[i]]; } }
    for (let len = 2; len <= n; len <<= 1) {
      const ang = -2 * Math.PI / len, wr = Math.cos(ang), wi = Math.sin(ang);
      for (let i = 0; i < n; i += len) {
        let cr = 1, ci = 0;
        for (let j = 0; j < len / 2; j++) {
          const ar = re[i + j], ai = im[i + j], br = re[i + j + len / 2] * cr - im[i + j + len / 2] * ci, bi = re[i + j + len / 2] * ci + im[i + j + len / 2] * cr;
          re[i + j] = ar + br; im[i + j] = ai + bi; re[i + j + len / 2] = ar - br; im[i + j + len / 2] = ai - bi;
          const t = cr * wr - ci * wi; ci = cr * wi + ci * wr; cr = t;
        }
      }
    }
  };


  /* ---------------- exact PNG decoder (keeps raw RGB under transparent pixels) ---------------- */
  F.decodePNG = async b => {
    const pc = F.pngChunks(b); if (!pc || !pc.ihdr) return null;
    const { width: w, height: h, bitDepth: bd, colorType: ct, interlace } = pc.ihdr;
    if (interlace || bd !== 8 || ![0, 2, 3, 4, 6].includes(ct) || w * h > 40e6) return null;
    const parts = pc.chunks.filter(c => c.type === 'IDAT'); let tot = 0; parts.forEach(c => tot += c.len);
    const idat = new Uint8Array(tot); let o = 0; for (const c of parts) { idat.set(b.subarray(c.off + 8, c.off + 8 + c.len), o); o += c.len; }
    let raw; try { raw = await F.inflate(idat, 'deflate'); } catch (e) { return null; }
    const ch = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[ct], stride = w * ch;
    let pal = null, trns = null;
    const pl = pc.chunks.find(c => c.type === 'PLTE'); if (pl) pal = b.subarray(pl.off + 8, pl.off + 8 + pl.len);
    const tr = pc.chunks.find(c => c.type === 'tRNS'); if (tr) trns = b.subarray(tr.off + 8, tr.off + 8 + tr.len);
    const out = new Uint8ClampedArray(w * h * 4); let prev = new Uint8Array(stride), cur = new Uint8Array(stride); let rows = 0;
    for (let y = 0; y < h; y++) {
      const base = y * (stride + 1); if (base + stride + 1 > raw.length) break;
      const ft = raw[base];
      for (let i = 0; i < stride; i++) {
        const x = raw[base + 1 + i], a = i >= ch ? cur[i - ch] : 0, bb = prev[i], c = i >= ch ? prev[i - ch] : 0;
        let v;
        if (ft === 0) v = x; else if (ft === 1) v = x + a; else if (ft === 2) v = x + bb; else if (ft === 3) v = x + ((a + bb) >> 1);
        else { const p = a + bb - c, pa = Math.abs(p - a), pb = Math.abs(p - bb), pcc = Math.abs(p - c); v = x + (pa <= pb && pa <= pcc ? a : pb <= pcc ? bb : c); }
        cur[i] = v & 255;
      }
      for (let x = 0; x < w; x++) {
        const q = (y * w + x) * 4, s0 = x * ch;
        if (ct === 6) { out[q] = cur[s0]; out[q + 1] = cur[s0 + 1]; out[q + 2] = cur[s0 + 2]; out[q + 3] = cur[s0 + 3]; }
        else if (ct === 2) { out[q] = cur[s0]; out[q + 1] = cur[s0 + 1]; out[q + 2] = cur[s0 + 2]; out[q + 3] = 255; }
        else if (ct === 0) { out[q] = out[q + 1] = out[q + 2] = cur[s0]; out[q + 3] = 255; }
        else if (ct === 4) { out[q] = out[q + 1] = out[q + 2] = cur[s0]; out[q + 3] = cur[s0 + 1]; }
        else { const k = cur[s0]; if (pal) { out[q] = pal[k * 3]; out[q + 1] = pal[k * 3 + 1]; out[q + 2] = pal[k * 3 + 2]; } out[q + 3] = trns && k < trns.length ? trns[k] : 255; }
      }
      const t = prev; prev = cur; cur = t; rows++;
    }
    return { data: out, width: w, height: h, rowsDecoded: rows, colorType: ct };
  };

  F.hexdump = (b, start = 0, len = 512) => {
    const lines = [];
    for (let p = start; p < Math.min(b.length, start + len); p += 16) {
      const row = b.subarray(p, Math.min(p + 16, b.length));
      const hex = Array.from(row, x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
      const asc2 = Array.from(row, x => (x >= 32 && x < 127 ? String.fromCharCode(x) : '.')).join('');
      lines.push(p.toString(16).padStart(8, '0') + '  ' + hex + '  ' + asc2);
    }
    return lines.join('\n');
  };

  return F;
});
