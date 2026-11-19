/* صائد الأعلام — واجهة الأدوات */
(function () {
  'use strict';
  const C = window.CTF, F = window.CTFF, G = window.GAME, W = window.CTFW, JF = window.CTFJ, KR = window.CTFK, PY = window.CTFP;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  // إظهار الحروف الخفية حتى يظهر الإخفاء بالمسافات والحروف صفرية العرض
  const vis = s => esc(s).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏⁠﻿]/g, c => '<span class="np" title="U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + '">·</span>');
  const fmtSize = n => n < 1024 ? n + ' بايت' : n < 1048576 ? (n / 1024).toFixed(1) + ' كيلوبايت' : (n / 1048576).toFixed(2) + ' ميغابايت';
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const tick = () => new Promise(r => setTimeout(r, 0));
  const ms = t0 => Math.round(performance.now() - t0);

  /* ---------- نسخ وتنزيل ---------- */
  const store = new Map(); let sid = 0;
  const keep = v => { const id = 'c' + (++sid); store.set(id, v); return id; };
  const copyBtn = (text, label = '📋 نسخ') => `<button class="small" data-cid="${keep(text)}">${label}</button>`;
  const dlBtn = (name, bytes, label = '⬇️ تنزيل') => `<button class="small" data-dl="${keep({ name, bytes })}">${label}</button>`;
  const anBtn = (name, bytes, label = '🔍 حلّل') => `<button class="small" data-an="${keep({ name, bytes })}">${label}</button>`;
  const toast = msg => G.toast(msg);
  function copy(v) {
    const fallback = () => { const ta = document.createElement('textarea'); ta.value = v; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) { } ta.remove(); toast('تم النسخ ✅'); };
    if (navigator.clipboard) navigator.clipboard.writeText(v).then(() => toast('تم النسخ ✅'), fallback); else fallback();
  }
  // داخل صفحة Claude نستخدم قدرة التنزيل، وعلى GitHub Pages رابط تنزيل عادي
  let dlCap; const inClaude = !!(window.claude && typeof window.claude.use === 'function');
  if (inClaude) window.claude.use('downloads').then(d => { dlCap = d; }).catch(() => { dlCap = null; });
  const ALLOWED = /\.(gif|png|jpg|jpeg|webp|mp4|webm|mov|txt|json|md|docx|pptx|epub|csv|ttf|html|svg|pdf|xlsx|zip)$/i;
  async function download(name, bytes) {
    if (inClaude) {
      if (!dlCap) { toast('التنزيل غير متاح هنا — استخدم زر «حلّل»'); return; }
      if (!ALLOWED.test(name)) { toast('هذه الصيغة لا تُنزَّل من هنا — استخدم «حلّل» أو نسخة GitHub'); return; }
      try { await dlCap.save({ filename: name, data: new Blob([bytes]) }); } catch (e) { if (e && e.code !== 'declined') toast('تعذّر التنزيل: ' + (e.message || e.code)); }
      return;
    }
    const u = URL.createObjectURL(new Blob([bytes])); const a = document.createElement('a'); a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 5000);
  }
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-cid]'); if (b) { copy(store.get(b.dataset.cid)); return; }
    const d = e.target.closest('[data-dl]'); if (d) { const v = store.get(d.dataset.dl); download(v.name, v.bytes); return; }
    const a = e.target.closest('[data-an]'); if (a) { const v = store.get(a.dataset.an); openBytes(v.name, v.bytes); return; }
    const c = e.target.closest('[data-clear]'); if (c) { const ta = document.getElementById(c.dataset.clear); ta.value = ''; ta.dispatchEvent(new Event('input')); ta.focus(); return; }
    const s = e.target.closest('[data-send]'); if (s) sendTo(s.dataset.send, store.get(s.dataset.val));
    const cp = e.target.closest('.cp'); if (cp) { copy(cp.textContent.trim()); }
  });

  /* ---------- التبويبات ---------- */
  const TABS = ['scan', 'decode', 'cipher', 'file', 'hash', 'web', 'python', 'modexp', 'train', 'cheat'];
  const TABNAME = { decode: 'فك الترميز', cipher: 'الشيفرات', hash: 'الهاش', scan: 'الفحص', file: 'التحليل', web: 'الويب' };
  function showTab(id) {
    if (!TABS.includes(id)) id = 'scan';
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    $$('.panel').forEach(p => p.classList.toggle('active', p.id === id));
    if (location.hash !== '#' + id) history.replaceState(null, '', '#' + id);
    G.useTool(id);
    if (id === 'train') G.renderMissions();
  }
  $$('#tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
  document.addEventListener('keydown', e => {
    if (e.altKey && e.key >= '1' && e.key <= '9') { e.preventDefault(); showTab(TABS[+e.key - 1]); }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const id = $('.panel.active').id; e.preventDefault();
      ({ scan: () => scanText(true), decode: runMagic, cipher: runAllCiphers, web: runWeb, python: () => pyRun() })[id]?.();
    }
  });
  function sendTo(tab, text) {
    const map = { decode: 'decIn', cipher: 'ciIn', hash: 'hiIn', scan: 'scanText', web: 'wbIn' };
    const el = document.getElementById(map[tab]); if (!el) return;
    el.value = text; showTab(tab); el.dispatchEvent(new Event('input'));
    if (tab === 'decode') runMagic(); if (tab === 'cipher') runAllCiphers(); if (tab === 'web') runWeb();
    window.scrollTo(0, 0);
  }
  function setField(id, val, tab) { showTab(tab); const el = document.getElementById(id); el.value = val; el.dispatchEvent(new Event('input')); el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.focus(); }
  function fillRSA(r) { showTab('hash'); $('#rsP').value = r.p; $('#rsQ').value = r.q; $('#rsE').value = r.e; $('#rsC').value = r.c; $('#rsN').value = ''; $('#rsD').value = ''; $('#rsBtn').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  function openBytes(name, bytes) { showTab('file'); currentFile = { name, bytes, mime: '' }; triageBytes(name, bytes, ''); window.scrollTo(0, 0); }
  const sendBtn = (tab, text, label) => `<button class="small" data-send="${tab}" data-val="${keep(text)}">${label}</button>`;

  /* ---------- إعدادات صيغة العلم ---------- */
  const SKEY = 'ctfkit.settings';
  try { Object.assign(C.settings, JSON.parse(localStorage.getItem(SKEY) || '{}')); } catch (e) { }
  $('#flagPrefix').value = C.settings.prefix || ''; $('#flagRegex').value = C.settings.regex || ''; $('#flagCase').checked = C.settings.caseInsensitive !== false;
  const saveSettings = debounce(() => {
    C.settings.prefix = $('#flagPrefix').value.trim().replace(/\{.*$/, '');
    C.settings.regex = $('#flagRegex').value.trim(); C.settings.caseInsensitive = $('#flagCase').checked;
    if (C.settings.regex) { try { new RegExp(C.settings.regex); $('#flagRegex').style.borderColor = ''; } catch (e) { $('#flagRegex').style.borderColor = 'var(--bad)'; } }
    try { localStorage.setItem(SKEY, JSON.stringify(C.settings)); } catch (e) { }
    if ($('#scanText').value.trim()) scanText(true);
  }, 300);
  ['#flagPrefix', '#flagRegex'].forEach(s => $(s).addEventListener('input', saveSettings)); $('#flagCase').addEventListener('change', saveSettings);

  /* ---------- عناصر عرض مشتركة ---------- */
  function renderFlags(flags, title = '🚩 أعلام محتملة') {
    if (!flags.length) return '';
    G.onFlags(flags);
    return `<div class="flags"><h2>${title} (${flags.length})</h2>` + flags.map(f => `<div class="flagrow ${f.likely === false ? 'unlikely' : ''}"><code>${vis(f.flag)}</code>${copyBtn(f.flag)}<span class="how">${esc(f.method)}</span></div>`).join('') + `</div>`;
  }
  const resRow = (label, text, hit, extra = '') => `<div class="res ${hit ? 'hit' : ''}"><div class="lbl">${esc(label)}</div><pre>${vis(C.preview(text, 3000))}</pre><div>${copyBtn(text)}${extra}</div></div>`;
  function setupDrop(zone, cb) {
    const inp = $('input[type=file]', zone);
    zone.addEventListener('click', () => inp.click());
    inp.addEventListener('change', () => { if (inp.files[0]) cb(inp.files[0]); inp.value = ''; });
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('over'));
    zone.addEventListener('drop', e => { e.preventDefault(); e.stopPropagation(); zone.classList.remove('over'); if (e.dataTransfer.files[0]) cb(e.dataTransfer.files[0]); });
  }
  document.addEventListener('dragover', e => e.preventDefault());
  document.addEventListener('drop', e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (!f) return; if ($('.panel.active').id === 'file') triageFile(f); else { showTab('scan'); scanFile(f); } });
  document.addEventListener('paste', e => { const f = e.clipboardData && e.clipboardData.files && e.clipboardData.files[0]; if (f) { e.preventDefault(); if ($('.panel.active').id === 'file') triageFile(f); else { showTab('scan'); scanFile(f); } } });

  /* ================= الفحص السريع ================= */
  function scanText(force) {
    const t = $('#scanText').value, out = $('#scanOut');
    if (!t.trim()) { out.innerHTML = ''; return; }
    if (!force && !$('#scanAuto').checked) return;
    const t0 = performance.now();
    const deep = C.deepFlagSearch(t), ident = C.identify(t);
    const magic = t.length <= 20000 ? C.magic(t.trim(), { depth: 6, maxNodes: 1500 }) : null;
    let h = renderFlags(deep.flags);
    if (!deep.flags.length && !JF.isJSFuck(t)) h += `<div class="noflag">🕵️ لم نجد صيغة علم${C.settings.prefix ? ' لـ <code>' + esc(C.settings.prefix) + '{…}</code>' : ''} بعد. انظر إلى التعرّف وعمليات الفك بالأسفل.</div>`;
    if (deep.hints.length) h += `<div class="card"><h3>👀 لمحنا بادئة علم مرمّزة!</h3>` + deep.hints.map(x => `<div>تبدو مثل <b dir="ltr">${esc(x.prefix)}{</b> مرمّزة بـ <span class="tag">${esc(x.encoding)}</span> عند الموضع ${x.offset}: <code>${esc(x.sig)}</code></div>`).join('') + `<div class="muted small-t">خذ البيانات حول هذا الموضع وفكّها في تبويب فك الترميز.</div></div>`;
    if (ident.length) h += `<div class="card"><h3>🔬 ماذا يشبه هذا؟</h3><ul class="idlist">` + ident.map(i => `<li><b>${esc(i.kind)}</b> <span class="muted">${vis(i.detail)}</span> ${sendBtn(i.tool, t.trim(), 'افتح في ' + (TABNAME[i.tool] || ''))}</li>`).join('') + `</ul></div>`;
    if (magic && magic.outputs.length) h += `<div class="card"><h3>✨ أفضل عمليات الفك التلقائي</h3>` + magic.outputs.slice(0, 6).map(o => resRow(o.chain.join(' → '), o.s, C.findFlags(o.s).length, sendBtn('decode', o.s, 'تابِع ←'))).join('') + `</div>`;
    h += `<div class="status">⏱️ فُحص ${t.length.toLocaleString('ar')} حرف في ${ms(t0)} ملّي ثانية</div>`;
    if (JF.isJSFuck(t)) h = `<div id="scanJsf"><div class="card"><span class="spinner"></span> 🤡 هذا JSFuck — نفكّه بأمان…</div></div>` + h;
    out.innerHTML = h;
    if (JF.isJSFuck(t)) jsfDecode(t).then(r => { const el = $('#scanJsf'); if (el && $('#scanText').value === t) el.innerHTML = jsfRender(r, true); });
  }
  $('#scanText').addEventListener('input', debounce(() => scanText(false), 350));
  $('#scanBtn').addEventListener('click', () => scanText(true));
  setupDrop($('#scanDrop'), f => scanFile(f));

  const readFile = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(new Uint8Array(r.result)); r.onerror = rej; r.readAsArrayBuffer(f); });
  let currentFile = null;

  async function getPixels(bytes, mime) {
    const id = F.identify(bytes)[0];
    if (id && id.ext === 'png') { const p = await F.decodePNG(bytes); if (p && p.rowsDecoded) return { data: p.data, width: p.width, height: p.rowsDecoded, exact: true }; }
    if (!id || !['png', 'jpg', 'gif', 'bmp', 'webp', 'ico', 'tif'].includes(id.ext)) return null;
    try {
      const bmp = await createImageBitmap(new Blob([bytes], { type: mime || 'image/' + id.ext }), { premultiplyAlpha: 'none', colorSpaceConversion: 'none' });
      const cv = document.createElement('canvas'); cv.width = bmp.width; cv.height = bmp.height;
      const ctx = cv.getContext('2d', { willReadFrequently: true }); ctx.drawImage(bmp, 0, 0);
      return { data: ctx.getImageData(0, 0, bmp.width, bmp.height).data, width: bmp.width, height: bmp.height, exact: id.ext === 'bmp' || id.ext === 'gif' };
    } catch (e) { return null; }
  }

  /* البحث عن كل الأعلام داخل ملف — يستخدمه الفحص السريع والتحليل الكامل */
  async function fileFlags(name, bytes, mime, depth = 0) {
    const flags = [], notes = [], seen = new Set();
    const add = (list, where) => list.forEach(f => { if (seen.has(f.flag)) return; seen.add(f.flag); flags.push({ flag: f.flag, method: where + (f.method && f.method !== 'نص مباشر' ? ' · ' + f.method : ''), likely: f.likely }); });
    const text = C.latin1(bytes);
    add(C.deepFlagSearch(text, { maxTokens: 300 }).flags, 'بايتات الملف');
    const u16 = F.strings(bytes, 4, true).filter(s => s.enc === 'utf16le').map(s => s.s).join('\n');
    if (u16) add(C.deepFlagSearch(u16).flags, 'نصوص UTF-16');
    const ex = F.exif(bytes);
    if (ex && ex.tags.length) add(C.deepFlagSearch(ex.tags.map(t => t[1]).join('\n')).flags, 'بيانات EXIF');
    if (F.pngChunks(bytes)) { const tx = await F.pngText(bytes); if (tx.length) add(C.deepFlagSearch(tx.map(t => t[0] + ': ' + t[1]).join('\n')).flags, 'مقطع نص PNG'); }
    const jp = F.jpegInfo(bytes); if (jp && jp.comments.length) add(C.deepFlagSearch(jp.comments.join('\n')).flags, 'تعليق JPEG');
    const tr = F.trailing(bytes);
    if (tr && tr.extra > 0) {
      const tb = bytes.subarray(tr.end); notes.push(`${fmtSize(tr.extra)} من البيانات بعد نهاية ${tr.type}`);
      add(C.deepFlagSearch(C.latin1(tb)).flags, 'بيانات بعد النهاية');
      if (depth < 2) { const sub = await fileFlags(name + '.trailing', tb, '', depth + 1); add(sub.flags, 'بيانات بعد النهاية'); notes.push(...sub.notes.map(n => 'بعد النهاية: ' + n)); }
    }
    const id = F.identify(bytes)[0];
    if (id && id.ext === 'zip' && depth < 2) {
      const ents = F.zipEntries(bytes);
      if (ents.comment) add(C.deepFlagSearch(ents.comment).flags, 'تعليق ZIP');
      for (const e of ents.slice(0, 200)) {
        add(C.deepFlagSearch(e.name + '\n' + (e.comment || '')).flags, 'اسم ملف في ZIP');
        if (e.encrypted) { notes.push(`🔒 الملف "${e.name}" محمي بكلمة سر`); continue; }
        if (e.size > 30e6) continue;
        try { const d = await F.zipRead(bytes, e); const sub = await fileFlags(e.name, d, '', depth + 1); add(sub.flags, 'داخل ZIP › ' + e.name); } catch (err) { notes.push(`تعذّر استخراج "${e.name}": ${err.message}`); }
      }
    }
    if (id && id.ext === 'gz' && depth < 2) { try { const d = await F.inflate(bytes, 'gzip'); notes.push('تم فك ضغط GZIP إلى ' + fmtSize(d.length)); add((await fileFlags(name.replace(/\.gz$/, ''), d, '', depth + 1)).flags, 'داخل GZIP'); } catch (e) { } }
    if (id && id.ext === 'zlib' && depth < 2) { try { const d = await F.inflate(bytes, 'deflate'); add((await fileFlags(name, d, '', depth + 1)).flags, 'داخل zlib'); } catch (e) { } }
    const emb = F.scanEmbedded(bytes, 50).filter(x => !(tr && tr.extra > 0 && x.offset >= tr.end));
    if (emb.length) notes.push(`${emb.length} توقيع ملف مضمّن: ` + [...new Set(emb.map(x => x.name))].join('، '));
    if (depth < 1) for (const x of emb.filter(x => x.ext === 'zip').slice(0, 1)) { const sub = await fileFlags('embedded.zip', bytes.subarray(x.offset), '', depth + 1); add(sub.flags, 'ZIP مضمّن @' + x.offset); }
    if (depth < 2) {
      const px = await getPixels(bytes, mime);
      if (px) {
        for (const combo of F.lsbAutoCombos()) {
          const outb = F.lsbExtract(px.data, px.width, px.height, { ...combo, maxBytes: 8192 });
          const s = C.latin1(outb);
          const fl = C.findFlags(s).concat(C.findFlags(s, true)).filter(f => C.printableRatio(f) > 0.95);
          const label = `LSB ${combo.channels} bit ${combo.bit}, ${combo.order === 'row' ? 'rows' : 'cols'}, ${combo.msbFirst ? 'MSB' : 'LSB'}-first`;
          fl.forEach(f => add([{ flag: f, method: label, likely: true }], 'الصورة'));
          if (!fl.length) { const dm = C.deepFlagSearch(s.slice(0, 2048).replace(/[^\x20-\x7e\n]+.*$/s, ''), { maxTokens: 5 }); dm.flags.forEach(f => add([{ ...f, method: label + ' · ' + f.method }], 'الصورة')); }
          const hid = F.identify(outb)[0]; if (hid && !['txt', 'bin', 'zlib', 'mp3', 'ico', 'sh', 'pyc'].includes(hid.ext)) notes.push(`${label} يبدأ بتوقيع ${hid.name} — استخرجه في تحليل الملفات`);
        }
        if (!px.exact) notes.push('فكّ المتصفح الصورة بنفسه — قيم LSB للصور المضغوطة أو الشفافة قد تكون تقريبية');
      }
    }
    return { flags, notes };
  }
  const sameExt = (a, b) => { const g = [['jpg', 'jpeg', 'jfif'], ['tif', 'tiff'], ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt', 'ods', 'epub', 'xpi', 'whl', 'ipa', 'kmz'], ['doc', 'xls', 'ppt', 'msg', 'msi'], ['mp4', 'mov', 'm4a', 'm4v', '3gp', 'heic', 'avif'], ['exe', 'dll', 'sys', 'scr'], ['xml', 'svg', 'html', 'xhtml', 'plist'], ['txt', 'md', 'log', 'csv'], ['gz', 'tgz'], ['pem', 'crt', 'key', 'cer'], ['sqlite', 'db', 'sqlite3'], ['class', 'macho'], ['elf', 'so', 'o', 'bin'], ['mp3', 'mp2'], ['pcap', 'cap', 'dmp'], ['ogg', 'oga', 'ogv', 'opus']]; return a === b || g.some(x => x.includes(a) && x.includes(b)); };

  async function scanFile(file) {
    const out = $('#scanOut');
    out.innerHTML = `<div class="card"><span class="spinner"></span> جارٍ فحص <b>${esc(file.name)}</b> (${fmtSize(file.size)})…</div>`;
    const bytes = await readFile(file); currentFile = { name: file.name, bytes, mime: file.type };
    const t0 = performance.now(); await tick();
    const ids = F.identify(bytes), r = await fileFlags(file.name, bytes, file.type);
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const mismatch = ids[0] && ids[0].ext !== 'txt' && ids[0].ext !== 'bin' && ext && !sameExt(ext, ids[0].ext);
    let h = renderFlags(r.flags);
    if (!r.flags.length) h += `<div class="noflag">🕵️ لم نجد علماً تلقائياً. افتح التحليل الكامل لطبقات البتات والنصوص وعرض Hex والاستخراج.</div>`;
    h += `<div class="card"><h3>📄 ${esc(file.name)} · ${fmtSize(bytes.length)}</h3>
      <div>النوع المكتشف: ${ids.map(i => `<span class="tag">${esc(i.name)}</span>`).join('')} ${mismatch ? `<span class="tag bad">الامتداد .${esc(ext)} لا يطابق النوع الحقيقي!</span>` : ''}</div>
      <div>الإنتروبيا: ${F.entropy(bytes).toFixed(2)} / 8</div>
      ${r.notes.length ? '<ul>' + [...new Set(r.notes)].map(n => `<li>${esc(n)}</li>`).join('') + '</ul>' : ''}
      <div class="btns"><button class="primary" id="toTriage">🗂️ افتح التحليل الكامل</button></div></div>`;
    h += `<div class="status">⏱️ تم الفحص في ${ms(t0)} ملّي ثانية</div>`;
    out.innerHTML = h;
    $('#toTriage').addEventListener('click', () => { showTab('file'); triageBytes(currentFile.name, currentFile.bytes, currentFile.mime); });
  }

  /* ================= فك الترميز ================= */
  function runMagic() {
    const t = $('#decIn').value.trim(), out = $('#decMagicOut');
    if (!t) { out.innerHTML = ''; return; }
    if (JF.isJSFuck(t)) { out.innerHTML = `<div class="noflag">🤡 هذا JSFuck — حوّلناه إلى أداة فك JSFuck بالأسفل.</div>`; $('#jsfIn').value = t; runJsf(); $('#jsfCard').scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    const t0 = performance.now();
    const r = C.magic(t, { depth: +$('#decDepth').value, maxNodes: 4000, top: 15 });
    let h = renderFlags(r.flags.map(f => ({ flag: f.flag, method: f.chain.join(' → ') || 'مباشر' })));
    h += `<div class="card"><h3>📜 النتائج مرتبة حسب سهولة القراءة</h3>` + (r.outputs.length ? r.outputs.map(o => resRow(o.chain.join(' → '), o.s, C.findFlags(o.s).length, `<button class="small" data-apply="${keep(o)}">🧪 حمّل في الوصفة</button>`)).join('') : '<div class="muted">لا توجد عمليات فك صالحة. ربما هي شيفرة (جرّب تبويب الشيفرات)، أو بيانات مضغوطة، أو ترميز مخصص.</div>') + `<div class="status">جُرّب ${r.nodes} احتمال في ${ms(t0)} ملّي ثانية</div></div>`;
    out.innerHTML = h;
    resetRecipe();
  }
  $('#decMagic').addEventListener('click', runMagic);
  $('#decIn').addEventListener('input', debounce(() => { const v = $('#decIn').value; if (v.length < 20000 || JF.isJSFuck(v)) runMagic(); }, 400));
  $('#decMagicOut').addEventListener('click', e => { const b = e.target.closest('[data-apply]'); if (!b) return; const o = store.get(b.dataset.apply); recipe = { base: $('#decIn').value.trim(), steps: [...o.chain] }; history2 = [o.s]; renderRecipe(o.s); $('#decOps').scrollIntoView({ behavior: 'smooth', block: 'center' }); });

  const OPS = [
    ['فك', [['Base64', C.D.base64], ['Base64URL', C.D.base64url], ['Base32', C.D.base32], ['Base58', C.D.base58], ['Base85', C.D.base85], ['Hex', C.D.hex], ['Binary', C.D.binary], ['Octal', C.D.octal], ['Decimal', C.D.decimal], ['URL', C.D.url], ['HTML entities', C.D.html], ['Morse', C.D.morse], ['Unicode escapes', C.D.unicode], ['Quoted-printable', C.D.qp]]],
    ['تحويل', [['Reverse', C.reverse], ['ROT13', s => C.rot(s, 13)], ['ROT-N…', null], ['ROT47', C.rot47], ['Atbash', C.atbash], ['UPPER', s => s.toUpperCase()], ['lower', s => s.toLowerCase()], ['Swap case', s => s.replace(/[a-z]/gi, c => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())], ['Remove spaces', s => s.replace(/\s+/g, '')], ['Remove non-printable', s => s.replace(/[^\x20-\x7e\n]/g, '')], ['Show zero-width', s => s.replace(/[​-‏⁠﻿]/g, c => '<U+' + c.charCodeAt(0).toString(16).toUpperCase() + '>')], ['Run Brainfuck', s => { const r = C.brainfuck(s); return r.out + (r.error ? '\n[' + r.error + ']' : ''); }], ['Every 2nd char', s => Array.from(s).filter((_, i) => i % 2 === 0).join('')]]],
    ['ترميز', [['→ Base64', C.E.base64], ['→ Base32', C.E.base32], ['→ Base58', C.E.base58], ['→ Hex', C.E.hex], ['→ Binary', C.E.binary], ['→ Decimal', C.E.decimal], ['→ Octal', C.E.octal], ['→ URL', C.E.url], ['→ HTML', C.E.html], ['→ Unicode', C.E.unicode], ['→ Morse', C.E.morse]]],
  ];
  let recipe = { base: '', steps: [] }, history2 = [];
  const opsEl = $('#decOps');
  opsEl.innerHTML = OPS.map(([g, list]) => `<div class="grp">${g}</div>` + list.map(([n]) => n === 'ROT-N…' ? `<span><button class="small" data-op="${esc(n)}">ROT-N</button><input type="number" id="decRotN" value="3" min="1" max="25" style="width:52px;padding:2px 4px;margin-left:2px"></span>` : `<button class="small" data-op="${esc(n)}">${esc(n)}</button>`).join('')).join('');
  const OPFN = Object.fromEntries(OPS.flatMap(([, l]) => l));
  function resetRecipe() { recipe = { base: $('#decIn').value.trim(), steps: [] }; history2 = []; renderRecipe(recipe.base); }
  function curOut() { return history2.length ? history2[history2.length - 1] : $('#decIn').value; }
  function renderRecipe(s) {
    $('#decOut').value = s; $('#decChain').textContent = ['Input', ...recipe.steps].join(' → ');
    const fl = C.findFlags(s);
    $('#decOutInfo').innerHTML = `${s.length} حرف · ${Math.round(C.printableRatio(s) * 100)}% قابل للطباعة` + (fl.length ? ` · <b style="color:var(--mint)">🚩 <span dir="ltr">${esc(fl[0])}</span></b>` : '');
    if (fl.length && recipe.steps.length) G.onFlags([{ flag: fl[0], method: recipe.steps.join(' → ') }]);
  }
  opsEl.addEventListener('click', e => {
    const b = e.target.closest('[data-op]'); if (!b) return;
    let name = b.dataset.op, fn = OPFN[name];
    if (name === 'ROT-N…') { const n = parseInt($('#decRotN').value, 10) || 0; fn = s => C.rot(s, n); name = 'ROT' + n; }
    let out; try { out = fn(curOut()); } catch (err) { out = null; }
    if (out == null) { toast(name + ': غير صالح لهذا المدخل'); return; }
    recipe.steps.push(name); history2.push(out); renderRecipe(out);
  });
  $('#decCopy').addEventListener('click', () => copy($('#decOut').value));
  $('#decUse').addEventListener('click', () => { $('#decIn').value = $('#decOut').value; runMagic(); });
  $('#decUndo').addEventListener('click', () => { recipe.steps.pop(); history2.pop(); renderRecipe(curOut()); });
  $('#decReset').addEventListener('click', resetRecipe);

  /* ================= الشيفرات ================= */
  const ciIn = () => $('#ciIn').value;
  function runAllCiphers() {
    const s = ciIn(), out = $('#ciAllOut'); if (!s.trim()) { out.innerHTML = ''; return; }
    const groups = [];
    const letters = (s.match(/[a-z]/gi) || []).length;
    if (letters) {
      groups.push(['قيصر / ROT (أفضل 5)', C.caesarAll(s).slice(0, 5)]);
      groups.push(['Atbash · ROT47', [{ label: 'Atbash', text: C.atbash(s), flags: C.findFlags(C.atbash(s), true) }, { label: 'ROT47', text: C.rot47(s), flags: C.findFlags(C.rot47(s), true) }]]);
      groups.push(['حل Vigenère التلقائي', C.vigenereSolve(s).slice(0, 3)]);
      groups.push(['Affine (أفضل 3)', C.affineAll(s).slice(0, 3)]);
      groups.push(['السياج المتعرج (أفضل 3)', C.railAll(s).slice(0, 3)]);
    }
    if (/^[abAB01\s\/,|.\-]+$/.test(s.trim()) && s.replace(/[^abAB01]/g, '').length >= 10) { const b = C.bacon(s); groups.push(['Bacon', Object.entries(b).map(([k, v]) => ({ label: { std26: 'Bacon بـ 26 حرفاً', std24: 'Bacon بـ 24 حرفاً (I=J، U=V)', inv26: 'Bacon 26 معكوس', inv24: 'Bacon 24 معكوس' }[k], text: v, flags: C.findFlags(v, true) }))]); }
    const pb = C.parseBytesInput(s);
    if (pb.bytes.length >= 4 && pb.as !== 'text') groups.push([`XOR بايت واحد (المدخل قُرئ كـ ${pb.as})`, C.xorBrute(pb.bytes).slice(0, 3)]);
    const allFlags = []; groups.forEach(([g, list]) => list.forEach(r => (r.flags || []).forEach(f => allFlags.push({ flag: f, method: g.replace(/ \(.*/, '') + ' · ' + r.label, q: g.startsWith('XOR') ? C.chi(r.text) * 0.5 : C.chi(r.text) }))));
    const bestQ = Math.min(...allFlags.map(f => f.q)); allFlags.forEach(f => f.likely = f.q <= bestQ * 1.6 + 0.05); allFlags.sort((a, b) => a.q - b.q);
    const seen = new Set();
    let h = renderFlags(allFlags.filter(f => !seen.has(f.flag) && seen.add(f.flag)));
    h += `<div class="card">` + groups.map(([g, list]) => list.length ? `<h3 style="margin-top:8px">${esc(g)}</h3>` + list.map(r => resRow(r.label, r.text, (r.flags || []).length)).join('') : '').join('') + `</div>`;
    out.innerHTML = h;
  }
  $('#ciAll').addEventListener('click', runAllCiphers);
  function updateCipherTools() {
    const s = ciIn();
    const k = $('#vgKey').value, m = $('#vgMode').value;
    const vg = !k ? '(اكتب مفتاحاً)' : m === 'beau' ? C.beaufort(s, k) : C.vigenere(s, k, m === 'dec');
    $('#vgOut').textContent = vg;
    if (k && C.findFlags(vg, true).length) G.onFlags([{ flag: C.findFlags(vg, true)[0], method: 'Vigenère' }]);
    const n = +$('#csShift').value; $('#csVal').textContent = n;
    let cs = C.rot(s, n); if ($('#csDigits').checked) cs = C.rotDigits(cs, n % 10); $('#csOut').textContent = cs;
    const a = +$('#afA').value, b = +$('#afB').value, rails = +$('#rfRails').value, off = +$('#rfOff').value;
    const rf = $('#rfMode').value === 'dec' ? C.railDecrypt(s, rails, off) : C.railEncrypt(s, rails);
    const bc = C.bacon(s);
    $('#miscOut').innerHTML = [['Affine a=' + a + ' b=' + b, C.affineDecrypt(s, a, b)], ['السياج المتعرج ' + rails, rf], ['Atbash', C.atbash(s)], ['ROT47', C.rot47(s)], ['Bacon (26 / 24)', bc.std26 + '  /  ' + bc.std24]].map(([l, v]) => `<tr><th>${esc(l)}</th><td class="mono">${vis(C.preview(v, 2000))}</td></tr>`).join('');
    $('#subOut').textContent = C.substitute(s, subMap());
    const fq = C.freq(s); const max = Math.max(1, ...Object.values(fq.counts)); const engMax = 12.702;
    $('#freqInfo').textContent = `${fq.total} حرف · مؤشر التطابق ${fq.ioc.toFixed(4)} (الإنجليزية ≈ 0.066، العشوائي ≈ 0.038)` + (fq.total ? ' · الأكثر تكراراً: ' + Object.entries(fq.counts).sort((x, y) => y[1] - x[1]).slice(0, 6).map(x => x[0]).join(' ') : '');
    $('#freqBars').innerHTML = Object.entries(fq.counts).map(([L, c]) => { const eng = C.FREQ[L.toLowerCase()]; return `<div style="height:${fq.total ? c / max * 100 : 0}%" title="${L}: ${c}"><span>${L}</span></div><div class="eng" style="height:${eng / engMax * 100 * (fq.total ? 1 : 0)}%;flex:.35" title="English ${L}: ${eng}%"></div>`; }).join('');
  }
  $('#afA').innerHTML = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25].map(a => `<option>${a}</option>`).join('');
  ['#ciIn', '#vgKey', '#vgMode', '#csShift', '#csDigits', '#afA', '#afB', '#rfRails', '#rfOff', '#rfMode'].forEach(s => $(s).addEventListener('input', debounce(updateCipherTools, 120)));
  $('#ciIn').addEventListener('input', debounce(() => { if (ciIn().length < 5000) runAllCiphers(); }, 500));
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $('#subGrid').innerHTML = Array.from(ALPHA, L => `<label>${L}<input type="text" maxlength="1" data-sub="${L}"></label>`).join('');
  const subMap = () => Object.fromEntries($$('[data-sub]').filter(i => i.value).map(i => [i.dataset.sub, i.value]));
  $('#subGrid').addEventListener('input', updateCipherTools);
  $('#subFreq').addEventListener('click', () => { const fq = C.freq(ciIn()).counts, order = Object.entries(fq).sort((a, b) => b[1] - a[1]).map(x => x[0]), eng = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'; $$('[data-sub]').forEach(i => { const r = order.indexOf(i.dataset.sub); i.value = fq[i.dataset.sub] ? eng[r] : ''; }); updateCipherTools(); });
  $('#subClear').addEventListener('click', () => { $$('[data-sub]').forEach(i => i.value = ''); updateCipherTools(); });
  const AS = { hex: 'hex', base64: 'base64', text: 'نص', decimal: 'أرقام عشرية' };
  function xorInput() { return C.parseBytesInput(ciIn(), $('#xoFmt').value); }
  function xorShow(bytes, info) {
    const t = C.latin1(bytes), fl = C.findFlags(t);
    $('#xoInfo').innerHTML = info + (fl.length ? ` · <b style="color:var(--mint)">🚩 <span dir="ltr">${esc(fl[0])}</span></b>` : '');
    $('#xoOut').innerHTML = vis(C.preview(t, 5000)) + '\n\nhex: ' + esc(C.toHex(bytes.subarray(0, 512), ' '));
    if (fl.length) { G.onFlags([{ flag: fl[0], method: 'XOR' }]); G.event('xor'); }
  }
  function runXorKey() {
    const k = $('#xoKey').value; if (!k || !ciIn()) return;
    const key = $('#xoKeyFmt').value === 'hex' ? C.fromHex(k) : C.utf8(k); if (!key) { $('#xoInfo').textContent = 'المفتاح ليس hex صالحاً'; return; }
    const inp = xorInput(); xorShow(C.xor(inp.bytes, key), `المدخل قُرئ كـ ${AS[inp.as]} (${inp.bytes.length} بايت)`);
  }
  ['#xoKey', '#xoKeyFmt', '#xoFmt'].forEach(s => $(s).addEventListener('input', runXorKey));
  $('#xoBrute').addEventListener('click', () => { const inp = xorInput(); const r = C.xorBrute(inp.bytes); $('#xoInfo').innerHTML = `المدخل قُرئ كـ ${AS[inp.as]}. أفضل المفاتيح:`; $('#xoOut').innerHTML = r.map(x => `<b>${esc(x.label)}</b> ${x.flags.length ? '🚩' : ''}\n${vis(C.preview(x.text, 300))}`).join('\n\n'); const hit = r.find(x => x.flags.length); if (hit) { G.onFlags([{ flag: hit.flags[0], method: 'XOR' }]); G.event('xor'); } });
  $('#xoKnownBtn').addEventListener('click', () => {
    const inp = xorInput(), r = C.xorKnownPlain(inp.bytes, $('#xoKnown').value, +$('#xoOff').value || 0);
    const best = r.tries[0]; if (!best) return;
    $('#xoKey').value = C.toHex(best.key); $('#xoKeyFmt').value = 'hex';
    const pr = b => esc(C.latin1(b).replace(/[^\x20-\x7e]/g, '.'));
    xorShow(C.xor(inp.bytes, best.key), `بايتات المفتاح من النص المعروف: <code>${C.toHex(r.fragment, ' ')}</code> (<span dir="ltr">"${pr(r.fragment)}"</span>) ← أفضل مفتاح متكرر <code>${C.toHex(best.key)}</code> (<span dir="ltr">"${pr(best.key)}"</span>، الطول ${best.key.length}). إن كان المفتاح أطول من النص المعروف، أطِل النص المعروف.`);
  });

  /* ================= تحليل الملفات ================= */
  setupDrop($('#fileDrop'), f => triageFile(f));
  async function triageFile(file) { const bytes = await readFile(file); currentFile = { name: file.name, bytes, mime: file.type }; triageBytes(file.name, bytes, file.type); }
  const stem = n => n.replace(/\.[^.]*$/, '');
  async function triageBytes(name, bytes, mime) {
    const out = $('#fileOut');
    out.innerHTML = `<div class="card"><span class="spinner"></span> جارٍ تحليل ${esc(name)}…</div>`; await tick();
    const ids = F.identify(bytes), main = ids[0] || { name: 'غير معروف', ext: 'bin' };
    const ext = (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
    const mismatch = main.ext !== 'txt' && main.ext !== 'bin' && ext && !sameExt(ext, main.ext);
    const blocks = F.entropyBlocks(bytes, 96), ent = F.entropy(bytes);
    const col = h => `hsl(${Math.round(220 - h / 8 * 220)},75%,${35 + h / 8 * 22}%)`;
    let h = `<div id="tFlags"><div class="card"><span class="spinner"></span> نبحث عن الأعلام (البايتات، البيانات الوصفية، الأرشيفات، LSB)…</div></div>`;
    h += `<div class="card"><h2>📄 ${esc(name)}</h2>
      <table><tr><th>الحجم</th><td>${fmtSize(bytes.length)} (${bytes.length.toLocaleString('ar')} بايت)</td></tr>
      <tr><th>النوع المكتشف</th><td>${ids.map(i => `<span class="tag">${esc(i.name)}</span>`).join('')} ${mismatch ? `<span class="tag bad">الامتداد .${esc(ext)} لا يطابق — النوع الحقيقي .${main.ext}</span>` + dlBtn(stem(name) + '.' + main.ext, bytes, '⬇️ تنزيل بالامتداد .' + main.ext) : ''}</td></tr>
      <tr><th>أول البايتات</th><td class="mono">${C.toHex(bytes.subarray(0, 16), ' ')}</td></tr>
      <tr><th>الإنتروبيا</th><td>${ent.toFixed(3)} / 8 ${ent > 7.5 ? '<span class="tag warn">مضغوط أو مشفّر</span>' : ''}<div class="entropy" title="الإنتروبيا عبر الملف (أزرق = منخفضة، أحمر = عالية)">${blocks.map(b => `<div style="background:${col(b.h)}" title="@${b.off}: ${b.h.toFixed(2)}"></div>`).join('')}</div></td></tr>
      <tr><th>الهاش</th><td class="mono" id="tHashes"><span class="spinner"></span></td></tr></table></div>`;
    const tr = F.trailing(bytes);
    const emb = F.scanEmbedded(bytes, 300);
    if ((tr && tr.extra > 0) || emb.length) {
      h += `<div class="card"><h3>🕳️ بيانات مخفية / مضمّنة</h3>`;
      if (tr && tr.extra > 0) { const tb = bytes.subarray(tr.end); const tid = F.identify(tb)[0]; h += `<div class="res hit"><div class="lbl">${fmtSize(tr.extra)} بعد نهاية ${esc(tr.type)} @ ${tr.end}</div><pre>${tid ? '[' + esc(tid.name) + ']\n' : ''}${vis(C.preview(C.latin1(tb.subarray(0, 600)), 600))}</pre><div>${anBtn(stem(name) + '_trailing.' + (tid ? tid.ext : 'bin'), tb)} ${dlBtn(stem(name) + '_trailing.' + (tid ? tid.ext : 'bin'), tb)} ${sendBtn('scan', C.latin1(tb.subarray(0, 200000)), '🔎 افحص كنص')}</div></div>`; }
      if (emb.length) h += `<table><tr><th>الموضع</th><th>Hex</th><th>التوقيع</th><th></th></tr>` + emb.map((x, i) => { const end = (emb.slice(i + 1).find(y => y.offset > x.offset) || { offset: bytes.length }).offset; return `<tr><td>${x.offset}</td><td class="mono">0x${x.offset.toString(16)}</td><td>${esc(x.name)}</td><td>${anBtn(stem(name) + '_' + x.offset + '.' + x.ext, bytes.subarray(x.offset))} ${dlBtn(stem(name) + '_' + x.offset + '.' + x.ext, bytes.subarray(x.offset))} ${end < bytes.length ? dlBtn(stem(name) + '_' + x.offset + '-' + end + '.' + x.ext, bytes.subarray(x.offset, end), '⬇️ حتى التالي') : ''}</td></tr>`; }).join('') + `</table><div class="muted small-t">توقيعات ملفات داخل الملف (مثل binwalk). بعضها إنذار كاذب؛ وداخل ZIP يظهر كل ملف مخزّن.</div>`;
      h += `</div>`;
    }
    h += `<div id="tArchive"></div><div id="tMeta"></div><div id="tImage"></div><div id="tAudio"></div>`;
    h += `<div class="card"><h3>🔤 النصوص (Strings)</h3><div class="btns"><label class="small-t">أقل طول <input type="number" id="stMin" value="5" min="2"></label><input type="text" id="stFilter" dir="ltr" placeholder="فلتر (regex)" spellcheck="false"><label class="small-t"><input type="checkbox" id="stU16" checked> تضمين UTF-16</label><span id="stInfo" class="muted small-t"></span></div><div class="out" style="margin-top:8px;max-height:420px"><pre id="stOut"></pre></div></div>`;
    h += `<div class="card"><h3>🧱 عرض Hex</h3><div class="btns"><label class="small-t">الموضع <input type="text" id="hxOff" dir="ltr" value="0" style="width:110px"></label><label class="small-t">عدد البايتات <input type="number" id="hxLen" value="512" min="16" step="256"></label><button id="hxEnd">آخر 512 بايت</button></div><div class="out" style="margin-top:8px"><pre id="hxOut"></pre></div></div>`;
    out.innerHTML = h;

    C.allHashes(bytes).then(hs => { $('#tHashes').innerHTML = Object.entries(hs).filter(([k]) => k !== 'SHA-384').map(([k, v]) => `${k}: ${v} ${copyBtn(v)}`).join('<br>'); }).catch(() => { $('#tHashes').textContent = 'MD5: ' + C.md5(bytes); });
    const renderStrings = () => {
      const min = Math.max(2, +$('#stMin').value || 5), filt = $('#stFilter').value;
      let re = null; try { re = filt ? new RegExp(filt, 'i') : null; } catch (e) { }
      const all = F.strings(bytes, min, $('#stU16').checked, 50000), list = re ? all.filter(x => re.test(x.s)) : all;
      $('#stInfo').textContent = `${list.length.toLocaleString('ar')} نص${list.length > 5000 ? ' (نعرض أول 5000)' : ''}`;
      $('#stOut').innerHTML = list.slice(0, 5000).map(x => `<span class="muted">${x.off.toString(16).padStart(8, '0')}${x.enc === 'utf16le' ? 'ᵘ' : ' '}</span> ${C.findFlags(x.s).length ? '<b style="color:var(--mint)">' + esc(x.s) + '</b>' : esc(x.s)}`).join('\n');
    };
    ['#stMin', '#stFilter', '#stU16'].forEach(s => $(s).addEventListener('input', debounce(renderStrings, 250))); renderStrings();
    const renderHex = () => { const o = parseInt($('#hxOff').value, /^0x/i.test($('#hxOff').value) ? 16 : 10) || 0; $('#hxOut').textContent = F.hexdump(bytes, Math.max(0, o), +$('#hxLen').value || 512); };
    ['#hxOff', '#hxLen'].forEach(s => $(s).addEventListener('input', debounce(renderHex, 200))); renderHex();
    $('#hxEnd').addEventListener('click', () => { $('#hxOff').value = Math.max(0, bytes.length - 512); renderHex(); });

    // محتويات الأرشيف
    const zipBase = main.ext === 'zip' ? bytes : (tr && tr.extra > 0 && F.identify(bytes.subarray(tr.end))[0]?.ext === 'zip') ? bytes.subarray(tr.end) : (emb.find(x => x.ext === 'zip') ? bytes.subarray(emb.find(x => x.ext === 'zip').offset) : null);
    if (zipBase) {
      const ents = F.zipEntries(zipBase);
      if (ents.length) {
        const rows = [];
        for (const e of ents.slice(0, 500)) {
          let btn = '';
          if (e.encrypted) btn = '<span class="tag warn">🔒 بكلمة سر</span>';
          else { try { const d = await F.zipRead(zipBase, e); const fn = e.name.split('/').pop() || 'file'; btn = anBtn(fn, d) + ' ' + dlBtn(fn, d) + (d.length < 200000 && C.printableRatio(C.latin1(d.subarray(0, 2000))) > 0.9 ? ' ' + sendBtn('scan', C.bytesToText(d), '🔎 افحص كنص') : ''); } catch (err) { btn = `<span class="tag bad">${esc(err.message)}</span>`; } }
          rows.push(`<tr><td class="mono">${vis(e.name)}${e.comment ? ' <span class="muted">// ' + vis(e.comment) + '</span>' : ''}</td><td>${fmtSize(e.size)}</td><td>${e.method === 0 ? 'مخزّن' : e.method === 8 ? 'deflate' : e.method}</td><td>${btn}</td></tr>`);
        }
        $('#tArchive').innerHTML = `<div class="card"><h3>📦 محتويات ZIP (${ents.length})</h3>${ents.comment ? `<div>تعليق الأرشيف: <code>${vis(ents.comment)}</code></div>` : ''}<table><tr><th>الاسم</th><th>الحجم</th><th>الضغط</th><th></th></tr>` + rows.join('') + `</table></div>`;
      }
    }
    if (main.ext === 'gz') { try { const d = await F.inflate(bytes, 'gzip'); $('#tArchive').innerHTML = `<div class="card"><h3>📦 محتويات GZIP</h3>تم فك الضغط: ${fmtSize(d.length)} · ${esc((F.identify(d)[0] || {}).name || '')} ${anBtn(stem(name), d)} ${dlBtn(stem(name), d)}</div>`; } catch (e) { } }

    // البيانات الوصفية
    let mh = '';
    const ex = F.exif(bytes);
    if (ex && ex.tags.length) {
      mh += `<h3>📸 بيانات EXIF</h3><table>` + ex.tags.map(([k, v]) => `<tr><th dir="ltr">${esc(k)}</th><td class="mono">${C.findFlags(v).length ? '<b style="color:var(--mint)">' + vis(v) + '</b>' : vis(v)}</td></tr>`).join('') + `</table>`;
      if (ex.gps) mh += `<div class="btns"><span class="tag good">📍 GPS <span dir="ltr">${ex.gps.lat}, ${ex.gps.lon}</span></span><a href="https://www.openstreetmap.org/?mlat=${ex.gps.lat}&mlon=${ex.gps.lon}#map=16/${ex.gps.lat}/${ex.gps.lon}" target="_blank" rel="noopener">افتح في OpenStreetMap</a><a href="https://www.google.com/maps?q=${ex.gps.lat},${ex.gps.lon}" target="_blank" rel="noopener">خرائط Google</a></div>`;
    }
    const pc = F.pngChunks(bytes);
    if (pc) {
      const txt = await F.pngText(bytes);
      if (txt.length) mh += `<h3>📝 مقاطع نص PNG</h3><table>` + txt.map(([k, v]) => `<tr><th dir="ltr">${vis(k)}</th><td class="mono">${vis(v)} ${sendBtn('scan', v, '🔎 افحص')}</td></tr>`).join('') + `</table>`;
      const bad = pc.chunks.filter(c => !c.crcOk);
      mh += `<h3>🧩 مقاطع PNG</h3><div>${pc.ihdr ? `<span dir="ltr">${pc.ihdr.width} × ${pc.ihdr.height}</span>، عمق البت ${pc.ihdr.bitDepth}، نوع اللون ${pc.ihdr.colorType}${pc.ihdr.interlace ? '، متداخلة' : ''}` : ''}</div><div class="mono small-t">${pc.chunks.map(c => `<span class="tag ${c.crcOk ? '' : 'bad'}">${esc(c.type)} ${c.len}${c.crcOk ? '' : ' CRC✗'}</span>`).join('')}</div>`;
      if (bad.some(c => c.type === 'IHDR')) mh += `<div class="btns"><span class="tag bad">خطأ CRC في IHDR — العرض أو الارتفاع عُدّل غالباً</span><button id="pngFix" class="primary">🩹 أوجد الأبعاد الحقيقية</button><span id="pngFixOut" class="status"></span></div>`;
      else if (bad.length) mh += `<div class="tag warn">أخطاء CRC في: ${bad.map(c => esc(c.type)).join('، ')} — البيانات عُدّلت</div>`;
    }
    const jp = F.jpegInfo(bytes);
    if (jp && jp.comments.length) mh += `<h3>💬 تعليقات JPEG</h3>` + jp.comments.map(c => `<div class="mono">${vis(c)} ${sendBtn('scan', c, '🔎 افحص')}</div>`).join('');
    if (mh) $('#tMeta').innerHTML = `<div class="card">${mh}</div>`;
    const pf = $('#pngFix');
    if (pf) pf.addEventListener('click', async () => {
      $('#pngFixOut').innerHTML = '<span class="spinner"></span> نبحث…'; await tick();
      const r = F.pngFixDims(bytes);
      if (r && r.fixed) {
        $('#pngFixOut').innerHTML = `الحجم الحقيقي: <b dir="ltr">${r.width} × ${r.height}</b> ` + anBtn(stem(name) + '_fixed.png', r.fixed) + ' ' + dlBtn(stem(name) + '_fixed.png', r.fixed, '⬇️ تنزيل الصورة المصلحة');
        const img = new Image(); img.src = URL.createObjectURL(new Blob([r.fixed], { type: 'image/png' })); img.style.cssText = 'max-width:100%;display:block;margin-top:8px;border-radius:8px'; $('#pngFixOut').after(img);
        G.event('pngfix');
      } else $('#pngFixOut').textContent = 'لم نجد أبعاداً مطابقة (ربما عُدّل الـ CRC نفسه).';
    });

    const px = await getPixels(bytes, mime);
    if (px) renderImageTools(px, name);
    if (['wav', 'mp3', 'ogg', 'flac'].includes(main.ext) || /^audio\//.test(mime || '')) renderAudio(bytes);

    const r = await fileFlags(name, bytes, mime);
    $('#tFlags').innerHTML = renderFlags(r.flags) + (r.flags.length ? '' : '<div class="noflag">🕵️ لم نجد علماً تلقائياً — تصفّح الأقسام بالأسفل.</div>') + (r.notes.length ? `<div class="card"><h3>🔎 ملاحظات</h3><ul>${[...new Set(r.notes)].map(n => `<li>${esc(n)}</li>`).join('')}</ul></div>` : '');
  }

  function renderImageTools(px, name) {
    const { data, width: w, height: h } = px;
    const scale = Math.max(1, Math.min(8, Math.floor(512 / Math.max(w, h))));
    $('#tImage').innerHTML = `<div class="card"><h3>🖼️ تحليل الصورة — <span dir="ltr">${w} × ${h}</span>${px.exact ? '' : ' <span class="muted small-t">(فكّها المتصفح)</span>'}</h3>
      <div class="planes" id="plBtns"><button class="small on" data-pl="orig">Original</button><button class="small" data-pl="inv">Inverted</button><button class="small" data-pl="eq">Contrast</button>${'RGBA'.split('').map(c => [0, 1, 2, 3, 4, 5, 6, 7].map(b => `<button class="small" data-pl="${c}${b}">${c}${b}</button>`).join('')).join('<span style="width:8px"></span>')}<button class="small" data-pl="alpha">Alpha≠255</button></div>
      <canvas id="plCanvas" width="${w}" height="${h}" style="width:${w * scale}px"></canvas>
      <div class="status">ابحث عن نص أو رمز QR أو ضوضاء منتظمة. الطبقة 0 = أقل بت أهمية. الأسهم ← → تتنقل بين الطبقات.</div>
      <h3 style="margin-top:12px">🧬 استخراج LSB</h3>
      <div class="btns"><label class="small-t">القنوات <input type="text" id="lsCh" dir="ltr" value="RGB" style="width:70px"></label><label class="small-t">البت <select id="lsBit">${[0, 1, 2, 3, 4, 5, 6, 7].map(b => `<option>${b}</option>`).join('')}</select></label>
      <label class="small-t">الترتيب <select id="lsOrd"><option value="row">صفوف</option><option value="col">أعمدة</option></select></label><label class="small-t">ترتيب البتات <select id="lsMsb"><option value="1">MSB أولاً</option><option value="0">LSB أولاً</option></select></label><button id="lsBtn" class="primary">⛏️ استخرج</button></div>
      <div id="lsInfo" class="status"></div><div class="out" style="margin-top:6px"><pre id="lsOut"></pre></div></div>`;
    const cv = $('#plCanvas'), ctx = cv.getContext('2d'), img = ctx.createImageData(w, h);
    const draw = mode => {
      const o = img.data;
      if (mode === 'orig') o.set(data);
      else if (mode === 'inv') for (let i = 0; i < data.length; i += 4) { o[i] = 255 - data[i]; o[i + 1] = 255 - data[i + 1]; o[i + 2] = 255 - data[i + 2]; o[i + 3] = 255; }
      else if (mode === 'eq') { const mn = [255, 255, 255], mx = [0, 0, 0]; for (let i = 0; i < data.length; i += 4) for (let c = 0; c < 3; c++) { mn[c] = Math.min(mn[c], data[i + c]); mx[c] = Math.max(mx[c], data[i + c]); } for (let i = 0; i < data.length; i += 4) { for (let c = 0; c < 3; c++) o[i + c] = (data[i + c] - mn[c]) * 255 / Math.max(1, mx[c] - mn[c]); o[i + 3] = 255; } }
      else if (mode === 'alpha') for (let i = 0; i < data.length; i += 4) { const v = data[i + 3] === 255 ? 0 : 255; o[i] = o[i + 1] = o[i + 2] = v; o[i + 3] = 255; }
      else { const ci = 'RGBA'.indexOf(mode[0]), bit = +mode[1]; for (let i = 0; i < data.length; i += 4) { const v = (data[i + ci] >> bit) & 1 ? 255 : 0; o[i] = o[i + 1] = o[i + 2] = v; o[i + 3] = 255; } }
      ctx.putImageData(img, 0, 0);
      $$('#plBtns button').forEach(b => b.classList.toggle('on', b.dataset.pl === mode));
    };
    draw('orig');
    $('#plBtns').addEventListener('click', e => { const b = e.target.closest('[data-pl]'); if (b) draw(b.dataset.pl); });
    const modes = $$('#plBtns button').map(b => b.dataset.pl);
    document.onkeydown = e => { if ($('.panel.active').id !== 'file' || /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) || !$('#plCanvas')) return; const cur = modes.indexOf(($('#plBtns .on') || {}).dataset?.pl); if (e.key === 'ArrowRight') draw(modes[(cur + 1) % modes.length]); if (e.key === 'ArrowLeft') draw(modes[(cur - 1 + modes.length) % modes.length]); };
    $('#lsBtn').addEventListener('click', () => {
      const ch = $('#lsCh').value.toUpperCase().replace(/[^RGBA]/g, '') || 'RGB';
      const outb = F.lsbExtract(data, w, h, { channels: ch, bit: +$('#lsBit').value, order: $('#lsOrd').value, msbFirst: $('#lsMsb').value === '1' });
      const s = C.latin1(outb), hid = F.identify(outb)[0], fl = C.findFlags(s);
      const fn = stem(name) + '_lsb_' + ch + '.' + (hid ? hid.ext : 'bin');
      $('#lsInfo').innerHTML = `${outb.length.toLocaleString('ar')} بايت · يبدأ بـ: ${esc(hid ? hid.name : '?')} ${fl.length ? '· <b style="color:var(--mint)">🚩 <span dir="ltr">' + esc(fl[0]) + '</span></b>' : ''} ` + anBtn(fn, outb) + ' ' + dlBtn(fn, outb) + ' ' + sendBtn('scan', s.slice(0, 5000).replace(/\0+$/, ''), '🔎 افحص كنص');
      $('#lsOut').innerHTML = vis(s.slice(0, 2000)) + '\n\nhex: ' + C.toHex(outb.subarray(0, 64), ' ');
      if (fl.length) G.onFlags([{ flag: fl[0], method: 'LSB ' + ch }]);
    });
  }

  async function renderAudio(bytes) {
    $('#tAudio').innerHTML = `<div class="card"><h3>🎧 المخطط الطيفي للصوت</h3><div id="spInfo" class="status"><span class="spinner"></span> جارٍ فك الصوت…</div><canvas id="spCanvas" style="width:100%;height:320px"></canvas><div class="status">غالباً يُرسم النص أو الصورة المخفية هنا. الترددات العالية في الأعلى؛ ارفع التباين إن كانت باهتة.</div><div class="btns"><label class="small-t">التباين <input type="range" id="spGain" min="1" max="10" value="4"></label></div></div>`;
    let buf;
    try { const AC = window.AudioContext || window.webkitAudioContext; const ac = new AC(); buf = await ac.decodeAudioData(bytes.slice().buffer); ac.close && ac.close(); }
    catch (e) { $('#spInfo').textContent = 'لم يستطع المتصفح فك هذا الصوت (' + e.message + ').'; return; }
    const ch = buf.getChannelData(0), N = 1024, cols = Math.min(1600, Math.max(200, Math.floor(ch.length / 256)));
    const hop = Math.max(1, Math.floor((ch.length - N) / cols)), mags = [];
    const win = new Float32Array(N).map((_, i) => 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (N - 1)));
    let maxv = 1e-9;
    for (let c = 0; c < cols; c++) {
      const re = new Float64Array(N), im = new Float64Array(N), s = c * hop;
      for (let i = 0; i < N; i++) re[i] = (ch[s + i] || 0) * win[i];
      F.fft(re, im); const m = new Float32Array(N / 2);
      for (let i = 0; i < N / 2; i++) { m[i] = Math.log10(1 + Math.hypot(re[i], im[i])); if (m[i] > maxv) maxv = m[i]; }
      mags.push(m);
    }
    // تكبير تلقائي: نعرض فقط الترددات التي فيها محتوى
    let top = 16; for (const m of mags) for (let i = m.length - 1; i > top; i--) if (m[i] > maxv * 0.35) { top = i; break; }
    const H = Math.min(N / 2, Math.ceil(top * 1.12) + 4);
    const cv = $('#spCanvas'); cv.width = cols; cv.height = H; const ctx = cv.getContext('2d'), img = ctx.createImageData(cols, H);
    const paint = () => {
      const g = +$('#spGain').value / 4;
      for (let x = 0; x < cols; x++) for (let y = 0; y < H; y++) { const v = Math.min(1, mags[x][H - 1 - y] / maxv * g), p = (y * cols + x) * 4; img.data[p] = 255 * Math.min(1, v * 2); img.data[p + 1] = 255 * Math.max(0, v * 2 - 1); img.data[p + 2] = 255 * (v < .5 ? v : 1 - v) * .8 + 30 * (1 - v); img.data[p + 3] = 255; }
      ctx.putImageData(img, 0, 0);
    };
    paint(); $('#spGain').addEventListener('input', paint);
    $('#spInfo').textContent = `${buf.duration.toFixed(2)} ثانية · ${buf.sampleRate} هرتز · ${buf.numberOfChannels} قناة · نعرض من 0 إلى ${Math.round(H / (N / 2) * buf.sampleRate / 2)} هرتز (تكبير تلقائي)`;
    G.event('audio');
  }

  /* ================= الهاش والأرقام ================= */
  $('#hiIn').addEventListener('input', () => {
    const s = $('#hiIn').value.trim(), o = $('#hiOut'); if (!s) { o.innerHTML = ''; return; }
    const jwt = C.jwtDecode(s);
    if (jwt) { o.innerHTML = `<span class="tag good">JWT</span> الخوارزمية <b>${esc(jwt.header.alg || '?')}</b>${String(jwt.header.alg).toLowerCase() === 'none' ? ' <span class="tag warn">غير موقّع</span>' : ''}<h3 style="margin-top:8px">الترويسة</h3><div class="out"><pre>${esc(JSON.stringify(jwt.header, null, 2))}</pre></div><h3 style="margin-top:8px">المحتوى</h3><div class="out"><pre>${esc(JSON.stringify(jwt.payload, null, 2))}</pre></div>` + (jwt.payload.exp ? `<div class="status">ينتهي في ${new Date(jwt.payload.exp * 1000).toISOString()}</div>` : ''); return; }
    const r = C.identifyHash(s);
    o.innerHTML = r.length ? `<ul class="idlist">${r.map(x => `<li><b>${esc(x.name)}</b> <span class="muted">${esc(x.note)}</span></li>`).join('')}</ul><div class="muted small-t">${s.length} حرفاً. جرّب «فحص كلمات مرشحة» بالأسفل بكلمات من التحدي.</div>` : '<span class="muted">ليست صيغة هاش معروفة. جرّب الفحص السريع.</span>';
    if (/^[a-f0-9]{32,128}$/i.test(s)) { $('#hwHash').value = s; $('#crkHash').value = s; }
  });
  const ASNAME = { text: 'نص UTF-8', hex: 'بايتات hex', base64: 'base64', decimal: 'بايتات عشرية' };
  const runHashCalc = debounce(async () => {
    const s = $('#hcIn').value, fmt = $('#hcFmt').value;
    if (!s) { $('#hcOut').innerHTML = ''; $('#hcInfo').textContent = ''; return; }
    const bytes = fmt === 'text' ? C.utf8(s) : C.parseBytesInput(s, fmt).bytes;
    $('#hcInfo').textContent = `${bytes.length.toLocaleString('ar')} بايت (${ASNAME[fmt]})`;
    const hs = await C.allHashes(bytes);
    $('#hcOut').innerHTML = Object.entries(hs).map(([k, v]) => `<tr><th>${k}</th><td class="mono">${v}</td><td>${copyBtn(v)}</td></tr>`).join('');
  }, 150);
  ['#hcIn', '#hcFmt'].forEach(x => $(x).addEventListener('input', runHashCalc));
  runHashCalc();
  $('#hwBtn').addEventListener('click', async () => {
    const target = $('#hwHash').value.trim().toLowerCase(), words = $('#hwWords').value.split(/\r?\n/).map(w => w.trim()).filter(Boolean);
    const algo = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' }[target.length];
    if (!algo) { $('#hwOut').textContent = 'ألصق هاش hex بطول 32 أو 40 أو 64 أو 128 حرفاً.'; return; }
    if (!words.length) { $('#hwOut').textContent = 'اكتب كلمة مرشحة واحدة على الأقل في المربع.'; return; }
    const cands = new Set();
    for (const w of words) { cands.add(w); if ($('#hwVar').checked) { const v = [w.toLowerCase(), w.toUpperCase(), w[0].toUpperCase() + w.slice(1).toLowerCase(), C.reverse(w)]; v.forEach(x => cands.add(x)); for (const x of v) for (let d = 0; d < 100; d++) cands.add(x + d); } }
    $('#hwOut').innerHTML = `<span class="spinner"></span> نفحص ${cands.size.toLocaleString('ar')} احتمالاً بـ ${algo}…`; await tick();
    let hit = null;
    for (const c of cands) { const hv = algo === 'MD5' ? C.md5(c) : await C.sha(algo, c); if (hv === target) { hit = c; break; } }
    $('#hwOut').innerHTML = hit ? `<b style="color:var(--mint)">🎉 تطابق: <span dir="ltr">${esc(hit)}</span></b> ${copyBtn(hit)}` : `لا تطابق بين ${cands.size.toLocaleString('ar')} احتمالاً (${algo}).`;
    if (hit) G.event('hashmatch');
  });
  const numUpdate = () => {
    const s = $('#nmIn').value; const n = C.parseBig(s, $('#nmBase').value);
    $('#nmOut').innerHTML = n == null ? (s.trim() ? '<tr><td class="muted">ليس رقماً صالحاً في هذا الأساس</td></tr>' : '') : C.numberViews(n).map(([k, v]) => `<tr><th>${k}</th><td class="mono">${vis(C.preview(v, 2000))}</td><td>${copyBtn(v)}</td></tr>`).join('');
    if (n != null) { const t = C.bytesToText(C.bigToBytes(n)); const fl = C.findFlags(t, true); if (fl.length) G.onFlags([{ flag: fl[0], method: 'رقم ← نص' }]); }
  };
  ['#nmIn', '#nmBase'].forEach(s => $(s).addEventListener('input', numUpdate));
  $('#tcIn').addEventListener('input', () => {
    const s = $('#tcIn').value; if (!s) { $('#tcOut').innerHTML = ''; return; }
    const rows = C.textCodes(s).slice(0, 300);
    const joined = { 'عشري': C.E.decimal(s), Hex: C.E.hex(s), 'ثنائي': C.E.binary(s), 'ثُماني': C.E.octal(s), 'كرقم واحد': BigInt('0x' + (C.E.hex(s) || '0')).toString() };
    $('#tcOut').innerHTML = `<table>${Object.entries(joined).map(([k, v]) => `<tr><th>${k}</th><td class="mono">${esc(C.preview(v, 1500))}</td><td>${copyBtn(v)}</td></tr>`).join('')}</table><details style="margin-top:6px"><summary class="muted small-t">لكل حرف</summary><table><tr><th>الحرف</th><th>عشري</th><th>Hex</th><th>ثنائي</th><th>Code point</th></tr>${rows.map(r => `<tr><td class="mono">${vis(r.ch)}</td><td class="mono">${r.dec}</td><td class="mono">${r.hex}</td><td class="mono">${r.bin}</td><td class="mono">${r.cp}</td></tr>`).join('')}</table></details>`;
  });
  $('#rsBtn').addEventListener('click', () => {
    const P = id => { const v = $(id).value.trim(); return v ? C.parseBig(v, /^0x/i.test(v) ? 16 : 10) : null; };
    const p = P('#rsP'), q = P('#rsQ'), e = P('#rsE'), c = P('#rsC'); let n = P('#rsN'), d = P('#rsD');
    const rows = []; const show = () => { $('#rsOut').innerHTML = rows.map(([k, v, cp]) => `<tr><th>${k}</th><td class="mono">${vis(String(v))}</td><td>${cp ? copyBtn(String(v)) : ''}</td></tr>`).join(''); };
    if (c == null || e == null) { rows.push(['خطأ', 'نحتاج على الأقل e و c']); return show(); }
    if (p && q) n = p * q;
    if (!d && p && q) { const phi = (p - 1n) * (q - 1n); d = C.modinv(e, phi); rows.push(['φ(n)', phi, true]); if (!d) rows.push(['ملاحظة', 'لا يوجد معكوس لـ e بالنسبة لـ φ(n) — تحقق من p و q و e']); }
    if (n) rows.push(['n', n, true]); if (d) rows.push(['d', d, true]);
    const showM = (label, m) => { const t = C.bytesToText(C.bigToBytes(m)); rows.push([label + ' (رقم)', m, true]); rows.push([label + ' (كنص)', t, true]); if (C.printableRatio(t) > 0.9) { G.event('rsa'); const fl = C.findFlags(t); if (fl.length) G.onFlags([{ flag: fl[0], method: 'RSA' }]); } };
    if (d && n) showM('m', C.modpow(c, d, n));
    if (e <= 17n) { const r = C.iroot(c, e); if (r ** e === c) showM('m = الجذر ' + e + ' لـ c (e صغير)', r); else if (!d) rows.push(['e صغير', 'c ليس قوة ' + e + ' كاملة (الرسالة محشوّة أو طويلة)']); }
    if (!d && !(e <= 17n)) rows.push(['الخطوة التالية', 'حلّل n أولاً (factordb.com) ثم أدخل p و q']);
    show();
  });

  /* ================= JSFuck ================= */
  const jsfDecode = t => JF.deobfuscate(t);
  function jsfRender(r, compact) {
    const out = r.output || '';
    if (!out && r.error) return `<div class="noflag">⚠️ تعذّر الفك: ${esc(r.error)}</div>`;
    const layers = r.layers.length, captured = r.layers.some(l => l.payloads.length);
    const fl = C.deepFlagSearch(out).flags.filter(f => f.likely !== false).map(f => ({ ...f, method: 'JSFuck' + (layers > 1 ? ' ×' + layers : '') + ' · ' + f.method }));
    let h = renderFlags(fl);
    h += `<div class="card"><h3>🤡 نتيجة فك JSFuck</h3><div class="btns" style="margin-top:0">${layers > 1 ? `<span class="tag">${layers} طبقات</span>` : ''}<span class="tag ${captured ? 'warn' : 'good'}">${captured ? '🛡️ كود مُلتقط — لم يُشغَّل' : 'نص ناتج'}</span>${r.layers[0].via === 'page' ? '<span class="tag">داخل الصفحة</span>' : ''}</div>
      <div class="out" style="margin-top:8px"><pre>${vis(C.preview(out, 20000))}</pre></div>
      <div class="btns">${copyBtn(out, '📋 نسخ الكود')}${sendBtn('scan', out, '🔎 افحص الناتج')}${compact ? '' : sendBtn('decode', out, '🧩 فك الناتج')}</div></div>`;
    return h;
  }
  async function runJsf() {
    const t = $('#jsfIn').value.trim(); if (!t) { $('#jsfOut').innerHTML = ''; $('#jsfInfo').textContent = ''; return; }
    if (!JF.CHARSET.test(t)) { $('#jsfInfo').textContent = '⚠️ ليس JSFuck: المسموح فقط [ ] ( ) ! + والمسافات'; $('#jsfOut').innerHTML = ''; return; }
    $('#jsfInfo').innerHTML = '<span class="spinner"></span> نفك…'; const t0 = performance.now();
    const r = await jsfDecode(t);
    $('#jsfInfo').textContent = `⏱️ ${ms(t0)} ملّي ثانية · ${t.length.toLocaleString('ar')} رمز`;
    $('#jsfOut').innerHTML = jsfRender(r, false);
  }
  $('#jsfBtn').addEventListener('click', runJsf);
  $('#jsfIn').addEventListener('input', debounce(runJsf, 500));

  /* ================= الويب ================= */
  function kvTable(rows, title, withDecode = true) {
    if (!rows.length) return '';
    let found = [];
    const body = rows.map(([k, v, note]) => {
      const d = withDecode ? W.decodeValue(v) : null;
      if (d) found.push(d.text);
      return `<tr><th dir="ltr">${vis(k)}</th><td class="mono">${vis(C.preview(v, 600))}${d ? `<div style="color:var(--mint);margin-top:3px">↳ <span class="tag good">${esc(d.how)}</span> ${vis(C.preview(d.text, 600))}</div>` : ''}${note ? `<div><span class="tag ${note[0]}">${esc(note[1])}</span></div>` : ''}</td><td>${copyBtn(d ? d.text : v)}</td></tr>`;
    }).join('');
    return { html: `<h3 style="margin-top:10px">${title} (${rows.length})</h3><table>${body}</table>`, found };
  }
  function runWeb() {
    const raw = $('#wbIn').value, out = $('#wbOut');
    if (!raw.trim()) { out.innerHTML = ''; return; }
    const t0 = performance.now(), p = W.parseHttp(raw);
    const decoded = []; let h = '', sec = '';
    const add = r => { if (!r) return; sec += r.html; decoded.push(...r.found); };
    if (p.kind === 'request') sec += `<div class="reqline"><b>${esc(p.method)}</b> ${vis(p.url)} <span class="muted">${esc(p.version)}</span></div>`;
    else if (p.kind === 'response') sec += `<div class="reqline">${esc(p.version)} <b class="st${String(p.status)[0]}">${p.status}</b> ${esc(p.reason)}</div>`;
    else sec += `<div class="noflag">لم نتعرّف على سطر HTTP في البداية — سنعامل النص كمحتوى (body).</div>`;
    add(kvTable(p.query, '🔗 معاملات الرابط (Query)'));
    add(kvTable(p.cookies, '🍪 الكوكيز (Cookie)'));
    add(kvTable(p.setCookies.map(c => [c.name, c.value, (!c.httpOnly || !c.secure) ? ['warn', 'ينقصها ' + [!c.httpOnly && 'HttpOnly', !c.secure && 'Secure'].filter(Boolean).join(' و ')] : null]), '🍪 كوكيز يضعها الخادم (Set-Cookie)'));
    add(kvTable(p.headers.filter(([k]) => !/^(cookie|set-cookie)$/i.test(k)).map(([k, v]) => [k, v, W.headerNote(k, v)]), '📨 الترويسات (Headers)', true));
    add(kvTable(p.bodyParams, '📝 معاملات المحتوى (Body)'));
    if (p.json) add(kvTable(W.flattenJson(p.json), '🧾 محتوى JSON'));
    const hf = W.htmlFindings(p.body);
    let hh = '';
    if (hf.comments.length) hh += `<h3 style="margin-top:10px">💬 تعليقات HTML (${hf.comments.length})</h3>` + hf.comments.map(c => `<div class="mono" style="margin:3px 0">&lt;!-- ${vis(c)} --&gt; ${copyBtn(c)}</div>`).join('');
    if (hf.hidden.length) hh += `<h3 style="margin-top:10px">🙈 حقول مخفية</h3><table>` + hf.hidden.map(([n, v]) => `<tr><th dir="ltr">${vis(n)}</th><td class="mono">${vis(v)}</td></tr>`).join('') + `</table>`;
    if (hf.forms.length) hh += `<h3 style="margin-top:10px">📋 نماذج (Forms)</h3>` + hf.forms.map(f => `<div class="mono">${esc(f)}</div>`).join('');
    if (hf.links.length || hf.scripts.length) hh += `<h3 style="margin-top:10px">🧭 روابط وملفات JavaScript</h3><div class="mono small-t">` + [...hf.scripts.map(x => '📜 ' + x), ...hf.links.slice(0, 80).map(x => '🔗 ' + x)].map(esc).join('<br>') + `</div>`;
    if (hf.meta.length) hh += `<h3 style="margin-top:10px">🏷️ وسوم Meta</h3><table>` + hf.meta.map(([k, v]) => `<tr><th dir="ltr">${esc(k)}</th><td class="mono">${vis(v)}</td></tr>`).join('') + `</table>`;
    decoded.push(...hf.comments, ...hf.hidden.map(x => x[1]));
    const curl = W.toCurl(p);
    const all = [raw, ...decoded].join('\n');
    const flags = C.deepFlagSearch(all).flags.filter(f => f.likely !== false).map(f => ({ ...f, method: 'HTTP · ' + f.method }));
    h += renderFlags(flags);
    if (!flags.length) h += `<div class="noflag">🕵️ لا علم ظاهر بعد. راجع الكوكيز والترويسات والتعليقات بالأسفل، وجرّب تعديل القيم في Burp Repeater.</div>`;
    h += `<div class="card"><h3>${p.kind === 'request' ? '📤 الطلب' : p.kind === 'response' ? '📥 الاستجابة' : '📄 المحتوى'}</h3>${sec}</div>`;
    if (hh) h += `<div class="card">${hh}</div>`;
    if (curl) h += `<div class="card"><h3>⌨️ أمر curl لإعادة إرسال الطلب</h3><div class="out"><pre>${esc(curl)}</pre></div><div class="btns">${copyBtn(curl, '📋 نسخ الأمر')}<span class="muted small-t">شغّله في الطرفية (Terminal) مثل Repeater في Burp — فقط على مواقع المسابقة.</span></div></div>`;
    if (p.body && p.body.trim() && !p.json) h += `<div class="card"><h3>📦 المحتوى (Body) — ${fmtSize(new TextEncoder().encode(p.body).length)}</h3><div class="out"><pre>${vis(C.preview(p.body, 8000))}</pre></div><div class="btns">${sendBtn('scan', p.body, '🔎 افحص المحتوى')}${copyBtn(p.body)}</div></div>`;
    h += `<div class="status">⏱️ ${ms(t0)} ملّي ثانية</div>`;
    out.innerHTML = h;
  }
  $('#wbBtn').addEventListener('click', runWeb);
  $('#wbIn').addEventListener('input', debounce(() => { if ($('#wbIn').value.length < 200000) runWeb(); }, 400));
  $('#wbSample').addEventListener('click', () => { $('#wbIn').value = W.SAMPLE; runWeb(); });
  function runCompare() {
    const a = $('#cmpA').value, b = $('#cmpB').value;
    if (!a && !b) { $('#cmpOut').innerHTML = ''; $('#cmpInfo').textContent = ''; return; }
    const d = W.diffLines(a, b, { ignoreWs: $('#cmpWs').checked, ignoreCase: $('#cmpCase').checked }), only = $('#cmpOnly').checked;
    const cnt = { add: 0, del: 0, chg: 0 }; d.forEach(x => { if (cnt[x.t] != null) cnt[x.t]++; });
    $('#cmpInfo').innerHTML = (cnt.add + cnt.del + cnt.chg) ? `<span class="tag good">+${cnt.add} مضاف</span><span class="tag bad">−${cnt.del} محذوف</span><span class="tag warn">~${cnt.chg} متغيّر</span>${d.truncated ? ' (أول 2500 سطر)' : ''}` : '<span class="tag good">✓ متطابقان</span>';
    $('#cmpOut').innerHTML = d.filter(x => !only || x.t !== 'same').slice(0, 3000).map(x => {
      if (x.t === 'same') return `<div class="dl same"><span class="sig"> </span>${esc(x.a)}</div>`;
      if (x.t === 'add') return `<div class="dl add"><span class="sig">+</span>${vis(x.b)}</div>`;
      if (x.t === 'del') return `<div class="dl del"><span class="sig">−</span>${vis(x.a)}</div>`;
      const c = W.charDiff(x.a, x.b);
      return `<div class="dl chg"><span class="sig">−</span>${esc(c.pre)}<mark>${vis(c.aMid)}</mark>${esc(c.post)}</div><div class="dl chg"><span class="sig">+</span>${esc(c.pre)}<mark>${vis(c.bMid)}</mark>${esc(c.post)}</div>`;
    }).join('') || '<div class="muted">لا اختلافات.</div>';
  }
  $('#cmpBtn').addEventListener('click', runCompare);
  ['#cmpWs', '#cmpCase', '#cmpOnly'].forEach(s => $(s).addEventListener('change', runCompare));
  ['#cmpA', '#cmpB'].forEach(s => $(s).addEventListener('input', debounce(() => { if ($('#cmpA').value.length + $('#cmpB').value.length < 400000) runCompare(); }, 400)));

  /* ================= كسر الهاش ================= */
  const crkMode = () => $('input[name=crkMode]:checked').value;
  function crkToggle() { const b = crkMode() === 'brute'; $('#crkBrute').hidden = !b; $('#crkDict').hidden = b; if (b) crkEst(); }
  $$('input[name=crkMode]').forEach(r => r.addEventListener('change', crkToggle));
  function crkEst() {
    const cs = KR.CHARSETS[$('#crkCharset').value], n = cs.length, mn = +$('#crkMin').value || 1, mx = Math.max(mn, +$('#crkMax').value || 1);
    const total = KR.bruteCount(n, mn, mx), rate = 180000, secs = total / rate;
    const time = secs < 1 ? 'أقل من ثانية' : secs < 90 ? Math.round(secs) + ' ثانية' : secs < 5400 ? Math.round(secs / 60) + ' دقيقة' : secs < 1e6 ? Math.round(secs / 3600) + ' ساعة' : 'وقت طويل جداً';
    $('#crkEst').innerHTML = `${total.toLocaleString('ar')} احتمال · تقدير زمني ≈ ${time} (SHA أبطأ من MD5)` + (total > 5e7 ? ' <span class="tag bad">كبير جداً — قلّل الطول أو المجموعة</span>' : '');
  }
  ['#crkCharset', '#crkMin', '#crkMax'].forEach(x => $(x).addEventListener('input', crkEst));
  let crkRunning = false;
  $('#crkBtn').addEventListener('click', async () => {
    if (crkRunning) return;
    const target = $('#crkHash').value.trim().toLowerCase();
    const algo = KR.algoFor(target);
    if (!algo) { $('#crkOut').innerHTML = `<div class="noflag">⚠️ ألصق هاش hex بطول 32 (MD5) أو 40 (SHA-1) أو 64 (SHA-256). SHA-512 غير مدعوم في الكسر — استخدم «فحص كلمات مرشحة».</div>`; return; }
    const mode = crkMode();
    let opts = { target, algo, mode };
    if (mode === 'dict') {
      const extra = $('#crkWords').value.split(/\r?\n/).map(w => w.trim()).filter(Boolean);
      const words = [...new Set([...($('#crkCommon').checked ? KR.COMMON : []), ...extra])];
      if (!words.length) { $('#crkOut').innerHTML = `<div class="noflag">أضف كلمات أو فعّل القائمة المدمجة.</div>`; return; }
      opts.words = words; opts.mutate = $('#crkMut').checked;
    } else {
      opts.charset = $('#crkCharset').value; opts.minLen = +$('#crkMin').value || 1; opts.maxLen = Math.max(opts.minLen, +$('#crkMax').value || 1);
    }
    crkRunning = true; $('#crkBtn').textContent = '🔨 يكسر…'; $('#crkStop').hidden = false; $('#crkOut').innerHTML = '';
    const t0 = performance.now();
    const r = await KR.crack(opts, p => { $('#crkProg').innerHTML = `<span class="spinner"></span> جُرّب ${p.tried.toLocaleString('ar')} احتمال… (${Math.round(p.tried / (p.ms / 1000)).toLocaleString('ar')} / ثانية)`; });
    crkRunning = false; $('#crkBtn').textContent = '🔨 ابدأ الكسر'; $('#crkStop').hidden = true; $('#crkProg').textContent = '';
    if (r.error) { $('#crkOut').innerHTML = `<div class="noflag">⚠️ ${esc(r.error)}</div>`; return; }
    if (r.found != null) {
      $('#crkOut').innerHTML = `<div class="flags"><h2>🎉 تم الكسر!</h2><div class="flagrow"><code dir="ltr">${vis(r.found)}</code>${copyBtn(r.found)}<span class="how">${r.algo} · ${r.tried.toLocaleString('ar')} محاولة · ${ms(t0)} ملّي ثانية</span></div></div>`;
      G.event('hashmatch');
      const fl = C.findFlags(r.found); if (fl.length) G.onFlags([{ flag: fl[0], method: 'كسر الهاش' }]);
    } else {
      $('#crkOut').innerHTML = `<div class="noflag">🕵️ لم نجد الأصل بعد ${r.tried.toLocaleString('ar')} محاولة. ${mode === 'dict' ? 'جرّب القوة الغاشمة أو أضف كلمات.' : 'جرّب طولاً أكبر أو مجموعة رموز أوسع (سيستغرق وقتاً أطول).'}</div>`;
    }
  });
  $('#crkStop').addEventListener('click', () => { if (KR.stop()) { crkRunning = false; $('#crkBtn').textContent = '🔨 ابدأ الكسر'; $('#crkStop').hidden = true; $('#crkProg').textContent = ''; $('#crkOut').innerHTML = `<div class="noflag">⏹️ أُوقف الكسر.</div>`; } });

  /* ================= بايثون (Pyodide) ================= */
  let pyBytes = null, pyLoadingShown = false;
  const pyGutter = $('#pyGutter');
  function pyNums() {
    const n = $('#pyCode').value.split('\n').length;
    let t = ''; for (let i = 1; i <= n; i++) t += i + '\n';
    pyGutter.textContent = t;
    pyGutter.style.transform = `translateY(${-$('#pyCode').scrollTop}px)`;
  }
  $('#pyCode').addEventListener('scroll', () => { pyGutter.style.transform = `translateY(${-$('#pyCode').scrollTop}px)`; });
  $('#pyCode').addEventListener('input', pyNums);
  $('#pyCode').value = PY.TEMPLATE;
  pyNums();
  $('#pySnip').innerHTML = '<option value="">اختر عملية عكسية شائعة…</option>' + Object.keys(PY.SNIPPETS).map(k => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
  $('#pySnip').addEventListener('change', e => {
    const k = e.target.value; if (!k) return;
    const ta = $('#pyCode'), add = PY.SNIPPETS[k];
    ta.value = ta.value.replace(/\s*$/, '') + '\n\n' + add + '\n';
    e.target.value = ''; ta.focus(); ta.scrollTop = ta.scrollHeight; pyNums();
  });
  const readText = f => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsText(f); });
  function pyLoadScript(name, text) {
    $('#pyCode').value = text.replace(/\r\n/g, '\n'); pyNums(); $('#pyOut').innerHTML = '';
    $('#pyFile').innerHTML = `📜 <b dir="ltr">${esc(name)}</b> حُمِّل في المحرّر` + (pyBytes ? ` · الملف المشفّر لا يزال متاحاً كـ <code dir="ltr">data</code>` : '');
    toast('تم تحميل السكربت 📜'); $('#pyCode').focus();
  }
  async function pyAddFile(f) {
    if (/\.py$/i.test(f.name) || f.type === 'text/x-python') { pyLoadScript(f.name, await readText(f)); return; }
    pyBytes = await readFile(f); $('#pyFile').innerHTML = `✅ <b dir="ltr">${esc(f.name)}</b> · ${fmtSize(pyBytes.length)} — متاح كـ <code dir="ltr">data</code>`;
  }
  setupDrop($('#pyDrop'), pyAddFile);
  // explicit 'load .py' button
  $('#pyLoad').addEventListener('click', () => $('#pyScriptInput').click());
  $('#pyScriptInput').addEventListener('change', async e => { const f = e.target.files[0]; if (f) pyLoadScript(f.name, await readText(f)); e.target.value = ''; });
  // drop a .py directly onto the editor
  const pyEd = $('#pyEditor');
  pyEd.addEventListener('dragover', e => { e.preventDefault(); pyEd.classList.add('dragover'); });
  pyEd.addEventListener('dragleave', () => pyEd.classList.remove('dragover'));
  pyEd.addEventListener('drop', async e => { e.preventDefault(); e.stopPropagation(); pyEd.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) { if (/\.(py|txt)$/i.test(f.name) || /^text\//.test(f.type)) pyLoadScript(f.name, await readText(f)); else pyAddFile(f); } });
  // Ctrl+Enter / Tab inside the editor
  $('#pyCode').addEventListener('keydown', e => {
    if (e.key === 'Tab') { e.preventDefault(); const t = e.target, st = t.selectionStart, en = t.selectionEnd; t.value = t.value.slice(0, st) + '    ' + t.value.slice(en); t.selectionStart = t.selectionEnd = st + 4; pyNums(); }
  });
  $('#pyReset').addEventListener('click', () => { $('#pyCode').value = PY.TEMPLATE; $('#pyOut').innerHTML = ''; pyNums(); });
  function pyCleanTrace(err) {
    if (!err || !err.trim()) return '';
    const lines = err.replace(/\s+$/, '').split('\n');
    const out = []; let skipHdr = true;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/\/lib\/python[\d.]*\.zip|_pyodide[\/\\]_base\.py|site-packages[\/\\]_pyodide/.test(l)) { if (i + 1 < lines.length && /^\s/.test(lines[i + 1])) i++; continue; }
      if (/^\s*(await CodeRunner\(|\.run_async\(|coroutine = eval\(|\.{3}<\d+ lines>\.{3})/.test(l)) continue;
      if (skipHdr && /^Traceback/.test(l)) { out.push(l); skipHdr = false; continue; }
      out.push(l);
    }
    let r = out.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    if (/^Traceback/.test(r) && !/File "<exec>"/.test(r)) r = r.replace(/^Traceback.*?\n/, '');
    return r;
  }
  async function pyEnsure() {
    if (PY.loaded()) return true;
    const t0 = performance.now();
    $('#pyStatus').innerHTML = '<span class="spinner"></span> تحميل محرك بايثون (~13 ميغابايت) لأول مرة…';
    const timer = setInterval(() => { $('#pyStatus').innerHTML = `<span class="spinner"></span> تحميل محرك بايثون… ${Math.round((performance.now() - t0) / 1000)} ثانية`; }, 500);
    try { await PY.init(stage => { if (stage === 'cdn') $('#pyStatus').innerHTML = '<span class="spinner"></span> المحلي غير متاح، نجرّب الإنترنت (CDN)…'; }); }
    catch (e) { clearInterval(timer); $('#pyStatus').textContent = ''; $('#pyOut').innerHTML = `<div class="noflag">⚠️ تعذّر تحميل محرك بايثون. على GitHub Pages أو النسخة المحمّلة يعمل بلا إنترنت؛ في المعاينة قد يحتاج اتصالاً. (${esc(e.message || '')})</div>`; return false; }
    clearInterval(timer); return true;
  }
  function pyRenderOut(r, title) {
    const combined = (r.stdout || '') + (r.result && r.result !== 'None' ? '\n' + r.result : '');
    const flags = C.deepFlagSearch(combined).flags.filter(f => f.likely !== false).map(f => ({ ...f, method: title + ' · ' + f.method }));
    let h = renderFlags(flags);
    h += `<div class="card"><h3>${esc(title)}</h3>`;
    if (r.stdout && r.stdout.trim()) h += `<div class="pyres"><pre>${vis(r.stdout)}</pre></div>`;
    if (r.result && r.result !== 'None') h += `<div class="muted small-t" style="margin-top:6px">قيمة آخر تعبير:</div><div class="pyres"><pre>${vis(r.result)}</pre></div>`;
    const cleanErr = pyCleanTrace(r.stderr);
    if (cleanErr) h += `<div class="muted small-t" style="margin-top:6px">أخطاء / تتبّع:</div><div class="pyres pyerr"><pre>${vis(cleanErr)}</pre></div>`;
    if (!((r.stdout && r.stdout.trim()) || (r.result && r.result !== 'None') || cleanErr)) h += `<div class="muted">(لا مخرجات — استخدم print())</div>`;
    h += `<div class="btns">${combined.trim() ? copyBtn(combined.trim(), '📋 نسخ الناتج') + sendBtn('scan', combined, '🔎 افحص الناتج') : ''}</div></div>`;
    $('#pyOut').innerHTML = h;
  }
  async function pyAuto() {
    const btn = $('#pyAuto'), run = $('#pyRun'); if (btn.disabled) return;
    btn.disabled = true; run.disabled = true;
    if (!(await pyEnsure())) { btn.disabled = false; run.disabled = false; return; }
    $('#pyStatus').innerHTML = '<span class="spinner"></span> يفحص دالة التشفير…'; const t0 = performance.now();
    const _clear = "for _n in ['encrypt','enc','encode','cipher','scramble','obfuscate','encrypt_flag','transform','crypt','do_encrypt','xor_encrypt','encipher']:\n    globals().pop(_n, None)\n__name__ = '__frozen__'\n";
    await PY.run(_clear + $('#pyCode').value, pyBytes, 20000); // fresh: drop stale funcs, define this script's, skip main
    const r = await PY.run(PY.AUTO, pyBytes, 45000);
    btn.disabled = false; run.disabled = false; $('#pyStatus').textContent = `⏱️ ${ms(t0)} ملّي ثانية`;
    if (r.error) { $('#pyOut').innerHTML = `<div class="noflag">⚠️ ${esc(r.error)}</div>`; return; }
    pyRenderOut(r, '🪄 اعكس تلقائياً');
  }
  $('#pyAuto').addEventListener('click', pyAuto);
  async function pyRun() {
    const code = $('#pyCode').value; if (!code.trim()) return;
    const btn = $('#pyRun'); if (btn.disabled) return;
    btn.disabled = true;
    if (!(await pyEnsure())) { btn.disabled = false; return; }
    $('#pyStatus').innerHTML = '<span class="spinner"></span> يشغّل…'; const t0 = performance.now();
    const r = await PY.run(code, pyBytes);
    btn.disabled = false; $('#pyStatus').textContent = `⏱️ ${ms(t0)} ملّي ثانية`;
    if (r.error) { $('#pyOut').innerHTML = `<div class="noflag">⚠️ ${esc(r.error)}</div>`; return; }
    pyRenderOut(r, '📤 الناتج');
  }
  $('#pyRun').addEventListener('click', pyRun);

  function openPython(name, bytes) { showTab('python'); pyBytes = bytes; $('#pyFile').innerHTML = `✅ <b dir="ltr">${esc(name)}</b> · ${fmtSize(bytes.length)} — متاح كـ <code dir="ltr">data</code>`; $('#pyCode').focus(); window.scrollTo(0, 0); }
  /* ================= فك الأسّ النمطي / RSA ================= */
  const meField = id => { const v = $(id).value.trim(); if (!v) return null; const n = C.parseBigFlexible(v); return n; };
  function meToggleExtra() {
    const t = $('#meType').value;
    $('#meExtra').hidden = !(t === 'pq' || t === 'factors');
    if (t === 'pq') { $('#mePlab').firstChild.textContent = 'p '; $('#meQlab').hidden = false; $('#meQlab').firstChild.textContent = 'q '; }
    else if (t === 'factors') { $('#mePlab').firstChild.textContent = 'العوامل (مفصولة بفواصل، أو p^k) '; $('#meQlab').hidden = true; }
  }
  $('#meType').addEventListener('change', meToggleExtra); meToggleExtra();
  $('#meSample').addEventListener('click', () => { $('#meN').value = '2^136+85'; $('#meE').value = '31337'; $('#meC').value = ''; $('#meType').value = 'prime'; meToggleExtra(); $('#meInfo').textContent = 'ضع قيمة c من الملف ثم اضغط فكّ. (n أوّلي، والرتبة = n−1)'; });
  // determine the group order from n and the chosen type; returns {order, how} or {error} or {need}
  function meOrder(n) {
    const t = $('#meType').value;
    if (t === 'prime') { if (!C.isProbablePrime(n)) return { warn: 'ملاحظة: n لا يبدو أوّلياً، لكن سأستخدم n−1 كما طلبت.', order: n - 1n, how: 'n−1 (قلت إنه أوّلي)' }; return { order: n - 1n, how: 'n−1 (n أوّلي ✓)' }; }
    if (t === 'pq') { const p = meField('#meP'), q = meField('#meQ'); if (p == null || q == null) return { error: 'أدخل p و q.' }; if (p * q !== n) return { error: 'p·q لا يساوي n (p·q = ' + (p*q) + ').' }; if (!C.isProbablePrime(p) || !C.isProbablePrime(q)) return { warn: 'تحذير: p أو q لا يبدو أوّلياً.', order: (p-1n)*(q-1n), how: '(p−1)(q−1)' }; return { order: (p-1n)*(q-1n), how: '(p−1)(q−1)' }; }
    if (t === 'factors') {
      const raw = $('#meP').value.trim(); if (!raw) return { error: 'أدخل العوامل.' };
      const fac = {}; let prod = 1n;
      for (const part of raw.split(/[,\s]+/).filter(Boolean)) { const m = part.split('^'); const P = C.parseBigFlexible(m[0]); if (P == null) return { error: 'عامل غير صالح: ' + part }; const k = m[1] ? BigInt(m[1]) : 1n; fac[P] = (fac[P] || 0n) + k; prod *= P ** k; }
      if (prod !== n) return { error: 'حاصل ضرب العوامل لا يساوي n (= ' + prod + ').' };
      return { order: C.phiFromFactors(fac), how: 'φ(n) من العوامل' };
    }
    // auto
    if (C.isProbablePrime(n)) return { order: n - 1n, how: 'n−1 (n أوّلي ✓)' };
    const r = C.factorize(n, 1.2e6);
    if (!r.factors) return { needFactors: true };
    const fs = Object.entries(r.factors).map(([p, k]) => k > 1n ? p + '^' + k : p).join(' · ');
    return { order: C.phiFromFactors(r.factors), how: 'φ(n) من التحليل: ' + fs };
  }
  function meShowSecret(h, m) {
    const bytes = C.bigToBytes(m), txt = C.bytesToText(bytes), fl = C.findFlags(txt);
    let out = h;
    out += `<tr><th>secret (عشري)</th><td class="mono">${esc(m.toString())}</td><td>${copyBtn(m.toString())}</td></tr>`;
    out += `<tr><th>secret (hex)</th><td class="mono">0x${esc(m.toString(16))}</td><td>${copyBtn('0x'+m.toString(16))}</td></tr>`;
    out += `<tr><th>secret (نص)</th><td class="mono">${C.findFlags(txt).length ? '<b style=\"color:var(--mint)\">'+vis(txt)+'</b>' : vis(txt)}</td><td>${copyBtn(txt)}</td></tr>`;
    return { rows: out, flag: fl[0] };
  }
  $('#meDec').addEventListener('click', () => {
    const n = meField('#meN'), e = meField('#meE'), c = meField('#meC');
    if (n == null || e == null || c == null) { $('#meOut').innerHTML = `<div class="noflag">⚠️ أدخل n و e و c (أرقام أو صيغ مثل 2^136+85).</div>`; return; }
    if (c >= n) { $('#meOut').innerHTML = `<div class="noflag">⚠️ c أكبر من أو يساوي n — تحقّق من القيم.</div>`; return; }
    const t0 = performance.now(), od = meOrder(n);
    if (od.error) { $('#meOut').innerHTML = `<div class="noflag">⚠️ ${esc(od.error)}</div>`; return; }
    if (od.needFactors) { $('#meOut').innerHTML = `<div class="noflag">🧮 n ليس أوّلياً ولم أستطع تحليله بسرعة. إن عرفت عوامله (مثلاً من factordb.com) اختر «عوامل معروفة» وأدخلها، أو «n = p·q».</div>`; return; }
    const order = od.order, g = C.bgcd(((e % order) + order) % order, order);
    let h = `<div class="card"><h3>🔓 النتيجة</h3><table><tr><th>الرتبة المستخدمة</th><td class="mono">${esc(od.how)}</td><td></td></tr>`;
    if (g !== 1n) {
      h += `</table><div class="tag warn" style="margin-top:8px">gcd(e, order) = ${esc(g.toString())} ≠ 1</div><div class="muted small-t" style="margin-top:6px">لا يوجد مقلوب فريد للأسّ، فهناك عدة جذور. هذا يحتاج خوارزمية جذر e-th (مثل Adleman–Manders–Miller) غير مدعومة هنا. إن كان e صغيراً جرّب «مساعد RSA» في تبويب الهاش للجذر الصحيح، أو قلّل المسألة يدوياً.</div></div>`;
      $('#meOut').innerHTML = h; return;
    }
    const d = C.modinv(e, order), m = C.modpow(c, d, n), verify = C.modpow(m, e, n) === c;
    h += `<tr><th>d = e⁻¹ mod order</th><td class="mono">${esc(d.toString())}</td><td>${copyBtn(d.toString())}</td></tr>`;
    const r = meShowSecret(h, m);
    let body = r.rows + `<tr><th>تحقّق</th><td>${verify ? '<span class="tag good">✅ secret^e mod n = c — صحيح</span>' : '<span class="tag bad">⚠️ لا يتطابق</span>'}</td><td></td></tr></table>`;
    body += `<div class="btns">${copyBtn(m.toString(),'📋 نسخ العشري')}${sendBtn('scan', C.bytesToText(C.bigToBytes(m)), '🔎 افحص النص')}</div></div>`;
    let full = r.flag ? renderFlags([{ flag: r.flag, method: 'فك أسّي (RSA، n أوّلي)' }]) : '';
    full += body + `<div class="status">⏱️ ${ms(t0)} ملّي ثانية</div>`;
    $('#meOut').innerHTML = full;
  });
  $('#meEnc').addEventListener('click', () => {
    const n = meField('#meN'), e = meField('#meE'), m = meField('#meC');
    if (n == null || e == null || m == null) { $('#meOut').innerHTML = `<div class="noflag">⚠️ أدخل n و e والرسالة m (في خانة c).</div>`; return; }
    const c = C.modpow(((m % n) + n) % n, e, n);
    $('#meOut').innerHTML = `<div class="card"><h3>🔒 التشفير</h3><table><tr><th>c = m^e mod n (عشري)</th><td class="mono">${esc(c.toString())}</td><td>${copyBtn(c.toString())}</td></tr><tr><th>c (hex)</th><td class="mono">0x${esc(c.toString(16))}</td><td>${copyBtn('0x'+c.toString(16))}</td></tr></table></div>`;
  });

  window.UI = { sendTo, setField, fillRSA, openBytes, openPython, showTab, copy };
  showTab(location.hash.slice(1) || 'scan');
  updateCipherTools();
})();
