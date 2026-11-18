/* صائد الأعلام — طبقة اللعب: نقاط الخبرة، المستويات، الأوسمة، المهمات، الاحتفالات */
(function () {
  'use strict';
  const C = window.CTF;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const KEY = 'ctfkit.game.v1';
  const TOOLS = ['scan', 'decode', 'cipher', 'file', 'hash', 'web'];

  const LEVELS = [[0, '🐣', 'مبتدئ'], [60, '🔍', 'مستكشف'], [180, '🕵️', 'محقق'], [400, '🧩', 'مفكّك شفرات'], [700, '🛡️', 'حارس رقمي'], [1100, '🚩', 'صائد أعلام'], [1600, '🏆', 'أسطورة CTF']];
  const BADGES = [
    { id: 'first', icon: '🚩', name: 'أول علم', desc: 'اعثر على أول علم' },
    { id: 'layers', icon: '🧅', name: 'مقشّر البصل', desc: 'افكك علماً مخفياً تحت طبقتين أو أكثر' },
    { id: 'caesar', icon: '🏛️', name: 'صديق قيصر', desc: 'اكسر شيفرة إزاحة (ROT)' },
    { id: 'xor', icon: '⚡', name: 'ساحر XOR', desc: 'استرجع علماً مشفّراً بـ XOR' },
    { id: 'pixels', icon: '🖼️', name: 'عين البكسل', desc: 'استخرج علماً من بتات الصورة (LSB)' },
    { id: 'meta', icon: '📸', name: 'محقق الصور', desc: 'اعثر على علم في بيانات EXIF' },
    { id: 'archive', icon: '📦', name: 'فاتح الصناديق', desc: 'اعثر على علم داخل أرشيف ZIP' },
    { id: 'png', icon: '🩹', name: 'طبيب الصور', desc: 'أصلح أبعاد صورة PNG معدّلة' },
    { id: 'audio', icon: '🎧', name: 'أذن ذهبية', desc: 'افتح المخطط الطيفي لملف صوتي' },
    { id: 'webdet', icon: '🕸️', name: 'محقق الويب', desc: 'اعثر على علم داخل طلب أو استجابة HTTP' },
    { id: 'hash', icon: '🧂', name: 'صائد الهاشات', desc: 'طابق هاشاً مع كلمته الأصلية' },
    { id: 'rsa', icon: '🔑', name: 'كاسر RSA', desc: 'فك رسالة RSA' },
    { id: 'explorer', icon: '🧭', name: 'المستكشف', desc: 'استخدم الأدوات الست كلها' },
    { id: 'flags10', icon: '🎯', name: 'عشرة أعلام', desc: 'اجمع 10 أعلام مختلفة' },
    { id: 'm5', icon: '⭐', name: 'خمس مهمات', desc: 'حلّ 5 مهمات تدريبية' },
    { id: 'mall', icon: '👑', name: 'بطل التدريب', desc: 'حلّ كل مهمات التدريب' },
  ];
  const MISSION_BADGE = { caesar: 'caesar', onion: 'layers', xor: 'xor', lsb: 'pixels', exif: 'meta', zip: 'archive', png: 'png', audio: 'audio', hash: 'hash', rsa: 'rsa', web: 'webdet' };
  const MISSIONS = window.CTF_MISSIONS || [];

  const def = () => ({ xp: 0, flags: [], tools: [], badges: [], solved: {}, hints: {}, name: '', toolXp: 0 });
  let st = def();
  try { st = Object.assign(def(), JSON.parse(localStorage.getItem(KEY) || '{}')); } catch (e) { }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(st)); } catch (e) { } };
  const levelOf = xp => { let i = 0; LEVELS.forEach((l, k) => { if (xp >= l[0]) i = k; }); return i; };

  /* ---------- feedback: toast, unlock card, confetti ---------- */
  let toastT;
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 1600); }
  const queue = []; let showing = false;
  function unlock(icon, small, title) { queue.push([icon, small, title]); if (!showing) nextUnlock(); }
  function nextUnlock() {
    const it = queue.shift(); if (!it) { showing = false; return; }
    showing = true; const u = $('#unlock');
    u.innerHTML = `<span class="ui">${it[0]}</span><div><small>${esc(it[1])}</small><b>${esc(it[2])}</b></div>`;
    u.classList.add('show'); setTimeout(() => { u.classList.remove('show'); setTimeout(nextUnlock, 350); }, 2300);
  }
  const cv = $('#confetti'); const cx = cv.getContext('2d'); let parts = [], raf = 0;
  function confetti(n = 120) {
    if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    cv.width = innerWidth; cv.height = innerHeight;
    const cols = ['#ffc93c', '#3ddc97', '#ff6b9a', '#5ac8fa', '#8b5cf6', '#ffffff'];
    for (let i = 0; i < n; i++) parts.push({ x: innerWidth / 2 + (Math.random() - .5) * 200, y: innerHeight / 3, vx: (Math.random() - .5) * 14, vy: -Math.random() * 12 - 4, s: 5 + Math.random() * 6, r: Math.random() * 6, vr: (Math.random() - .5) * .4, c: cols[i % cols.length], life: 90 + Math.random() * 50, e: Math.random() < .25 ? '🚩' : null });
    if (!raf) raf = requestAnimationFrame(step);
  }
  function step() {
    cx.clearRect(0, 0, cv.width, cv.height);
    parts = parts.filter(p => p.life-- > 0 && p.y < cv.height + 40);
    for (const p of parts) {
      p.vy += .35; p.vx *= .99; p.x += p.vx; p.y += p.vy; p.r += p.vr;
      cx.save(); cx.translate(p.x, p.y); cx.rotate(p.r); cx.globalAlpha = Math.min(1, p.life / 30);
      if (p.e) { cx.font = '18px serif'; cx.fillText(p.e, -9, 9); } else { cx.fillStyle = p.c; cx.fillRect(-p.s / 2, -p.s / 3, p.s, p.s * .66); }
      cx.restore();
    }
    raf = parts.length ? requestAnimationFrame(step) : 0;
    if (!raf) cx.clearRect(0, 0, cv.width, cv.height);
  }

  /* ---------- progression ---------- */
  function addXp(n, quiet) {
    if (n <= 0) return;
    const before = levelOf(st.xp); st.xp += n; save();
    if (!quiet) toast(`+${n} نقطة خبرة ✨`);
    const after = levelOf(st.xp);
    if (after > before) { const L = LEVELS[after]; unlock(L[1], 'مستوى جديد! ⬆️', `المستوى ${after + 1} — ${L[2]}`); confetti(180); }
    hud();
  }
  function badge(id) {
    if (st.badges.includes(id)) return;
    const b = BADGES.find(x => x.id === id); if (!b) return;
    st.badges.push(id); save(); unlock(b.icon, 'وسام جديد 🏅', b.name); addXp(20, true); confetti(90); hud();
  }
  function onFlags(list) {
    let gained = 0, celebrate = false;
    for (const f of list) {
      const k = f.flag.trim().toLowerCase();
      if (st.flags.includes(k)) continue;
      const plain = !f.method || /^(نص مباشر|مباشر)$/.test(f.method);
      if (f.likely === false || plain) continue; // only flags the tools actually uncovered count
      st.flags.push(k); celebrate = true;
      if (st.toolXp < 300) { gained += 10; st.toolXp += 10; }
      const m = f.method || '';
      if (/→/.test(m)) badge('layers');
      if (/ROT\d|قيصر/.test(m)) badge('caesar');
      if (/LSB/.test(m)) badge('pixels');
      if (/EXIF/.test(m)) badge('meta');
      if (/ZIP/.test(m)) badge('archive');
      if (/XOR|المفتاح 0x/.test(m)) badge('xor');
      if (/^HTTP/.test(m)) badge('webdet');
    }
    if (!st.flags.length) return;
    save();
    if (st.flags.length >= 1 && celebrate) badge('first');
    if (st.flags.length >= 10) badge('flags10');
    if (gained) addXp(gained);
    if (celebrate) confetti(70);
    hud();
  }
  function useTool(id) {
    if (!TOOLS.includes(id) || st.tools.includes(id)) return;
    st.tools.push(id); save(); addXp(5, true);
    if (TOOLS.every(t => st.tools.includes(t))) badge('explorer');
    hud();
  }
  function event(name) { ({ pngfix: 'png', audio: 'audio', hashmatch: 'hash', rsa: 'rsa', xor: 'xor' })[name] && badge(({ pngfix: 'png', audio: 'audio', hashmatch: 'hash', rsa: 'rsa', xor: 'xor' })[name]); }

  /* ---------- HUD & profile ---------- */
  function hud() {
    const i = levelOf(st.xp), L = LEVELS[i], N = LEVELS[i + 1];
    const pct = N ? (st.xp - L[0]) / (N[0] - L[0]) * 100 : 100;
    $('#hudAvatar').textContent = L[1]; $('#hudLevel').textContent = 'المستوى ' + (i + 1); $('#hudTitle').textContent = L[2];
    $('#hudXpFill').style.width = pct + '%'; $('#hudXp').textContent = st.xp; $('#hudNext').textContent = N ? N[0] : '—';
    $('#hudFlags').textContent = st.flags.length; $('#hudBadges').textContent = st.badges.length;
    const solved = MISSIONS.filter(m => st.solved[m.id]).length;
    $('#trainCount').textContent = solved + '/' + MISSIONS.length;
    if (!$('#profile').hidden) profile();
  }
  function profile() {
    const i = levelOf(st.xp), L = LEVELS[i], N = LEVELS[i + 1];
    $('#profAvatar').textContent = L[1]; $('#profName').value = st.name || '';
    $('#profLvl').textContent = `المستوى ${i + 1} — ${L[2]}`;
    $('#profXpFill').style.width = (N ? (st.xp - L[0]) / (N[0] - L[0]) * 100 : 100) + '%';
    $('#profXpText').textContent = N ? `${st.xp} / ${N[0]} نقطة خبرة للوصول إلى «${N[2]}»` : `${st.xp} نقطة خبرة — وصلت للقمة! 🏆`;
    const solved = MISSIONS.filter(m => st.solved[m.id]).length;
    $('#profStats').innerHTML = `<div><b>${st.xp}</b><span>نقاط الخبرة</span></div><div><b>${st.flags.length}</b><span>أعلام مجمّعة</span></div><div><b>${solved}/${MISSIONS.length}</b><span>مهمات محلولة</span></div><div><b>${st.badges.length}/${BADGES.length}</b><span>أوسمة</span></div>`;
    $('#profBadges').innerHTML = BADGES.map(b => `<div class="bdg ${st.badges.includes(b.id) ? 'got' : 'locked'}"><span class="bi">${b.icon}</span><b>${esc(b.name)}</b><span>${esc(b.desc)}</span></div>`).join('');
    $('#profLevels').innerHTML = LEVELS.map((l, k) => `<div class="${k === i ? 'cur' : k < i ? 'done' : ''}">${l[1]} ${k + 1}. ${esc(l[2])} <span class="muted small-t">${l[0]}+</span></div>`).join('');
  }
  $('#hudBtn').addEventListener('click', () => { $('#profile').hidden = false; profile(); });
  $('#profClose').addEventListener('click', () => { $('#profile').hidden = true; });
  $('#profile').addEventListener('click', e => { if (e.target.id === 'profile') $('#profile').hidden = true; });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#profile').hidden = true; });
  $('#profName').addEventListener('input', e => { st.name = e.target.value.slice(0, 30); save(); });
  let resetArm = false;
  $('#profReset').addEventListener('click', e => {
    if (!resetArm) { resetArm = true; e.target.textContent = 'متأكد؟ اضغط مرة أخرى'; setTimeout(() => { resetArm = false; e.target.textContent = 'إعادة ضبط التقدّم'; }, 3000); return; }
    st = def(); save(); resetArm = false; e.target.textContent = 'إعادة ضبط التقدّم'; hud(); profile(); renderMissions(); toast('تمت إعادة الضبط');
  });

  /* ---------- training missions ---------- */
  let filter = 'all';
  const b64ToBytes = b => { const s = atob(b); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; };
  const TOOLNAME = { decode: 'فك الترميز', cipher: 'الشيفرات', hash: 'الهاش والأرقام', file: 'تحليل الملفات', scan: 'الفحص السريع', web: 'أدوات الويب' };
  function renderMissions() {
    const box = $('#missions'); if (!box) return;
    const solved = MISSIONS.filter(m => st.solved[m.id]).length;
    $('#tpFill').style.width = (MISSIONS.length ? solved / MISSIONS.length * 100 : 0) + '%';
    const total = MISSIONS.reduce((a, m) => a + m.xp, 0), earned = MISSIONS.reduce((a, m) => a + (st.solved[m.id] || 0), 0);
    $('#tpText').textContent = `${solved} من ${MISSIONS.length} مهمة · ${earned} / ${total} نقطة`;
    box.innerHTML = MISSIONS.map((m, i) => {
      if (filter === 'todo' && st.solved[m.id]) return '';
      if (/^\d$/.test(filter) && String(m.stars) !== filter) return '';
      const ok = !!st.solved[m.id], hinted = !!st.hints[m.id];
      const body = m.fileData
        ? `<div class="file">📎 <b>${esc(m.file)}</b><span class="muted small-t">${Math.round(m.fileData.length * 3 / 4 / 1024 * 10) / 10} KB</span></div>`
        : `<div class="data"><pre>${esc(m.data)}</pre></div>`;
      return `<div class="mission ${ok ? 'solved' : ''}" data-mid="${m.id}">
        <div class="mh"><div class="mnum">${i + 1}</div><div><div class="mt">${esc(m.title)}</div>
        <div class="meta"><span class="stars">${'⭐'.repeat(m.stars)}</span> · <span class="xp">+${m.xp - (hinted ? 10 : 0)} XP</span> · الأداة: ${TOOLNAME[m.tool]}</div></div></div>
        <div class="story">${esc(m.story)}</div>
        ${body}
        <div class="btns" style="margin-top:0"><button class="small" data-act="open">🛠️ افتح في ${TOOLNAME[m.tool]}</button>${m.fileData ? '' : '<button class="small" data-act="copy">📋 نسخ</button>'}<button class="small" data-act="hint">💡 ${hinted ? 'التلميح' : 'تلميح (‎-10)'}</button></div>
        ${hinted ? `<div class="hint">💡 ${esc(m.hint)}</div>` : ''}
        <div class="answer"><input type="text" dir="ltr" placeholder="flag{...}" ${ok ? 'disabled value="✓"' : ''} spellcheck="false"><button class="primary small" data-act="check" ${ok ? 'disabled' : ''}>تحقّق</button></div>
        <div class="msg"></div></div>`;
    }).join('') || '<div class="noflag">لا توجد مهمات في هذا التصنيف 🎉</div>';
  }
  $('#trFilters').addEventListener('click', e => { const b = e.target.closest('[data-f]'); if (!b) return; filter = b.dataset.f; $$('#trFilters button').forEach(x => x.classList.toggle('on', x === b)); renderMissions(); });
  $('#missions').addEventListener('click', e => {
    const btn = e.target.closest('[data-act]'); if (!btn) return;
    const card = btn.closest('.mission'), m = MISSIONS.find(x => x.id === card.dataset.mid), UI = window.UI;
    const act = btn.dataset.act;
    if (act === 'open') {
      if (m.fileData) UI.openBytes(m.file, b64ToBytes(m.fileData));
      else if (m.rsa) UI.fillRSA(m.rsa);
      else if (m.id === 'big') UI.setField('nmIn', m.data, 'hash');
      else if (m.id === 'hash') UI.setField('hwHash', m.data, 'hash');
      else UI.sendTo(m.tool, m.data);
    } else if (act === 'copy') { UI.copy(m.data); }
    else if (act === 'hint') { if (!st.hints[m.id]) { st.hints[m.id] = true; save(); renderMissions(); } }
    else if (act === 'check') check(card, m);
  });
  $('#missions').addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.matches('.answer input')) { const card = e.target.closest('.mission'); check(card, MISSIONS.find(x => x.id === card.dataset.mid)); } });
  function check(card, m) {
    const inp = $('.answer input', card), msg = $('.msg', card), v = inp.value.trim().toLowerCase();
    if (!v) return;
    if (C.md5(v) === m.ans) {
      const reward = m.xp - (st.hints[m.id] ? 10 : 0);
      st.solved[m.id] = reward; if (!st.flags.includes(v)) st.flags.push(v); save();
      unlock('🎉', 'مهمة مكتملة!', m.title); confetti(160); addXp(reward);
      if (MISSION_BADGE[m.id]) badge(MISSION_BADGE[m.id]);
      if (st.flags.length >= 1) badge('first');
      const n = MISSIONS.filter(x => st.solved[x.id]).length;
      if (n >= 5) badge('m5'); if (n === MISSIONS.length) badge('mall');
      if (st.flags.length >= 10) badge('flags10');
      renderMissions(); hud();
    } else {
      msg.className = 'msg bad'; msg.textContent = ['ليس هذا… حاول مرة أخرى 🤔', 'قريب؟ تأكد من الصيغة flag{...}', 'لا تستسلم! جرّب التلميح 💡'][Math.floor(Math.random() * 3)];
      card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
    }
  }

  window.GAME = { onFlags, useTool, event, badge, addXp, renderMissions, toast, confetti, hud };
  hud(); renderMissions();
})();
