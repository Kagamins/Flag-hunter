/* صائد الأعلام — فك JSFuck بأمان.
   الفكرة: JSFuck يتكوّن فقط من []()!+ ولا يستطيع تشغيل أي كود إلا عبر Function constructor.
   نستبدل Function.prototype.constructor بفخّ: الدوال المساعدة الصغيرة التي يحتاجها JSFuck
   (return escape / unescape / Date / this ...) تُسمح، وأي كود آخر يُلتقط كنص ولا يُنفَّذ أبداً.
   التشغيل داخل Web Worker معزول مع مهلة زمنية. Browser: window.CTFJ   Node: module.exports */
(function (root, factory) {
  const J = factory();
  if (typeof module === 'object' && module.exports) module.exports = J; else root.CTFJ = J;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  const J = {};
  J.CHARSET = /^[\[\]()!+\s]+$/;
  J.isJSFuck = s => { const t = (s || '').trim(); return t.length >= 8 && J.CHARSET.test(t) && /\[\]/.test(t) && /!/.test(t) && /\+/.test(t); };

  // يعمل داخل الـ Worker (أو داخل الصفحة كخطة بديلة). لا يعتمد على أي متغير خارجي.
  function sandboxRun(code) {
    const RealFunction = Function;
    const payloads = [];
    const SAFE = [
      /^return\s*(escape|unescape|Date|String|Number|RegExp|Math|Object|Array|Boolean|atob|btoa|encodeURI|decodeURI|encodeURIComponent|decodeURIComponent|parseInt|parseFloat|isNaN|isFinite|Symbol|JSON)\s*;?\s*$/,
      /^return\s*\/[^\/\n]*\/[gimsuy]*\s*;?\s*$/,
      /^return\s*new\s+Date\(\s*-?\d+\s*\)\s*;?\s*$/,
      /^return\s*(-?\d+(\.\d+)?|"[^"\\]*"|'[^'\\]*'|\{\s*\}|\[\s*\]|true|false|null|undefined|NaN|Infinity)\s*;?\s*$/,
    ];
    const fakeGlobal = Object.freeze({ toString: () => '[object Window]' });
    function Trap() {
      const args = Array.prototype.slice.call(arguments).map(String);
      const body = args.length ? args[args.length - 1] : '';
      const b = body.trim();
      if (/^return\s*this\s*;?$/.test(b)) return function () { return fakeGlobal; };
      if (SAFE.some(r => r.test(b))) return RealFunction(body);
      payloads.push({ params: args.slice(0, -1), body });
      return function () { return undefined; };
    }
    Trap.prototype = RealFunction.prototype;
    // JSFuck reads letters from String(Function), so the trap must look exactly like the native one
    const nativeSrc = RealFunction.prototype.toString.call(RealFunction);
    Object.defineProperty(Trap, 'name', { value: 'Function' });
    Object.defineProperty(Trap, 'toString', { value: function () { return nativeSrc; } });
    const desc = Object.getOwnPropertyDescriptor(RealFunction.prototype, 'constructor');
    Object.defineProperty(RealFunction.prototype, 'constructor', { value: Trap, writable: true, configurable: true });
    let result, error, type;
    try { result = RealFunction('return (' + code + '\n)')(); type = typeof result; }
    catch (err) { error = String((err && err.message) || err); }
    finally { Object.defineProperty(RealFunction.prototype, 'constructor', desc); }
    let text = null;
    try { text = type === 'function' ? '[function]' : type === 'undefined' ? null : String(result); } catch (e) { text = '[unprintable]'; }
    return { payloads, result: text, type, error };
  }
  J._sandboxRun = sandboxRun;

  let workerURL = null;
  function getWorkerURL() {
    if (workerURL) return workerURL;
    const src = 'const sandboxRun = ' + sandboxRun.toString() + ';\nself.onmessage = e => { self.postMessage(sandboxRun(e.data)); };';
    workerURL = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
    return workerURL;
  }

  // يعيد Promise بـ {payloads, result, type, error, via}
  J.run = (code, timeout = 5000) => new Promise(resolve => {
    const t = (code || '').trim();
    if (!J.CHARSET.test(t)) { resolve({ payloads: [], result: null, error: 'النص يحتوي على رموز غير مسموحة في JSFuck (المسموح فقط [ ] ( ) ! +)' }); return; }
    let w;
    try { w = new Worker(getWorkerURL()); }
    catch (e) { const r = sandboxRun(t); r.via = 'page'; resolve(r); return; }
    const timer = setTimeout(() => { w.terminate(); resolve({ payloads: [], result: null, error: 'انتهت المهلة (' + timeout / 1000 + ' ثوانٍ)', via: 'worker' }); }, timeout);
    w.onmessage = e => { clearTimeout(timer); w.terminate(); resolve(Object.assign(e.data, { via: 'worker' })); };
    w.onerror = e => { clearTimeout(timer); w.terminate(); e.preventDefault && e.preventDefault(); const r = sandboxRun(t); r.via = 'page'; resolve(r); };
    w.postMessage(t);
  });

  // فك متكرر: إن كان الكود المستخرج نفسه JSFuck نفكّه مرة أخرى (حتى 4 طبقات)
  J.deobfuscate = async (code, maxLayers = 4) => {
    const layers = []; let cur = code;
    for (let i = 0; i < maxLayers; i++) {
      const r = await J.run(cur);
      layers.push(r);
      const next = r.payloads.length ? r.payloads[r.payloads.length - 1].body : r.result;
      if (!next || !J.isJSFuck(next)) break;
      cur = next;
    }
    const last = layers[layers.length - 1];
    const output = last.payloads.length ? last.payloads.map(p => p.params.length ? 'function (' + p.params.join(', ') + ') {\n' + p.body + '\n}' : p.body).join('\n\n// ---\n\n') : (last.result ?? '');
    return { layers, output, executedPayload: false, error: last.error };
  };
  return J;
});
