/* Shared local presentation only. No credential access or network calls. */
(function () {
  "use strict";
  const ICONS = {"search": "<circle cx=\"11\" cy=\"11\" r=\"6.5\"/><path d=\"m20 20-4.2-4.2\"/>", "grid": "<rect x=\"4\" y=\"4\" width=\"6.5\" height=\"6.5\" rx=\"1.6\"/><rect x=\"13.5\" y=\"4\" width=\"6.5\" height=\"6.5\" rx=\"1.6\"/><rect x=\"4\" y=\"13.5\" width=\"6.5\" height=\"6.5\" rx=\"1.6\"/><rect x=\"13.5\" y=\"13.5\" width=\"6.5\" height=\"6.5\" rx=\"1.6\"/>", "vault": "<rect x=\"3.5\" y=\"4.5\" width=\"17\" height=\"15\" rx=\"3\"/><circle cx=\"12\" cy=\"12\" r=\"3.2\"/><path d=\"M12 8.8v-1M12 16.2v-1M15.2 12h1M7.8 12h1\"/>", "star": "<path d=\"m12 4 2.4 4.9 5.4.8-3.9 3.8.9 5.4-4.8-2.6-4.8 2.6.9-5.4L4.2 9.7l5.4-.8z\"/>", "shield": "<path d=\"M12 3.5 5 6v5.5c0 4.4 3 7.8 7 9 4-1.2 7-4.6 7-9V6z\"/><path d=\"m9 12 2 2 4-4\"/>", "dice": "<rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"4\"/><circle cx=\"9\" cy=\"9\" r=\".9\" fill=\"currentColor\"/><circle cx=\"15\" cy=\"15\" r=\".9\" fill=\"currentColor\"/><circle cx=\"15\" cy=\"9\" r=\".9\" fill=\"currentColor\"/><circle cx=\"9\" cy=\"15\" r=\".9\" fill=\"currentColor\"/>", "share": "<circle cx=\"17\" cy=\"6\" r=\"2.5\"/><circle cx=\"7\" cy=\"12\" r=\"2.5\"/><circle cx=\"17\" cy=\"18\" r=\"2.5\"/><path d=\"m9.2 10.8 5.6-3.4M9.2 13.2l5.6 3.4\"/>", "device": "<rect x=\"3\" y=\"5\" width=\"13\" height=\"10\" rx=\"2\"/><path d=\"M6 19h7\"/><rect x=\"17.5\" y=\"9\" width=\"4\" height=\"10\" rx=\"1.2\"/>", "pulse": "<path d=\"M3 12h4l2.5-6 5 12 2.5-6h4\"/>", "lock": "<rect x=\"5\" y=\"10.5\" width=\"14\" height=\"10\" rx=\"2.5\"/><path d=\"M8 10.5V8a4 4 0 0 1 8 0v2.5\"/>", "moon": "<path d=\"M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10z\"/>", "sun": "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4\"/>", "plus": "<path d=\"M12 5v14M5 12h14\"/>", "copy": "<rect x=\"8.5\" y=\"8.5\" width=\"11\" height=\"11\" rx=\"2.5\"/><path d=\"M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2\"/>", "eye": "<path d=\"M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z\"/><circle cx=\"12\" cy=\"12\" r=\"2.8\"/>", "eyeoff": "<path d=\"M4 4l16 16M10 6c.6-.1 1.3-.2 2-.2 6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.6 3.4M6.5 7.6C4 9.4 2.5 12 2.5 12S6 18.5 12 18.5c1.8 0 3.3-.5 4.6-1.3\"/>", "arrow": "<path d=\"M7 17 17 7M8.5 7H17v8.5\"/>", "spark": "<path d=\"M12 3c.6 4.6 2.4 6.4 7 7-4.6.6-6.4 2.4-7 7-.6-4.6-2.4-6.4-7-7 4.6-.6 6.4-2.4 7-7zM19 16c.2 1.6.9 2.3 2.5 2.5-1.6.2-2.3.9-2.5 2.5-.2-1.6-.9-2.3-2.5-2.5 1.6-.2 2.3-.9 2.5-2.5z\"/>", "x": "<path d=\"M6 6l12 12M18 6 6 18\"/>", "refresh": "<path d=\"M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4\"/>", "key": "<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"m11 12 8.5-8.5M16.5 6.5l2.5 2.5M14 9l2 2\"/>", "gear": "<circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M12 3.5v2.2M12 18.3v2.2M3.5 12h2.2M18.3 12h2.2M6 6l1.6 1.6M16.4 16.4 18 18M6 18l1.6-1.6M16.4 7.6 18 6\"/>", "chev": "<path d=\"m9 6 6 6-6 6\"/>", "phone": "<rect x=\"7\" y=\"3\" width=\"10\" height=\"18\" rx=\"2.5\"/><path d=\"M11 18h2\"/>", "ext": "<path d=\"M9 4.5a2 2 0 0 1 4 0V6h4v4h1.5a2 2 0 0 1 0 4H17v5H6v-4h1.5a2 2 0 0 0 0-4H6V6h3z\"/>", "globe": "<circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M3.5 12h17M12 3.5c2.5 2.6 2.5 14.4 0 17M12 3.5c-2.5 2.6-2.5 14.4 0 17\"/>", "palette": "<path d=\"M12 3.5a8.5 8.5 0 0 0 0 17c1.2 0 1.8-.8 1.8-1.7 0-1.2-1-1.5-1-2.6 0-.9.7-1.6 1.6-1.6h2.1a4 4 0 0 0 4-4C20.5 6.8 16.7 3.5 12 3.5z\"/><circle cx=\"7.8\" cy=\"11\" r=\"1.1\" fill=\"currentColor\"/><circle cx=\"10.5\" cy=\"7.4\" r=\"1.1\" fill=\"currentColor\"/><circle cx=\"15\" cy=\"7.6\" r=\"1.1\" fill=\"currentColor\"/>", "pen": "<path d=\"M4 20h4L19 9l-4-4L4 16z\"/><path d=\"m13.5 6.5 4 4\"/>", "card": "<rect x=\"3\" y=\"5.5\" width=\"18\" height=\"13\" rx=\"2.5\"/><path d=\"M3 10h18M7 15h3\"/>", "note": "<path d=\"M6 3.5h8l4 4v13H6z\"/><path d=\"M14 3.5v4h4M9 12h6M9 15.5h6\"/>", "user": "<circle cx=\"12\" cy=\"8.5\" r=\"3.8\"/><path d=\"M4.5 20c1.2-3.6 4-5.3 7.5-5.3s6.3 1.7 7.5 5.3\"/>", "dots": "<circle cx=\"6\" cy=\"12\" r=\"1.2\" fill=\"currentColor\"/><circle cx=\"12\" cy=\"12\" r=\"1.2\" fill=\"currentColor\"/><circle cx=\"18\" cy=\"12\" r=\"1.2\" fill=\"currentColor\"/>"};
  const THEMES = ["night", "paper", "macchiato", "latte"];
  const KEY = "velaInstrumentTheme";
  const api = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : null;
  const escape = value => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const icon = (name, size = 18) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.shield}</svg>`;
  const glyphs = ["11111/10001/10011/10101/11001/10001/11111","00100/01100/00100/00100/00100/00100/01110","11110/00001/00001/01110/10000/10000/11111","11110/00001/00001/01110/00001/00001/11110","10010/10010/10010/11111/00010/00010/00010","11111/10000/10000/11110/00001/00001/11110","01111/10000/10000/11110/10001/10001/01110","11111/00001/00010/00100/01000/01000/01000","01110/10001/10001/01110/10001/10001/01110","01110/10001/10001/01111/00001/00001/11110"];
  function dots(value, pitch = 4) {
    const text = String(value); let circles = "";
    [...text].forEach((n,i) => glyphs[Number(n)]?.split("/").forEach((r,y) => [...r].forEach((v,x) => {
      circles += `<circle cx="${(i*6+x+.5)*pitch}" cy="${(y+.5)*pitch}" r="${pitch*.32}" opacity="${v==='1'?1:.09}"/>`;
    })));
    const width = Math.max(1, text.length*6-1)*pitch;
    return `<svg class="vela-dot-matrix" role="img" aria-label="${escape(text)}" viewBox="0 0 ${width} ${7*pitch}" width="${width}" height="${7*pitch}" fill="currentColor">${circles}</svg>`;
  }
  function mark() {
    return `<svg width="20" height="26" viewBox="0 0 20 26" fill="currentColor" aria-hidden="true">${Array.from({length:8},(_,y)=>[0,1].map(x=>`<circle cx="${y<5?3+x*14:3+x*14+(x?-1:1)*(y-4)*2}" cy="${2+y*3}" r="1.1"/>`).join("")).join("")}</svg>`;
  }
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-vela-theme", THEMES.includes(theme) ? theme : "night");
  }
  async function setTheme(theme) {
    if (!THEMES.includes(theme)) return;
    applyTheme(theme);
    await api?.storage?.local?.set({[KEY]:theme});
  }
  function animateReadout(el) {
    if (!el || matchMedia("(prefers-reduced-motion: reduce)").matches || !el.animate) return;
    el.animate([{opacity:.4,transform:"translateY(3px)"},{opacity:1,transform:"translateY(0)"}],{duration:180,easing:"ease-out"});
  }
  globalThis.VelaInstrument = {icon,dots,mark,setTheme,applyTheme,animateReadout};
  if (typeof document === "undefined") return;
  applyTheme("night");
  api?.storage?.local?.get(KEY).then(data => applyTheme(data[KEY])).catch(() => {});
  api?.storage?.onChanged?.addListener((changes, area) => { if (area === "local" && changes[KEY]) applyTheme(changes[KEY].newValue); });
  // Fonts are bundled. Resolving their URLs here also works for injected UI on arbitrary pages.
  if (api?.runtime?.getURL) {
    const assetRoot = api.runtime.getManifest?.()?.content_scripts?.[0]?.js?.some(name => name.startsWith("src/")) ? "src/shared/fonts" : "shared/fonts";
    const style = document.createElement("style");
    style.setAttribute("data-vela-ui", "true");
    style.textContent = [["VelaInter", "400"], ["VelaInter", "500"], ["VelaDisplay", "500"], ["VelaMono", "400"], ["VelaMono", "500"]].map(([name,weight]) => `@font-face{font-family:${name};font-weight:${weight};font-display:swap;src:url("${api.runtime.getURL(`${assetRoot}/${name}-${weight}.woff2`)}") format("woff2")}`).join("\n");
    document.documentElement.appendChild(style);
  }
})();
