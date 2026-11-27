function renderManagementInkShanShui() {
  function hash(n) {
    const x = Math.sin(n * 127.1 + 311.7) * 43758.5453123;
    return x - Math.floor(x);
  }
  function noise1D(x, seed) {
    const i = Math.floor(x);
    const f = x - i;
    const u = f * f * (3 - 2 * f);
    return hash(i + seed) * (1 - u) + hash(i + 1 + seed) * u;
  }
  function fbm(x, seed, octaves) {
    let v = 0, amp = 0.5, freq = 1;
    for (let o = 0; o < octaves; o++) {
      v += amp * noise1D(x * freq, seed + o * 19.3);
      freq *= 2.05;
      amp *= 0.5;
    }
    return v;
  }

  document.querySelectorAll(".ink-sidebar").forEach(sb => {
    if (sb.querySelector(".sidebar-ink-canvas")) return;
    const c = document.createElement("canvas");
    c.className = "sidebar-ink-canvas";
    c.setAttribute("aria-hidden", "true");
    const W = 476, H = 1040;
    c.width = W;
    c.height = H;
    sb.insertBefore(c, sb.firstChild);
    const ctx = c.getContext("2d");
    if (!ctx) return;

    const smokeGrad = ctx.createRadialGradient(W * 0.72, H * 0.34, 20, W * 0.65, H * 0.42, W * 0.95);
    smokeGrad.addColorStop(0, "rgba(138, 142, 146, 0.22)");
    smokeGrad.addColorStop(0.55, "rgba(78, 82, 86, 0.10)");
    smokeGrad.addColorStop(1, "rgba(24, 25, 27, 0)");
    ctx.fillStyle = smokeGrad;
    ctx.fillRect(0, 0, W, H);

    function drawRidge(baseY, amp, scale, seed, fillTop, fillBot, goldStroke) {
      const pts = [];
      ctx.beginPath();
      ctx.moveTo(0, H);
      for (let x = 0; x <= W; x += 3) {
        const env = 0.65 + 0.55 * Math.sin((x / W) * Math.PI * 0.92 + 0.3);
        const y = baseY - fbm(x * scale, seed, 5) * amp * env;
        pts.push([x, y]);
        ctx.lineTo(x, y);
      }
      ctx.lineTo(W, H);
      ctx.closePath();
      const g = ctx.createLinearGradient(0, baseY - amp, 0, H);
      g.addColorStop(0, fillTop);
      g.addColorStop(1, fillBot);
      ctx.fillStyle = g;
      ctx.fill();

      if (goldStroke) {
        ctx.save();
        ctx.beginPath();
        pts.forEach(([x, y], idx) => {
          if (idx === 0) ctx.moveTo(x, y + 1.5);
          else ctx.lineTo(x, y + 1.5);
        });
        const gg = ctx.createLinearGradient(W * 0.08, 0, W * 0.92, 0);
        gg.addColorStop(0, "rgba(216, 180, 106, 0)");
        gg.addColorStop(0.35, goldStroke);
        gg.addColorStop(0.75, "rgba(230, 198, 128, 0.52)");
        gg.addColorStop(1, "rgba(180, 140, 65, 0.08)");
        ctx.strokeStyle = gg;
        ctx.lineWidth = 2.2;
        ctx.stroke();
        ctx.restore();
      }
    }

    drawRidge(H * 0.52, 210, 0.007, 4.2, "rgba(98, 103, 108, 0.40)", "rgba(28, 30, 33, 0.85)", null);

    const mist1 = ctx.createRadialGradient(W * 0.48, H * 0.56, 10, W * 0.48, H * 0.58, W * 0.72);
    mist1.addColorStop(0, "rgba(238, 235, 226, 0.22)");
    mist1.addColorStop(0.6, "rgba(210, 207, 198, 0.08)");
    mist1.addColorStop(1, "rgba(25, 26, 28, 0)");
    ctx.fillStyle = mist1;
    ctx.fillRect(0, H * 0.28, W, H * 0.55);

    drawRidge(H * 0.66, 240, 0.0095, 13.7, "rgba(36, 38, 42, 0.92)", "rgba(14, 15, 17, 0.98)", "rgba(208, 168, 90, 0.44)");
    drawRidge(H * 0.81, 205, 0.012, 29.1, "rgba(15, 16, 18, 0.95)", "rgba(8, 9, 10, 1)", "rgba(197, 155, 72, 0.26)");

    for (let i = 0; i < 15; i++) {
      const cx = (hash(i * 3.1) * 0.68 - 0.08) * W;
      const cy = H * (0.74 + hash(i * 7.7) * 0.26);
      const rx = 70 + hash(i * 5.3) * 125;
      const mg = ctx.createRadialGradient(cx, cy, 4, cx, cy, rx);
      const alpha = 0.13 + hash(i * 11.9) * 0.15;
      mg.addColorStop(0, `rgba(244, 241, 234, ${alpha})`);
      mg.addColorStop(0.55, `rgba(222, 218, 208, ${alpha * 0.45})`);
      mg.addColorStop(1, "rgba(244, 241, 234, 0)");
      ctx.fillStyle = mg;
      ctx.beginPath();
      ctx.arc(cx, cy, rx, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let s = 0; s < 32; s++) {
      const sx = hash(s * 17.3) * W * 0.62;
      const sy = H * (0.77 + hash(s * 23.1) * 0.22);
      const sr = 1.2 + Math.pow(hash(s * 31.7), 2.4) * 8.5;
      ctx.fillStyle = `rgba(18, 19, 21, ${0.26 + hash(s * 41.2) * 0.52})`;
      ctx.beginPath();
      ctx.ellipse(sx, sy, sr * 1.25, sr * 0.85, hash(s) * Math.PI, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let g = 0; g < 12; g++) {
      const gx = W * (0.18 + hash(g * 19.9) * 0.68);
      const gy = H * (0.50 + hash(g * 29.3) * 0.34);
      const gr = 1.0 + hash(g * 37.1) * 1.7;
      ctx.fillStyle = `rgba(226, 193, 120, ${0.24 + hash(g * 13.3) * 0.34})`;
      ctx.beginPath();
      ctx.arc(gx, gy, gr, 0, Math.PI * 2);
      ctx.fill();
    }

    const topFade = ctx.createLinearGradient(0, 0, 0, H * 0.30);
    topFade.addColorStop(0, "rgba(24, 25, 27, 1)");
    topFade.addColorStop(1, "rgba(24, 25, 27, 0)");
    ctx.fillStyle = topFade;
    ctx.fillRect(0, 0, W, H * 0.30);
  });

  document.querySelectorAll(".ledger-heading").forEach(banner => {
    if (banner.querySelector(".banner-mist-canvas")) return;
    const bc = document.createElement("canvas");
    bc.className = "banner-mist-canvas";
    bc.setAttribute("aria-hidden", "true");
    const BW = 1400, BH = 260;
    bc.width = BW;
    bc.height = BH;
    banner.insertBefore(bc, banner.firstChild);
    const bctx = bc.getContext("2d");
    if (!bctx) return;

    function bannerRidge(baseY, amp, scale, seed, rgbaTop, goldRgba) {
      bctx.beginPath();
      bctx.moveTo(BW * 0.14, BH);
      const pts = [];
      for (let x = Math.floor(BW * 0.14); x <= BW; x += 4) {
        const fadeLeft = Math.min(1, (x - BW * 0.14) / (BW * 0.28));
        const y = baseY - fbm(x * scale, seed, 4) * amp * fadeLeft;
        pts.push([x, y]);
        bctx.lineTo(x, y);
      }
      bctx.lineTo(BW, BH);
      bctx.closePath();
      const g = bctx.createLinearGradient(0, baseY - amp, 0, BH);
      g.addColorStop(0, rgbaTop);
      g.addColorStop(1, "rgba(250, 248, 243, 0)");
      bctx.fillStyle = g;
      bctx.fill();

      if (goldRgba) {
        bctx.beginPath();
        pts.forEach(([x, y], i) => (i === 0 ? bctx.moveTo(x, y) : bctx.lineTo(x, y)));
        bctx.strokeStyle = goldRgba;
        bctx.lineWidth = 1.4;
        bctx.stroke();
      }
    }

    bannerRidge(BH * 0.86, 145, 0.0045, 8.1, "rgba(116, 122, 128, 0.09)", null);
    bannerRidge(BH * 0.94, 110, 0.0062, 21.4, "rgba(197, 155, 72, 0.08)", "rgba(197, 155, 72, 0.24)");
  });
}

async function initManagementOidcSso() {
  const tokenInput = document.querySelector('input[type="password"]');
  const lockForm = tokenInput ? tokenInput.closest("form") : null;
  if (!tokenInput || !lockForm) return;
  if (tokenInput.maxLength > 0 && tokenInput.maxLength < 16384) {
    tokenInput.maxLength = 16384;
  }

  const hash = location.hash || "";
  if (hash.startsWith("#oidc_ticket=")) {
    const ticket = decodeURIComponent(hash.slice("#oidc_ticket=".length));
    history.replaceState(null, "", location.pathname + location.search);
    if (ticket) {
      try {
        const res = await fetch("/auth/oidc/exchange", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ticket }),
          cache: "no-store",
          credentials: "same-origin",
        });
        if (res.ok) {
          const data = await res.json();
          if (data.access_token) {
            tokenInput.value = data.access_token;
            lockForm.requestSubmit();
            return;
          }
        }
      } catch {
        // Leave manual credential login available as fallback.
      }
    }
  }

  try {
    const res = await fetch("/auth/oidc/status", { cache: "no-store" });
    if (!res.ok) return;
    const info = await res.json();
    if (!info || info.enabled !== true) return;
    const box = document.createElement("div");
    box.className = "oidc-sso-box";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.id = "manage-oidc-login-button";
    btn.className = "primary-button btn-ink";
    btn.textContent = "用公司账号一键登录（SSO）";
    btn.addEventListener("click", () => {
      window.location.assign(`/auth/oidc/login?return_to=${encodeURIComponent(location.pathname)}`);
    });
    box.append(btn);
    lockForm.parentElement?.insertBefore(box, lockForm);
  } catch {
    // Ignore when OIDC SSO status endpoint is unavailable.
  }
}

renderManagementInkShanShui();
initManagementOidcSso();
