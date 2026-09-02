/* ================================================================
   Shared chart primitives for dashboard.html (owner views + the admin console).
   No external chart library — plain SVG (donut) and CSS transitions
   (bars) so everything stays on-brand and dependency-free. Loaded via
   a plain <script src="/charts.js"> before each page's own inline
   <script>, so window.renderDonut / wireTooltips / animateIn are
   ready by the time page code calls them.

   renderDonut() is safe to call again on the same container on every
   poll: the first call builds the SVG/legend DOM and reveals it from
   a zero-length arc (the "load with animation" case); every later
   call on an already-built container just updates the existing
   circles' stroke-dasharray/dashoffset in place, so a live-refresh
   smoothly morphs the wedges instead of restarting the draw-in.
   ================================================================ */
(function () {
  let tip = null;
  function tipEl() {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'chart-tooltip';
      document.body.appendChild(tip);
    }
    return tip;
  }
  function showTooltip(x, y, html) {
    const t = tipEl();
    t.innerHTML = html;
    t.classList.add('show');
    const pad = 16;
    t.style.left = (x + pad) + 'px';
    t.style.top = (y + pad) + 'px';
    const r = t.getBoundingClientRect();
    if (r.right > window.innerWidth - 8) t.style.left = Math.max(8, x - r.width - pad) + 'px';
    if (r.bottom > window.innerHeight - 8) t.style.top = Math.max(8, y - r.height - pad) + 'px';
  }
  function hideTooltip() { if (tip) tip.classList.remove('show'); }

  // Any element with data-tip-label (+ optional data-tip-value) gets a hover
  // tooltip — used for bar-chart rows/segments. These are read as *plain
  // text* and escaped here, once, right before going into the tooltip's
  // innerHTML — never accept pre-built HTML through a data attribute:
  // billboard/company/area names are user-controlled, and a value that's
  // already "escaped for the attribute" decodes back to raw markup by the
  // time you read el.dataset, so passing it straight to innerHTML from
  // there would be a stored-XSS hole. Labels/values that are always
  // hardcoded strings (the donut's own legend) build their tooltip HTML
  // directly in renderDonut() instead of going through this path.
  function wireTooltips(root) {
    (root || document).querySelectorAll('[data-tip-label]').forEach(el => {
      if (el.dataset.tipWired) return;
      el.dataset.tipWired = '1';
      const build = () => '<b>' + esc(el.dataset.tipLabel) + '</b>' + (el.dataset.tipValue ? '<br>' + esc(el.dataset.tipValue) : '');
      el.addEventListener('mouseenter', e => showTooltip(e.clientX, e.clientY, build()));
      el.addEventListener('mousemove', e => showTooltip(e.clientX, e.clientY, build()));
      el.addEventListener('mouseleave', hideTooltip);
    });
  }

  // Bar fills / segmented-bar wedges render at their resting size with
  // data-anim-val holding the real target (width % or flex-basis %) —
  // this flips them to that value one frame after mount so the CSS
  // transition already on .bar-fill / .util-bar .seg actually animates
  // the draw-in instead of just appearing at full size.
  function animateIn(root) {
    (root || document).querySelectorAll('[data-anim-val]').forEach(el => {
      requestAnimationFrame(() => requestAnimationFrame(() => {
        el.style[el.dataset.animProp || 'width'] = el.dataset.animVal;
      }));
    });
  }

  const R = 46, CX = 60, CY = 60, SW = 16;
  const CIRC = 2 * Math.PI * R;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // segments: [{ key, label, value, colorClass }] — colorClass is one of
  // green/amber/red/blue/accent/muted, resolved through CSS (.donut-c-*,
  // .donut-dot.c-*) rather than inline var() on an SVG presentation
  // attribute, matching how the rest of the app themes by classname.
  // opts: { centerLabel, formatTotal(n), formatValue(n) }
  function renderDonut(container, segments, opts) {
    opts = opts || {};
    const total = segments.reduce((s, seg) => s + (seg.value || 0), 0);
    const fresh = container.dataset.donutInit !== '1';

    if (fresh) {
      container.dataset.donutInit = '1';
      container.innerHTML =
        '<div class="donut-wrap">' +
          '<div class="donut-svg-box">' +
            '<svg viewBox="0 0 120 120" class="donut-svg">' +
              '<circle class="donut-track" cx="' + CX + '" cy="' + CY + '" r="' + R + '" stroke-width="' + SW + '"></circle>' +
              '<g class="donut-segs" transform="rotate(-90 ' + CX + ' ' + CY + ')"></g>' +
            '</svg>' +
            '<div class="donut-center">' +
              '<div class="donut-center-value"></div>' +
              '<div class="donut-center-label">' + esc(opts.centerLabel || 'Total') + '</div>' +
            '</div>' +
          '</div>' +
          '<div class="donut-legend"></div>' +
        '</div>';
      const g = container.querySelector('.donut-segs');
      segments.forEach(seg => {
        const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        c.setAttribute('cx', CX); c.setAttribute('cy', CY); c.setAttribute('r', R);
        c.setAttribute('stroke-width', SW);
        c.setAttribute('fill', 'none');
        c.setAttribute('stroke-dasharray', '0 ' + CIRC.toFixed(2));
        c.setAttribute('class', 'donut-seg donut-c-' + seg.colorClass);
        g.appendChild(c);
      });
      container.querySelector('.donut-legend').innerHTML = segments.map(seg =>
        '<div class="donut-legend-item" data-key="' + esc(seg.key) + '">' +
          '<i class="donut-dot c-' + seg.colorClass + '"></i>' +
          '<span class="donut-legend-label">' + esc(seg.label) + '</span>' +
          '<span class="donut-legend-value"></span>' +
        '</div>'
      ).join('');
    }

    const g = container.querySelector('.donut-segs');
    const legend = container.querySelector('.donut-legend');
    let offset = 0;
    segments.forEach((seg, i) => {
      const circle = g.children[i];
      const pct = total ? seg.value / total : 0;
      const len = pct * CIRC;
      const myOffset = offset;
      const apply = () => {
        circle.setAttribute('stroke-dasharray', len.toFixed(2) + ' ' + (CIRC - len).toFixed(2));
        circle.setAttribute('stroke-dashoffset', (-myOffset).toFixed(2));
      };
      if (fresh) requestAnimationFrame(() => requestAnimationFrame(apply));
      else apply();
      offset += len;

      // seg.label is always one of this file's own hardcoded strings (role/
      // status/etc. keys) — never user-controlled text — so building this
      // tooltip's HTML directly is safe; anything reader-supplied (company/
      // billboard/area names) goes through the escape-twice wireTooltips()
      // path above instead.
      const tipHtml = '<b>' + esc(seg.label) + '</b><br>' +
        (opts.formatValue ? opts.formatValue(seg.value) : seg.value) +
        (total ? ' · ' + Math.round(pct * 100) + '%' : '');
      circle.onmouseenter = e => { showTooltip(e.clientX, e.clientY, tipHtml); circle.classList.add('hover'); };
      circle.onmousemove = e => showTooltip(e.clientX, e.clientY, tipHtml);
      circle.onmouseleave = () => { hideTooltip(); circle.classList.remove('hover'); };

      const item = legend.children[i];
      if (item) {
        item.querySelector('.donut-legend-value').textContent = opts.formatValue ? opts.formatValue(seg.value) : seg.value;
        item.onmouseenter = e => { showTooltip(e.clientX, e.clientY, tipHtml); circle.classList.add('hover'); };
        item.onmousemove = e => showTooltip(e.clientX, e.clientY, tipHtml);
        item.onmouseleave = () => { hideTooltip(); circle.classList.remove('hover'); };
      }
    });

    const center = container.querySelector('.donut-center-value');
    if (center) center.textContent = opts.formatTotal ? opts.formatTotal(total) : total;
    container.querySelector('.donut-svg-box').classList.toggle('empty', !total);
  }

  window.renderDonut = renderDonut;
  window.chartTooltip = { show: showTooltip, hide: hideTooltip };
  window.wireTooltips = wireTooltips;
  window.animateIn = animateIn;
})();
