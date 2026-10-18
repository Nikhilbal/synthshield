"""Retro CRT / vintage-mainframe skin for the existing SYNTHSHIELD dashboard.

Install alongside `scripts/synthshield_dashboard.py` and run from repo root:
    python -m scripts.synthshield_dashboard_retro
Open http://127.0.0.1:8766

Only presentation is changed. Uses the same read-only recorded research evidence,
parsers and API handler as the existing evidence dashboard.
"""

from scripts import synthshield_dashboard as original

RETRO_CSS = r"""
/* VISUAL THEME ONLY — KEEP DATA AND AUTHORIZATION LOGIC UNCHANGED */
:root {
  color-scheme: dark;
  --bg: #080d09;
  --panel: #101b12;
  --panel2: #142317;
  --line: #3b6544;
  --text: #d8f2c9;
  --muted: #9eb89c;
  --teal: #b8ff85;
  --red: #ff8675;
  --amber: #ffd08a;
}
* { box-sizing: border-box; }
body {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  background:
    linear-gradient(90deg, transparent 0 96%, rgba(158,255,128,.025) 96% 100%),
    radial-gradient(circle at top center, #172b1b 0, #080d09 65%);
  background-size: 38px 38px, auto;
  letter-spacing: .015em;
}
body::after {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 999;
  background: repeating-linear-gradient(
    to bottom,
    transparent 0px, transparent 3px,
    rgba(0,0,0,.12) 3px, rgba(0,0,0,.12) 4px);
  opacity: .25;
}
header {
  border-bottom: 2px solid #68915e;
  background: #101a12;
  box-shadow: inset 0 -5px 0 rgba(143,216,121,.06);
}
.brand-icon {
  border-radius: 3px;
  background: #1f3c23;
  color: var(--teal);
  border: 1px solid #6b9c60;
  font-family: inherit;
}
.brand h1 {
  font-size: 22px;
  letter-spacing: .15em;
  text-shadow: 0 0 15px rgba(172,255,146,.17);
}
.brand small, .retro-banner, .metric span, th, .pill {
  text-transform: uppercase;
  letter-spacing: .11em;
}
.retro-tag { font-size: 11px; color: var(--amber); }
.retro-banner {
  border: 1px dashed #5c854e;
  background: #17261a;
  padding: 10px 14px;
  color: var(--teal);
  margin-bottom: 21px;
  font-size: 11px;
}
.pill {
  background: #1e3321;
  border: 1px solid #81bd70;
  border-radius: 2px;
  color: var(--teal);
}
.refresh, .controls button, .metric, .panel, .event, .alert, .notice,
.chip, .track, .label { border-radius: 2px; }
.metric, .panel {
  background: linear-gradient(140deg, #122017, #0c140f);
  border: 1px solid #426448;
  box-shadow: 3px 3px 0 rgba(108,158,97,.13), inset 0 1px 0 rgba(183,255,140,.045);
}
h2, h3 { text-transform: uppercase; letter-spacing: .06em; }
h2 { font-size: 24px; color: var(--teal); }
h2::before, h3::before { content: "> "; color: var(--amber); }
.metric b { color: var(--teal); font-weight: 800; }
.metric b.bad { color: var(--red); }
.track { background: #25372a; height: 12px; border: 1px solid #436247; }
.fill { background: repeating-linear-gradient(90deg, #7bbc68 0 8px, #c4e492 8px 11px); }
.fill.critical { background: repeating-linear-gradient(90deg, #c7604d 0 8px, #f2a17e 8px 11px); }
.event, .alert { border-left: 3px solid #568058; }
.chip.allow { background: #203920; color: #b8ff85; }
.chip.block { background: #412722; color: #ff967e; }
.refresh {
  color: #0b1809;
  background: #bcfc92;
  border: 1px solid #d3ffad;
  box-shadow: 3px 3px 0 #38583a;
  text-transform: uppercase;
}
.refresh:focus-visible, .controls button:focus-visible {
  outline: 2px solid #ffd08a;
  outline-offset: 3px;
}
.controls button.active { background: #233c25; }
td, th { border-bottom-color: #3b6042; }
a { color: #c5ffa3; }
::selection { background: #b8ff85; color: #0b120d; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
"""


def main() -> None:
    # Reuse the original handler, evidence parser, origin restriction, read-only
    # HTTP implementation, and protected API endpoint logic without duplicating it.
    if "</style>" not in original.PAGE:
        raise RuntimeError("Cannot find the dashboard style section; base UI changed.")
    page = original.PAGE.replace("</style>", RETRO_CSS + "\n</style>", 1)
    page = page.replace("<h1>SYNTHSHIELD</h1>",
                        '<h1>SYNTHSHIELD <span class="retro-tag">// RETRO MODE</span></h1>', 1)
    page = page.replace("● LOCAL EVIDENCE VIEW",
                        "◉ LOCAL ARCHIVE · RECORDED EVIDENCE", 1)
    page = page.replace("<h2>Security Overview</h2>",
                        "<h2>Security Evidence Console</h2>", 1)
    page = page.replace(
        '<main class="wrap">',
        '<main class="wrap"><div class="retro-banner">'
        'SYS:// SYNTHSHIELD / RESEARCH ARCHIVE · READ ONLY · '
        'DATA SOURCE: reports/phase12/ · NOT LIVE TELEMETRY'
        '</div>',
        1,
    )
    original.PAGE = page
    original.PORT = 8766
    original.main()


if __name__ == "__main__":
    main()
