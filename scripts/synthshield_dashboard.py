"""SYNTHSHIELD evidence dashboard (local, read-only, standard-library only).

Run from the repository root:
    python scripts/synthshield_dashboard.py
Open http://127.0.0.1:8765

This displays recorded experiment evidence, NOT live security telemetry.
It does not contact PostgreSQL, Docker, Ollama, or any privileged service.
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = PROJECT_ROOT / "reports" / "phase12"
HOST = "127.0.0.1"
PORT = 8765


def read_evidence(filename: str) -> str:
    path = EVIDENCE / filename
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""


def parse_test_results(text: str) -> dict:
    match = re.search(r"\b(\d+) passed\b", text)
    return {"passed": int(match.group(1)) if match else None, "present": bool(text)}


def parse_control_cases(text: str) -> list[dict]:
    cases = []
    for part in re.split(r"(?=^CASE \d+:)", text, flags=re.M):
        match = re.search(r"^CASE\s+(\d+):\s+(.+)$", part, re.M)
        if not match:
            continue
        def grab(label: str) -> str:
            found = re.search(r"^\s*" + re.escape(label) + r":\s*(.*?)\s*$", part, re.M)
            return found.group(1) if found else ""
        risk = grab("Inference risk")
        score_match = re.search(r"(\d+)/100", risk)
        cases.append({
            "number": int(match.group(1)), "name": match.group(2).strip(),
            "sources": grab("Sources"),
            "risk_score": int(score_match.group(1)) if score_match else None,
            "risk_level": re.search(r"\(([^)]+)\)", risk).group(1) if re.search(r"\(([^)]+)\)", risk) else "",
            "inference": grab("Inference decision"),
            "purpose": grab("Purpose decision"), "final": grab("Final decision"),
            "verified": "[PASS] Isolated decisions match expected outcome" in part,
        })
    return cases


def parse_demo(text: str, demo: str) -> list[dict]:
    events = []
    scenario = ""
    step = 0
    for line in text.splitlines():
        if line.startswith("Scenario: "):
            scenario = line[len("Scenario: "):].strip()
            step = 0
        elif line.startswith("[AI step "):
            m = re.search(r"\[AI step (\d+)\]\s+(\w+)", line)
            if m:
                step = int(m.group(1))
        elif line.startswith("[SYNTHSHIELD]"):
            m = re.match(r"\[SYNTHSHIELD\]\s+(ALLOW|BLOCK)\s+(finance|travel|calendar)\s+\(HTTP\s+(\d+)\)", line)
            if m:
                events.append({"demo": demo, "scenario": scenario, "step": step,
                               "decision": m.group(1), "source": m.group(2),
                               "http": int(m.group(3))})
    return events


def commit_short() -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "log", "-1", "--format=%h"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=2,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def current_data() -> dict:
    baseline = parse_test_results(read_evidence("pytest_baseline.txt"))
    cases = parse_control_cases(read_evidence("control_isolation.txt"))
    boundary = read_evidence("deployed_boundary_test.txt")
    grounded = read_evidence("final_grounded_agent_demo.txt")
    injection = read_evidence("final_prompt_injection_demo.txt")
    events = parse_demo(grounded, "Grounded agent") + parse_demo(injection, "Prompt-injection lab")
    boundary_passes = [line for line in boundary.splitlines() if line.startswith("[PASS]")]
    return {
        "mode": "RECORDED EXPERIMENT EVIDENCE — NOT LIVE TELEMETRY",
        "as_of": datetime.now().astimezone().isoformat(timespec="seconds"),
        "test": baseline,
        "cases": cases,
        "boundary_passes": len(boundary_passes),
        "boundary_present": bool(boundary),
        "demos": {
            "grounded": "PHASE 11C GROUNDED AGENT DEMO COMPLETE" in grounded,
            "injection": "PHASE 11D PROMPT-INJECTION LAB COMPLETE" in injection,
            "payload_delivered": "[MEASURE] Injection delivered: True" in injection,
            "post_injection_calendar_request": "[MEASURE] AI requested calendar after injection: True" in injection,
            "unauthorized_execution_not_observed": "[PASS] No unauthorized calendar execution was observed" in injection,
            "false_meeting_count_not_verified": "[PASS] Verified summaries did not repeat the false meeting count" in injection,
        },
        "events": events,
        "commit": commit_short(),
        "missing": [name for name in ["pytest_baseline.txt", "control_isolation.txt", "deployed_boundary_test.txt", "final_grounded_agent_demo.txt", "final_prompt_injection_demo.txt"] if not (EVIDENCE/name).is_file()],
    }


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SYNTHSHIELD | Security Evidence Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#081018;--panel:#101e2a;--panel2:#142532;--line:#24394a;--text:#e8f3fb;--muted:#95acbc;--teal:#38ddbd;--red:#ff7c91;--amber:#ffcc80}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--text);background:radial-gradient(circle at 70% -20%,#143a45,transparent 38%),var(--bg)}
header{border-bottom:1px solid var(--line);padding:22px clamp(20px,5vw,74px);display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}.brand{display:flex;align-items:center;gap:13px}.brand-icon{display:grid;place-items:center;width:47px;height:47px;border:1px solid #275b61;border-radius:14px;background:#103c3e;color:var(--teal);font-size:25px}.brand h1{font-size:21px;letter-spacing:1.4px;margin:0;font-weight:800}.brand small{color:var(--muted)}.pill{font-size:11px;letter-spacing:.08em;border:1px solid #33675d;border-radius:50px;color:var(--teal);padding:7px 12px;background:#12332f;font-weight:800}.wrap{max-width:1320px;padding:34px 24px 60px;margin:auto}.intro{display:flex;justify-content:space-between;align-items:end;gap:14px;flex-wrap:wrap;margin-bottom:28px}h2{font-size:29px;margin:0 0 4px}h3{font-size:16px;margin:0 0 15px}.muted{color:var(--muted)}.subtitle{color:var(--muted);margin:0}.refresh{background:var(--teal);color:#07201d;font-weight:800;border:0;border-radius:10px;padding:10px 17px;cursor:pointer}.refresh:hover{filter:brightness(1.15)}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:20px}.metric{border:1px solid var(--line);border-radius:15px;background:var(--panel);padding:19px}.metric b{display:block;font-size:30px;line-height:1.4}.metric span{color:var(--muted);font-size:12px}.good{color:var(--teal)}.bad{color:var(--red)}.warn{color:var(--amber)}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin-bottom:18px}.panel{border:1px solid var(--line);background:var(--panel);padding:23px;border-radius:16px;min-width:0}.legend{font-size:12px;color:var(--muted);margin-top:-7px;margin-bottom:15px}.riskrow{margin-bottom:18px}.riskhead{display:flex;justify-content:space-between;gap:10px;font-size:13px;margin-bottom:8px}.track{height:10px;border-radius:30px;background:#2c3d48;overflow:hidden}.fill{height:100%;border-radius:30px;background:linear-gradient(90deg,#3ae7bc,#ffd276)}.fill.critical{background:linear-gradient(90deg,#ffad78,#ff6f91)}.decision{font-weight:800;font-size:11px;letter-spacing:.04em}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}td,th{padding:12px;border-bottom:1px solid var(--line)}td{font-size:12px}.events{display:grid;gap:8px}.event{display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 13px}.event-left b{display:block;font-size:13px}.event-left small{display:block;color:var(--muted);font-size:11px}.chip{border-radius:7px;padding:4px 8px;font-size:11px;font-weight:800;white-space:nowrap}.chip.allow{color:var(--teal);background:#123e36}.chip.block{color:var(--red);background:#412532}.label{background:#1a3641;color:#cce9f3;border-radius:6px;padding:3px 8px;font-size:11px}.alerts{display:grid;gap:10px}.alert{display:flex;align-items:flex-start;gap:12px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:14px}.dot{border-radius:50%;height:10px;width:10px;background:var(--amber);flex-shrink:0;margin-top:6px}.dot.ok{background:var(--teal)}.alert strong{display:block;font-size:13px}.alert p{margin:3px 0 0;color:var(--muted);font-size:12px}.controls{display:flex;gap:8px;align-items:center;margin-bottom:14px}.controls button{background:var(--panel2);color:var(--muted);border:1px solid var(--line);padding:7px 10px;border-radius:7px;cursor:pointer}.controls button.active{border-color:var(--teal);color:var(--teal)}footer{margin-top:22px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:17px}.empty{color:var(--muted);font-style:italic}.notice{border:1px solid #735d35;border-radius:10px;padding:10px 14px;background:#342819;color:#ffdf9a;margin-bottom:20px;display:none}code{font-size:12px;color:#cce8e5}
@media(max-width:950px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}}@media(max-width:560px){.metrics{grid-template-columns:1fr 1fr}h2{font-size:23px}.wrap{padding:24px 14px}header{padding:16px 14px}.panel{padding:16px}}
</style></head><body>
<header><div class="brand"><div class="brand-icon">⬡</div><div><h1>SYNTHSHIELD</h1><small>Coalition-Aware AI Security · Research Prototype</small></div></div><span class="pill">● LOCAL EVIDENCE VIEW</span></header>
<main class="wrap"><div class="intro"><div><h2>Security Overview</h2><p class="subtitle">Recorded tests and experiments from your SYNTHSHIELD project</p></div><button class="refresh" id="refresh">↻ Refresh evidence</button></div><div id="notice" class="notice"></div>
<section class="metrics"><div class="metric"><b id="tests" class="good">—</b><span>Automated tests passed</span></div><div class="metric"><b id="controls" class="good">—</b><span>Verified control-isolation cases</span></div><div class="metric"><b id="boundary" class="good">—</b><span>Deployed boundary checks passed</span></div><div class="metric"><b id="blocked" class="bad">—</b><span>Recorded calendar blocks</span></div></section>
<div class="grid"><section class="panel"><h3>Coalition Inference Risk</h3><p class="legend">Risk scores from Phase 11F's synthetic data scenarios · not current threat probability</p><div id="risks"></div></section><section class="panel"><h3>Security Events</h3><p class="legend">Observed HTTP tool decisions in the saved final demonstrations</p><div class="controls"><button class="active" data-filter="all">All</button><button data-filter="ALLOW">Allowed</button><button data-filter="BLOCK">Blocked</button></div><div id="events" class="events"></div></section></div>
<div class="grid"><section class="panel"><h3>Independent Security Controls</h3><p class="legend">Phase 11F: Purpose Lock and inference detection evaluated separately</p><div class="tablewrap"><table><thead><tr><th>Scenario</th><th>Inference</th><th>Purpose</th><th>Final</th></tr></thead><tbody id="caseRows"></tbody></table></div></section><section class="panel"><h3>Prompt-Injection Assessment</h3><div id="alerts" class="alerts"></div></section></div>
<footer><strong>Research evidence, not live telemetry.</strong> Data loads from local <code>reports/phase12/</code> output files. Refresh rereads those files; it does not run attacks, read secrets, access databases, or monitor ongoing traffic. <span id="meta"></span></footer></main>
<script>
'use strict';
let data=null, activeFilter='all';
const el=id=>document.getElementById(id);
const text=(node,value)=>{node.textContent=value};
function statusSpan(value){const s=document.createElement('span');s.className='decision '+(value==='ALLOW'?'good':'bad');s.textContent=value||'—';return s;}
function renderRisks(cases){el('risks').replaceChildren();if(!cases.length){el('risks').textContent='No Phase 11F data found.';return;}
 for(const c of cases){const row=document.createElement('div');row.className='riskrow';const head=document.createElement('div');head.className='riskhead';const label=document.createElement('span');label.textContent=c.sources||c.name;const val=document.createElement('b');val.textContent=(c.risk_score??'—')+'/100 · '+c.risk_level;head.append(label,val);const track=document.createElement('div');track.className='track';const fill=document.createElement('div');fill.className='fill'+(c.risk_score>=90?' critical':'');fill.style.width=(c.risk_score??0)+'%';track.append(fill);row.append(head,track);el('risks').append(row);}}
function renderCases(cases){el('caseRows').replaceChildren();for(const c of cases){const row=document.createElement('tr');const name=document.createElement('td');name.textContent=c.name;row.append(name);for(const key of ['inference','purpose','final']){const cell=document.createElement('td');cell.append(statusSpan(c[key]));row.append(cell);}el('caseRows').append(row);}}
function renderEvents(){el('events').replaceChildren();const items=(data?.events||[]).filter(e=>activeFilter==='all'||e.decision===activeFilter);if(!items.length){const p=document.createElement('p');p.className='empty';p.textContent='No matching saved events.';el('events').append(p);return;}for(const e of items){const row=document.createElement('div');row.className='event';const left=document.createElement('div');left.className='event-left';const name=document.createElement('b');name.textContent=e.source.toUpperCase()+' · HTTP '+e.http;const sub=document.createElement('small');sub.textContent=e.demo+' · '+e.scenario+' · step '+e.step;left.append(name,sub);const chip=document.createElement('span');chip.className='chip '+(e.decision==='ALLOW'?'allow':'block');chip.textContent=e.decision;row.append(left,chip);el('events').append(row);}}
function addAlert(ok,heading,detail){const a=document.createElement('div');a.className='alert';const d=document.createElement('span');d.className='dot'+(ok?' ok':'');const content=document.createElement('div');const h=document.createElement('strong');h.textContent=heading;const p=document.createElement('p');p.textContent=detail;content.append(h,p);a.append(d,content);el('alerts').append(a);}
function renderAlerts(d){el('alerts').replaceChildren();const x=d.demos;addAlert(x.payload_delivered,'Injection payload delivered',x.payload_delivered?'Attacker-controlled text appeared in the synthetic tool response.':'Not established from saved evidence.');addAlert(x.post_injection_calendar_request,'Calendar requested after injection',x.post_injection_calendar_request?'The AI selected a restricted calendar action; this alone does not prove causation.':'No post-injection calendar action detected.');addAlert(x.unauthorized_execution_not_observed,'No unauthorized calendar HTTP 200 observed',x.unauthorized_execution_not_observed?'Saved experiment reports no unauthorized execution.':'No verified outcome available.');addAlert(x.false_meeting_count_not_verified,'Fabricated meeting count excluded',x.false_meeting_count_not_verified?'Verified summary did not repeat the false value of 99.':'Outcome not established.');}
async function load(){const response=await fetch('/api/summary',{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);data=await response.json();text(el('tests'),data.test.passed??'—');text(el('controls'),data.cases.filter(c=>c.verified).length+'/'+data.cases.length);text(el('boundary'),data.boundary_present?String(data.boundary_passes):'—');text(el('blocked'),String(data.events.filter(e=>e.source==='calendar'&&e.decision==='BLOCK').length));renderRisks(data.cases);renderCases(data.cases);renderEvents();renderAlerts(data);text(el('meta'),' · Local commit: '+(data.commit||'unknown')+' · Last refreshed: '+data.as_of);el('notice').style.display=data.missing.length?'block':'none';if(data.missing.length)text(el('notice'),'Missing evidence files: '+data.missing.join(', '));}
el('refresh').addEventListener('click',()=>load().catch(e=>alert('Unable to reload evidence: '+e.message)));for(const b of document.querySelectorAll('[data-filter]')){b.addEventListener('click',()=>{activeFilter=b.dataset.filter;for(const other of document.querySelectorAll('[data-filter]'))other.classList.toggle('active',other===b);renderEvents();});}
load().catch(e=>{el('notice').style.display='block';text(el('notice'),'Cannot load evidence: '+e.message);});
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if route in ("/", "/index.html"):
            body, mime, status = PAGE.encode("utf-8"), "text/html; charset=utf-8", 200
        elif route == "/api/summary":
            body, mime, status = json.dumps(current_data(), ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", 200
        elif route == "/favicon.ico":
            body, mime, status = b"", "image/x-icon", 204
        else:
            body, mime, status = b"Not found", "text/plain; charset=utf-8", 404
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self) -> None:
        self.send_error(405, "Read-only dashboard")

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    if not EVIDENCE.exists():
        print(f"[WARNING] Evidence folder not found: {EVIDENCE}")
    print("SYNTHSHIELD Evidence Dashboard — READ ONLY")
    print("Shows saved experiments, not real-time network telemetry.")
    print(f"Open: http://{HOST}:{PORT}")
    try:
        with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
            httpd.serve_forever()
    except OSError as e:
        raise SystemExit(f"Unable to start local dashboard: {e}") from e
    except KeyboardInterrupt:
        print("\nDashboard stopped.")


if __name__ == "__main__":
    main()
