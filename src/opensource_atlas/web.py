"""Local-only web dashboard for OpenSource Atlas."""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .github import GitHubAPIError, fetch_repository
from .report import build_report, to_markdown
from .scoring import score_repository

PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenSource Atlas</title><style>
:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#0b1020;color:#e8edf7;--muted:#9aa9c2;--line:#2b3851;--mint:#8be9d0}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0,#1a304a,transparent 45%),#0b1020;min-height:100vh}
main{max-width:1080px;margin:auto;padding:26px 18px 56px}.head{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:20px}.brand{display:flex;gap:12px;align-items:center}.logo{background:linear-gradient(135deg,#8be9d0,#8cb8ff);color:#081421;border-radius:12px;padding:12px;font-weight:900}h1{font-size:20px;margin:0}.muted{color:var(--muted);font-size:13px}.hero{padding:42px 0 24px;max-width:780px}.eyebrow{color:var(--mint);text-transform:uppercase;letter-spacing:2px;font-size:12px;font-weight:700}h2{font-size:clamp(30px,5vw,48px);line-height:1.1;letter-spacing:-1px;margin:14px 0}p{line-height:1.6}.hero p{color:var(--muted)}form{display:flex;gap:8px;background:#111a2d;border:1px solid #34435f;padding:8px;border-radius:14px;margin-top:22px}input{flex:1;min-width:0;background:transparent;border:0;outline:0;padding:12px;color:white;font-size:15px}button{border:0;border-radius:10px;background:var(--mint);color:#081721;padding:12px 16px;font-weight:800;cursor:pointer}button:disabled{opacity:.5}.hint{font-size:12px;color:var(--muted);margin:10px 4px}.notice{display:none;padding:13px;border-radius:10px;background:#302319;border:1px solid #785b38;color:#ffdda5}.notice.show{display:block}.results{display:none;margin-top:28px}.results.show{display:block}.row{display:flex;justify-content:space-between;align-items:end;gap:14px;margin:26px 0 12px}.row h3{margin:0}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card{background:#121b2d;border:1px solid var(--line);border-radius:15px;padding:17px;min-width:0}.label{font-size:12px;color:var(--muted)}.value{font-size:23px;font-weight:750;margin-top:8px;overflow-wrap:anywhere}.small{font-size:12px;color:var(--muted);margin-top:6px}.summary{display:grid;grid-template-columns:230px 1fr;gap:12px}.score{display:flex;flex-direction:column;justify-content:center}.score strong{font-size:56px;letter-spacing:-2px}.bar{height:7px;background:#2a3650;border-radius:99px;overflow:hidden;margin-top:12px}.bar i{display:block;height:100%;background:linear-gradient(90deg,#8be9d0,#8cb8ff);width:0}.component{border:1px solid var(--line);border-radius:11px;padding:12px;margin-bottom:9px}.component:last-child{margin-bottom:0}.ctop{display:flex;justify-content:space-between;gap:8px;font-size:13px}.component p{font-size:12px;color:var(--muted);margin-bottom:0}.actions{display:flex;gap:8px;flex-wrap:wrap}.secondary{background:#202c42;color:#e8edf7;border:1px solid #394862}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{color:var(--muted);font-weight:600}.notes{color:var(--muted);line-height:1.7;font-size:13px}.foot{border-top:1px solid var(--line);padding-top:18px;margin-top:40px;color:var(--muted);font-size:12px}@media(max-width:700px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.summary{grid-template-columns:1fr}.head .pill{display:none}}@media(max-width:460px){form{flex-direction:column}.grid{grid-template-columns:1fr 1fr}}
</style></head><body><main>
<header class="head"><div class="brand"><div class="logo">A</div><div><h1>OpenSource Atlas</h1><div class="muted">Repository Intelligence · Early access</div></div></div><div class="pill muted">Evidence-first analysis</div></header>
<section class="hero"><div class="eyebrow">Understand the project behind the stars</div><h2>Map the health of any public GitHub repository.</h2><p>Explore project signals, transparent heuristic scoring, and evidence in one concise report. Metadata is a starting point—not a code or security audit.</p><form id="form"><input id="repo" maxlength="2048" placeholder="owner/repository or GitHub URL" aria-label="GitHub repository" required><button id="submit">Analyze repository ↗</button></form><div class="hint">Public repositories only · No sign-in required · API rate limits may apply</div></section>
<div id="notice" class="notice" role="alert"></div><section id="results" class="results">
<div class="row"><div><h3 id="name">Repository overview</h3><div id="description" class="muted"></div></div><div class="actions"><button id="json" class="secondary">Export JSON</button><button id="md" class="secondary">Export Markdown</button></div></div>
<div id="stats" class="grid"></div><div class="row"><h3>Health indicator</h3><div id="basis" class="muted"></div></div>
<div class="summary"><div class="card score"><div class="label">Metadata-based score</div><div><strong id="score">—</strong><span class="muted"> / 100</span></div><div class="bar"><i id="scorebar"></i></div><div class="small">Heuristic triage signal, not a quality guarantee.</div></div><div class="card" id="components"></div></div>
<div class="row"><h3>Evidence & limitations</h3><span class="muted">Interpret in context</span></div><div class="card"><ul id="notes" class="notes"></ul><p class="muted">This report does not inspect source code, dependencies, vulnerabilities, or maintainer intent.</p></div>
<div class="row"><h3>Report details</h3><span class="muted">Raw GitHub metadata</span></div><div class="card"><table><tbody id="details"></tbody></table></div>
</section><footer class="foot">OpenSource Atlas · <a style="color:#8be9d0" href="https://github.com/liminghao540-cyber/OpenSource-Atlas">View source on GitHub</a> · No credentials collected</footer></main>
<script>
const $=id=>document.getElementById(id);let reportData=null;
function node(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n}
function stat(label,value,sub){const d=node('div',undefined,'card');d.append(node('div',label,'label'),node('div',value==null?'Unknown':value,'value'),node('div',sub,'small'));return d}
function detail(label,value){const tr=document.createElement('tr');tr.append(node('th',label),node('td',value==null?'Unknown':value));return tr}
function render(r){reportData=r;const repo=r.repository,h=r.health;$('name').textContent=repo.name||'Unknown repository';$('description').textContent=repo.description||'No description provided.';
$('stats').replaceChildren(stat('Stars',repo.stars==null?'Unknown':repo.stars.toLocaleString(),'Community interest signal'),stat('Forks',repo.forks==null?'Unknown':repo.forks.toLocaleString(),'Reuse signal'),stat('Open issues',repo.open_issues==null?'Unknown':repo.open_issues.toLocaleString(),'GitHub issue count'),stat('License',repo.license||'Not declared',repo.archived?'Repository archived':'License metadata'));
$('score').textContent=h.score==null?'—':h.score;$('basis').textContent=h.score_basis||'Score basis unavailable';$('scorebar').style.width=(h.score||0)+'%';const cs=$('components');cs.replaceChildren();
(h.components||[]).forEach(c=>{const d=node('div',undefined,'component'),top=node('div',undefined,'ctop');top.append(node('strong',c.name),node('span',c.points+' / '+c.max_points));const bar=node('div',undefined,'bar'),i=document.createElement('i');i.style.width=(c.max_points?100*c.points/c.max_points:0)+'%';bar.append(i);d.append(top,bar,node('p',c.evidence));cs.append(d)});
const ns=$('notes');ns.replaceChildren();(h.notes||[]).forEach(n=>ns.append(node('li',n)));
const dt=$('details');dt.replaceChildren(detail('Repository URL',repo.url),detail('Visibility',repo.visibility),detail('Default branch',repo.default_branch),detail('Created',repo.created_at),detail('Last updated',repo.updated_at),detail('Latest push',repo.pushed_at),detail('Topics',(repo.topics||[]).join(', ')||'None listed'),detail('Homepage',repo.homepage||'Not listed'),detail('Archived',repo.archived),detail('Report generated',r.generated_at));$('results').classList.add('show');$('notice').classList.remove('show')}
function error(message){$('notice').textContent=message;$('notice').classList.add('show')}
function download(name,type,text){const u=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
$('json').onclick=()=>{if(reportData)download('atlas-report.json','application/json',JSON.stringify(reportData,null,2))};
$('md').onclick=async()=>{if(!reportData)return;try{const r=await fetch('/api/markdown',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report:reportData})});if(!r.ok)throw Error('Markdown export failed.');download('atlas-report.md','text/markdown',await r.text())}catch(e){error(e.message)}};
$('form').onsubmit=async e=>{e.preventDefault();const b=$('submit');b.disabled=true;b.textContent='Analyzing…';try{const res=await fetch('/api/inspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repository:$('repo').value})});const data=await res.json();if(!res.ok)throw Error(data.error||'Request failed.');render(data)}catch(err){error(err.message||'Could not analyze repository.')}finally{b.disabled=false;b.textContent='Analyze repository ↗'}};
</script></body></html>'''


def analyze_repository(value: str) -> dict:
    repository = fetch_repository(value)
    return build_report(repository, score_repository(repository))


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenSourceAtlas/0.1"

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if urlparse(self.path).path != "/":
            self.send_body(404, b"Not found", "text/plain; charset=utf-8")
            return
        self.send_body(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/inspect", "/api/markdown"}:
            self.send_body(404, b'{"error":"Not found"}', "application/json; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1048576:
            self.send_body(413, b'{"error":"Request body must be between 1 byte and 1 MiB."}', "application/json; charset=utf-8")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_body(400, b'{"error":"Request body must be valid JSON."}', "application/json; charset=utf-8")
            return
        if path == "/api/markdown":
            report = payload.get("report") if isinstance(payload, dict) else None
            if not isinstance(report, dict) or not isinstance(report.get("repository"), dict) or not isinstance(report.get("health"), dict):
                self.send_body(400, b'{"error":"A valid report object is required."}', "application/json; charset=utf-8")
                return
            self.send_body(200, to_markdown(report).encode("utf-8"), "text/markdown; charset=utf-8")
            return
        value = payload.get("repository") if isinstance(payload, dict) else None
        if not isinstance(value, str) or not value.strip():
            self.send_body(400, b'{"error":"Provide owner/name or a GitHub URL."}', "application/json; charset=utf-8")
            return
        if len(value) > 2048:
            self.send_body(400, b'{"error":"Repository input is too long."}', "application/json; charset=utf-8")
            return
        try:
            report = analyze_repository(value)
        except (GitHubAPIError, ValueError) as exc:
            self.send_body(400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json; charset=utf-8")
            return
        self.send_body(200, json.dumps(report, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("For safety, the dashboard only binds to localhost.")
    server = ThreadingHTTPServer((host, port), Handler)
    print("OpenSource Atlas dashboard: http://" + host + ":" + str(port))
    print("Press Ctrl+C to stop. Local-only; uses public GitHub metadata.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OpenSource Atlas dashboard...")
    finally:
        server.server_close()


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
