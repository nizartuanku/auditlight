package webui

import "strings"

// indexHTML is the whole dashboard: markup, style and behaviour in one
// document, served from the binary. Nothing is fetched from the network, so the
// dashboard behaves identically on an air-gapped host.
const indexTemplateHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuditLight</title>
<style>
:root{
  --bg:#0c1016; --panel:#141a22; --panel2:#1a222c; --ink:#e8eef5; --muted:#93a1b1;
  --line:#232d3a; --accent:#5b8def; --accent-ink:#0c1016; --accent-soft:#16233b;
  --crit:#ff7b72; --high:#ffa657; --med:#e3b341; --low:#56d4a0; --info:#93a1b1;
  --ok:#56d4a0; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  --r:11px;
}
@media (prefers-color-scheme:light){
  :root{
    --bg:#f5f7fa; --panel:#ffffff; --panel2:#f0f3f7; --ink:#121821; --muted:#5c6773;
    --line:#e1e6ed; --accent:#2f6df6; --accent-ink:#ffffff; --accent-soft:#e9f0ff;
    --crit:#b3261e; --high:#c2410c; --med:#a16207; --low:#1d6b57; --info:#5c6773; --ok:#1d6b57;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.6}
button,input,textarea,select{font:inherit;color:inherit}
.app{max-width:1180px;margin:0 auto;padding:22px 20px 60px}
header{display:flex;align-items:center;justify-content:space-between;gap:18px;
  padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:22px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.brand svg{width:32px;height:32px;color:var(--accent)}
.bname{font-size:18px;font-weight:680;letter-spacing:-.015em}
.btag{font-size:12px;color:var(--muted)}
.lic{text-align:right;font-size:12.5px;color:var(--muted);max-width:420px}
.lic .tier{display:inline-block;padding:2px 10px;border-radius:999px;background:var(--accent-soft);
  color:var(--accent);font-weight:660;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.rail{display:flex;gap:8px;margin-bottom:22px;flex-wrap:wrap}
.step{flex:1;min-width:150px;display:flex;align-items:center;gap:10px;padding:11px 14px;
  background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  font-size:13.5px;color:var(--muted);transition:.18s}
.step .dot{width:23px;height:23px;border-radius:50%;background:var(--panel2);color:var(--muted);
  display:grid;place-items:center;font-size:12px;font-weight:680;flex:none;border:1px solid var(--line)}
.step.on{border-color:var(--accent);color:var(--ink);background:var(--accent-soft)}
.step.on .dot{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
.step.done .dot{background:var(--ok);color:var(--accent-ink);border-color:var(--ok)}
.step.done{color:var(--ink)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:20px 22px;margin-bottom:16px}
h2{font-size:17px;margin:0 0 4px;font-weight:660;letter-spacing:-.012em}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 16px}
label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted);font-weight:640;margin:0 0 6px}
textarea,input[type=text]{width:100%;background:var(--bg);border:1px solid var(--line);
  border-radius:9px;padding:10px 12px;font-family:var(--mono);font-size:13.5px;resize:vertical}
textarea:focus,input[type=text]:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.profiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(216px,1fr));gap:10px;margin-bottom:18px}
.prof{text-align:left;background:var(--panel2);border:1.5px solid var(--line);border-radius:10px;
  padding:13px 15px;cursor:pointer;transition:.15s}
.prof:hover:not(:disabled){border-color:var(--accent)}
.prof.sel{border-color:var(--accent);background:var(--accent-soft)}
.prof:disabled{opacity:.45;cursor:not-allowed}
.prof .t{font-weight:640;font-size:14.5px;margin-bottom:3px}
.prof .d{font-size:12.5px;color:var(--muted);line-height:1.5}
.prof .lock{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--med);margin-top:6px;font-weight:640}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.btn{background:var(--accent);color:var(--accent-ink);border:none;border-radius:9px;
  padding:11px 20px;font-weight:640;font-size:14px;cursor:pointer;transition:.15s}
.btn:hover:not(:disabled){filter:brightness(1.08)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
.actions{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap;align-items:center}
.affirm{display:flex;gap:11px;align-items:flex-start;background:var(--panel2);
  border:1px solid var(--line);border-left:3px solid var(--med);border-radius:0 9px 9px 0;
  padding:14px 16px;margin:16px 0;font-size:13.5px;line-height:1.55}
.affirm input{margin-top:3px;width:17px;height:17px;flex:none;accent-color:var(--accent)}
.bar{height:7px;background:var(--panel2);border-radius:99px;overflow:hidden;margin:14px 0 8px}
.bar i{display:block;height:100%;background:var(--accent);border-radius:99px;width:0;transition:width .4s ease}
.phase{font-family:var(--mono);font-size:13px;color:var(--muted)}
.runlist{margin-top:16px;max-height:250px;overflow:auto;border:1px solid var(--line);border-radius:9px}
.run{display:flex;align-items:center;gap:11px;padding:8px 13px;border-bottom:1px solid var(--line);font-size:13px}
.run:last-child{border-bottom:none}
.run .nm{font-family:var(--mono);flex:1}
.pill{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;font-weight:660;
  padding:2px 8px;border-radius:999px;background:var(--panel2);color:var(--muted)}
.pill.ok{color:var(--ok)} .pill.no{color:var(--crit)} .pill.skip{color:var(--med)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:10px;margin-bottom:16px}
.tile{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:13px 10px;text-align:center}
.tile .n{font-size:25px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.tile .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:4px}
.c-crit{color:var(--crit)} .c-high{color:var(--high)} .c-med{color:var(--med)}
.c-low{color:var(--low)} .c-info{color:var(--info)}
.find{border:1px solid var(--line);border-radius:10px;padding:13px 15px;margin-bottom:9px;background:var(--panel2)}
.find .h{display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
.find .ti{flex:1;min-width:200px;font-weight:620;font-size:14.5px}
.sev{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;font-weight:680;
  padding:2.5px 9px;border-radius:999px;white-space:nowrap}
.sev.critical{background:rgba(255,123,114,.16);color:var(--crit)}
.sev.high{background:rgba(255,166,87,.16);color:var(--high)}
.sev.medium{background:rgba(227,179,65,.16);color:var(--med)}
.sev.low{background:rgba(86,212,160,.16);color:var(--low)}
.sev.info{background:rgba(147,161,177,.16);color:var(--info)}
.find .m{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.tag{font-family:var(--mono);font-size:11.5px;color:var(--muted);background:var(--bg);
  padding:2px 8px;border-radius:6px;border:1px solid var(--line)}
.tag.agree{color:var(--ok);border-color:var(--ok)}
.notice{border-left:3px solid var(--med);background:var(--panel2);border-radius:0 9px 9px 0;
  padding:12px 15px;margin:12px 0;font-size:13.5px}
.err{border-left-color:var(--crit)}
.caps{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:7px;margin-top:6px}
.cap{display:flex;align-items:center;gap:9px;font-size:12.5px;padding:7px 11px;
  background:var(--panel2);border:1px solid var(--line);border-radius:8px}
.cap .st{width:7px;height:7px;border-radius:50%;flex:none;background:var(--muted)}
.cap .st.y{background:var(--ok)} .cap .st.n{background:var(--line)}
.cap .nm{font-family:var(--mono);flex:1}
details summary{cursor:pointer;color:var(--muted);font-size:13px;padding:4px 0}
.hidden{display:none}
.defs{display:grid;gap:9px;margin-top:6px}
.def{display:flex;gap:12px;align-items:center;flex-wrap:wrap;background:var(--panel2);
  border:1px solid var(--line);border-radius:10px;padding:12px 15px}
.def .dn{font-weight:640;font-size:14.5px;flex:1;min-width:160px}
.def .dm{font-size:12px;color:var(--muted);font-family:var(--mono)}
.def .acts{display:flex;gap:7px}
.mini{background:transparent;border:1px solid var(--line);border-radius:8px;
  padding:6px 12px;font-size:12.5px;cursor:pointer;color:var(--ink)}
.mini:hover{border-color:var(--accent)}
.mini.warn{border-color:var(--med);color:var(--med)}
.lapse{font-size:11.5px;color:var(--med)}
.ok-s{font-size:11.5px;color:var(--ok)}
.inline{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
@media (max-width:720px){.inline{grid-template-columns:1fr}}
.muted{color:var(--muted)}
.small{font-size:12.5px}
@media (max-width:720px){.row{grid-template-columns:1fr}.lic{text-align:left}}
/*EXPLORER-CSS*/
</style></head><body>
<div class="app">

<header>
  <div class="brand">
    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 2.6 44 14v22L24 47.4 4 36V14z" stroke="currentColor" stroke-width="2.6" stroke-linejoin="round" opacity=".92"/>
      <path d="M24 13.4 34.6 19.5v12.2L24 37.8l-10.6-6.1V19.5z" fill="currentColor" opacity=".18"/>
      <path d="M17.6 24.4l4.4 4.5 8.6-9.1" stroke="currentColor" stroke-width="2.9" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div><div class="bname">AuditLight</div><div class="btag" id="tagline">Loading…</div></div>
  </div>
  <div class="lic"><span class="tier" id="tier">—</span> <span id="licnote"></span></div>
</header>

<div class="rail">
  <div class="step on" id="s1"><span class="dot">1</span> Scope</div>
  <div class="step" id="s2"><span class="dot">2</span> Authorise</div>
  <div class="step" id="s3"><span class="dot">3</span> Assess</div>
  <div class="step" id="s4"><span class="dot">4</span> Report</div>
</div>

<!-- STEP 1 -->
<section class="card" id="p1">
  <h2>What are we assessing?</h2>
  <p class="sub">Pick a profile, then list the hosts, domains or URLs to examine. Every check is detection only — nothing here exploits anything.</p>
  <label>Assessment profile</label>
  <div class="profiles" id="profiles"></div>
  <div class="row">
    <div>
      <label for="targets">Targets — one per line</label>
      <textarea id="targets" rows="4" placeholder="example.com&#10;https://app.example.com&#10;192.0.2.10"></textarea>
    </div>
    <div>
      <label for="scope">Scope guard — optional</label>
      <textarea id="scope" rows="4" placeholder="example.com&#10;192.0.2.0/24"></textarea>
      <p class="small muted" style="margin:6px 0 0">Anything outside these domains or ranges is skipped, and the report says so.</p>
    </div>
  </div>
  <div id="scanpathwrap" class="hidden" style="margin-top:14px">
    <label for="scanpath">Filesystem path to search for exposed credentials</label>
    <input type="text" id="scanpath" placeholder="/srv/app">
  </div>
  <div class="actions"><button class="btn" id="to2">Continue</button><span class="small muted" id="e1"></span></div>
</section>

<!-- STEP 2 -->
<section class="card hidden" id="p2">
  <h2>Confirm you are authorised</h2>
  <p class="sub">AuditLight records this statement in a hash-chained log and prints it in the report. It is evidence that the assessment was sanctioned, which protects you as much as the target.</p>
  <label for="operator">Operator name</label>
  <input type="text" id="operator" placeholder="Your name">
  <div class="affirm">
    <input type="checkbox" id="confirmed">
    <label for="confirmed" style="text-transform:none;letter-spacing:0;font-size:13.5px;color:var(--ink);font-weight:400;margin:0" id="affirmtext">…</label>
  </div>
  <label for="confirm">Re-enter the targets, one per line</label>
  <textarea id="confirm" rows="3" placeholder="Type the targets again"></textarea>
  <p class="small muted" style="margin:6px 0 0">Typing them a second time is what turns a reflex click into a deliberate act.</p>
  <div class="actions">
    <button class="btn" id="run">Start assessment</button>
    <button class="btn ghost" id="back1">Back</button>
    <span class="small muted" id="e2"></span>
  </div>
</section>

<!-- STEP 3 -->
<section class="card hidden" id="p3">
  <h2 id="runtitle">Assessment running</h2>
  <p class="sub" id="runsub">Checks run in stages: discovery first, then the network, then each service, then the conclusions drawn from them.</p>
  <div class="bar"><i id="bar"></i></div>
  <div class="phase" id="phase">starting…</div>
  <div class="runlist hidden" id="runlist"></div>
</section>

<!-- STEP 4 -->
<section class="card hidden" id="p4">
  <h2>Results</h2>
  <p class="sub" id="ressub"></p>
  <div class="tiles" id="tiles"></div>
  <div id="capnotice"></div>
  <div class="actions" style="margin-top:0;margin-bottom:16px">
    <button class="btn" id="openAssess">Open assessment report</button>
    <button class="btn ghost" id="openProcess">Open process report</button>
    <button class="btn ghost hidden" id="openDelta">Open change report</button>
    <button class="btn ghost" id="again">New assessment</button>
  </div>
  <div class="hidden" id="savewrap" style="margin-bottom:16px">
    <div class="affirm" style="border-left-color:var(--accent)">
      <div>
        <b>Track this over time.</b> Save these targets as a recurring assessment and AuditLight
        will re-run them, then report what changed — what got fixed, what came back, what is new.
        <div class="inline">
          <div><label for="defname">Name</label>
            <input type="text" id="defname" placeholder="Acme quarterly perimeter"></div>
          <div><label for="definterval">Re-run every</label>
            <select id="definterval" style="width:100%;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:10px 12px">
              <option value="0">Only when I ask</option>
              <option value="7">7 days</option>
              <option value="30">30 days</option>
              <option value="90" selected>90 days</option>
            </select></div>
        </div>
        <div class="actions" style="margin-top:12px">
          <button class="btn" id="savedef">Save assessment</button>
          <span class="small muted" id="esave"></span>
        </div>
      </div>
    </div>
  </div>
  <div id="findings"></div>
</section>

<!--EXPLORER-->

<section class="card hidden" id="recur">
  <h2>Recurring assessments</h2>
  <p class="sub">Saved targets that re-run on a schedule. Each run is compared with the one before it,
  so the report answers the only question a client really asks: did the fixes hold?</p>
  <div class="defs" id="deflist"></div>
</section>

<details style="margin-top:18px">
  <summary>What this installation can check</summary>
  <div class="caps" id="caps"></div>
  <p class="small muted" style="margin-top:10px">Built-in checks always run. External tools add depth when installed; when they are missing the report says so, because a check that never ran must not read as a check that passed.</p>
</details>

</div>
<script>
"use strict";
const $ = s => document.querySelector(s);
const el = (t,c,x) => { const n=document.createElement(t); if(c)n.className=c; if(x!=null)n.textContent=x; return n; };
let state = { profile:null, profiles:[], job:null, timer:null, status:null };

async function api(path, opts){
  const r = await fetch(path, opts);
  let body = null;
  try { body = await r.json(); } catch(e) { body = null; }
  return { ok:r.ok, code:r.status, body };
}

function step(n){
  [1,2,3,4].forEach(i=>{
    const s=$("#s"+i), p=$("#p"+i);
    s.classList.toggle("on", i===n);
    s.classList.toggle("done", i<n);
    p.classList.toggle("hidden", i!==n);
  });
  // The explorer belongs to a finished run, so it goes away the moment the
  // operator steps back to set up a new one.
  if(n!==4) $("#pexp").classList.add("hidden");
  window.scrollTo({top:0,behavior:"smooth"});
}

async function boot(){
  const st = await api("/api/status");
  if(!st.ok) return;
  state.status = st.body;
  $("#tagline").textContent = st.body.tagline;
  $("#tier").textContent = (st.body.licence.tier||"free");
  $("#licnote").textContent = st.body.licence.notice||"";
  $("#affirmtext").textContent = st.body.affirmation;
  const caps = $("#caps");
  caps.innerHTML="";
  st.body.capabilities.forEach(c=>{
    const d=el("div","cap");
    d.appendChild(el("span","st "+(c.available?"y":"n")));
    d.appendChild(el("span","nm",c.name));
    d.appendChild(el("span","pill "+(c.available?"ok":""), c.available?(c.kind==="native"?"built in":"found"):"absent"));
    d.title = c.describe + (c.reason?" — "+c.reason:"");
    caps.appendChild(d);
  });

  const pr = await api("/api/profiles");
  if(!pr.ok) return;
  state.profiles = pr.body;
  const box = $("#profiles"); box.innerHTML="";
  pr.body.forEach(p=>{
    const b=el("button","prof");
    b.type="button"; b.disabled=!p.allowed;
    b.appendChild(el("div","t",p.title));
    b.appendChild(el("div","d",p.summary));
    if(!p.allowed) b.appendChild(el("div","lock","Requires a paid licence"));
    b.onclick=()=>{
      state.profile=p.name;
      [...box.children].forEach(c=>c.classList.remove("sel"));
      b.classList.add("sel");
      $("#scanpathwrap").classList.toggle("hidden", !(p.adapters||[]).includes("secrets"));
    };
    box.appendChild(b);
    if(p.allowed && !state.profile) b.click();
  });
}

$("#to2").onclick=()=>{
  const t=$("#targets").value.trim();
  if(!state.profile){ $("#e1").textContent="Choose a profile first."; return; }
  if(!t){ $("#e1").textContent="Add at least one target."; return; }
  $("#e1").textContent="";
  step(2);
};
$("#back1").onclick=()=>step(1);

const lines = v => v.split("\n").map(s=>s.trim()).filter(Boolean);

$("#run").onclick=async()=>{
  const e=$("#e2"); e.textContent="";
  if(!$("#operator").value.trim()){ e.textContent="Enter an operator name."; return; }
  if(!$("#confirmed").checked){ e.textContent="Accept the authorisation statement."; return; }
  const payload={
    profile:state.profile, operator:$("#operator").value.trim(),
    targets:lines($("#targets").value), confirm:lines($("#confirm").value),
    scope:lines($("#scope").value), confirmed:true,
    scan_path:$("#scanpath").value.trim()
  };
  $("#run").disabled=true;
  const r=await api("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  $("#run").disabled=false;
  if(!r.ok){ e.textContent=(r.body&&r.body.error)||("Request failed ("+r.code+")"); return; }
  state.job=r.body.id;
  step(3);
  $("#bar").style.width="4%";
  $("#runlist").innerHTML=""; $("#runlist").classList.add("hidden");
  poll();
};

function poll(){
  clearInterval(state.timer);
  state.timer=setInterval(async()=>{
    const r=await api("/api/jobs/"+state.job);
    if(!r.ok) return;
    const j=r.body;
    $("#bar").style.width=Math.max(4,j.progress)+"%";
    $("#phase").textContent=j.phase||j.state;
    if(j.adapters && j.adapters.length){
      const list=$("#runlist"); list.classList.remove("hidden"); list.innerHTML="";
      j.adapters.forEach(a=>{
        const d=el("div","run");
        d.appendChild(el("span","nm",a.name));
        if(a.findings) d.appendChild(el("span","small muted",a.findings+" found"));
        const cls=a.skipped?"skip":(a.ok?"ok":"no");
        d.appendChild(el("span","pill "+cls, a.skipped?"skipped":(a.ok?"ok":"failed")));
        list.appendChild(d);
      });
      list.scrollTop=list.scrollHeight;
    }
    if(j.state==="completed"||j.state==="failed"||j.state==="refused"){
      clearInterval(state.timer);
      finish(j);
    }
  },600);
}

async function finish(j){
  if(j.state!=="completed"){
    $("#runtitle").textContent = j.state==="refused" ? "Assessment refused" : "Assessment failed";
    $("#runsub").innerHTML="";
    const n=el("div","notice err", j.error||"The assessment did not complete.");
    $("#p3").appendChild(n);
    return;
  }
  const r=await api("/api/jobs/"+state.job+"/findings");
  const data=r.ok?r.body:{findings:[],total:0,shown:0,notice:""};
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  data.findings.forEach(f=>counts[f.severity]!==undefined&&counts[f.severity]++);
  const tiles=$("#tiles"); tiles.innerHTML="";
  [["critical","Critical","crit"],["high","High","high"],["medium","Medium","med"],
   ["low","Low","low"],["info","Info","info"]].forEach(([k,label,c])=>{
    const d=el("div","tile");
    const n=el("div","n c-"+c,String(counts[k])); d.appendChild(n);
    d.appendChild(el("div","l",label)); tiles.appendChild(d);
  });
  $("#ressub").textContent = data.total+" finding"+(data.total===1?"":"s")+
    " across "+(j.targets||[]).filter(t=>t.processed).length+" target(s). Detection only — nothing was exploited.";
  $("#capnotice").innerHTML="";
  if(data.notice) $("#capnotice").appendChild(el("div","notice",data.notice));

  const box=$("#findings"); box.innerHTML="";
  data.findings.slice(0,40).forEach(f=>{
    const d=el("div","find");
    const h=el("div","h");
    h.appendChild(el("div","ti",f.title));
    h.appendChild(el("span","sev "+f.severity,f.severity));
    d.appendChild(h);
    d.appendChild(el("div","small muted",(f.description||"").split("\n\n")[0]));
    const m=el("div","m");
    m.appendChild(el("span","tag",f.target+(f.port?":"+f.port:"")));
    m.appendChild(el("span","tag",f.category));
    m.appendChild(el("span","tag","confidence: "+f.confidence));
    if((f.source_tools||[]).length>1) m.appendChild(el("span","tag agree",f.source_tools.length+" checks agree"));
    (f.cve||[]).forEach(c=>m.appendChild(el("span","tag",c)));
    d.appendChild(m);
    box.appendChild(d);
  });
  if(data.findings.length>40) box.appendChild(el("p","small muted","Showing the 40 highest-ranked here. The full list is in the report."));

  const canTrack = state.status && state.status.reassessment;
  $("#openDelta").classList.toggle("hidden", !(canTrack && j.definition_id));
  $("#savewrap").classList.toggle("hidden", !(canTrack && !j.definition_id));
  if(canTrack && !j.definition_id && !$("#defname").value){
    $("#defname").value = (lines($("#targets").value)[0]||"assessment")+" — "+state.profile;
  }
  loadDefs();
  step(4);

  // The explorer is drawn from the same findings the list shows, so the two
  // views can never disagree about what this licence exposes.
  // Unhide before loading: a canvas inside a hidden card measures zero, and a
  // canvas sized from zero draws its nodes as ellipses.
  $("#pexp").classList.remove("hidden");
  const shown = await SX.load(state.job, data.findings);
  $("#pexp").classList.toggle("hidden", !shown);
}

$("#openAssess").onclick=()=>window.open("/api/jobs/"+state.job+"/report/assessment","_blank");
$("#openDelta").onclick=()=>window.open("/api/jobs/"+state.job+"/report/delta","_blank");

$("#savedef").onclick=async()=>{
  const e=$("#esave"); e.textContent="";
  const name=$("#defname").value.trim();
  if(!name){ e.textContent="Give it a name."; return; }
  const payload={
    name, profile:state.profile, operator:$("#operator").value.trim(),
    targets:lines($("#targets").value), scope:lines($("#scope").value),
    scan_path:$("#scanpath").value.trim(),
    interval_days:parseInt($("#definterval").value,10)||0,
    confirmed:true
  };
  $("#savedef").disabled=true;
  const r=await api("/api/definitions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  $("#savedef").disabled=false;
  if(!r.ok){ e.textContent=(r.body&&r.body.error)||("Request failed ("+r.code+")"); return; }
  e.textContent="Saved.";
  $("#savewrap").classList.add("hidden");
  loadDefs();
};

async function loadDefs(){
  if(!state.status || !state.status.reassessment) return;
  const r=await api("/api/definitions");
  if(!r.ok) return;
  const box=$("#deflist"); box.innerHTML="";
  if(!r.body || !r.body.length){ $("#recur").classList.add("hidden"); return; }
  $("#recur").classList.remove("hidden");
  r.body.forEach(d=>{
    const row=el("div","def");
    const left=el("div"); left.style.flex="1"; left.style.minWidth="200px";
    left.appendChild(el("div","dn",d.name));
    const meta=(d.targets||[]).join(", ")+" · "+d.profile+
      (d.interval_days? " · every "+d.interval_days+"d" : " · manual");
    left.appendChild(el("div","dm",meta));
    if(d.authorisation_valid){
      left.appendChild(el("div","ok-s","Authorised for "+d.authorisation_days_left+" more day(s)"));
    } else {
      left.appendChild(el("div","lapse","Authorisation lapsed — re-affirm to resume"));
    }
    if(d.last_skip_reason) left.appendChild(el("div","lapse",d.last_skip_reason));
    row.appendChild(left);

    const acts=el("div","acts");
    if(d.authorisation_valid){
      const run=el("button","mini","Run now");
      run.onclick=async()=>{
        run.disabled=true;
        const rr=await api("/api/definitions/"+d.id+"/run",{method:"POST"});
        run.disabled=false;
        if(!rr.ok){ alert((rr.body&&rr.body.error)||"Could not start"); return; }
        state.job=rr.body.id; step(3); $("#bar").style.width="4%";
        $("#runlist").innerHTML=""; $("#runlist").classList.add("hidden");
        poll();
      };
      acts.appendChild(run);
    } else {
      const re=el("button","mini warn","Re-affirm");
      re.onclick=async()=>{
        const who=prompt("Type your name to re-affirm authorisation for: "+(d.targets||[]).join(", "));
        if(!who) return;
        const rr=await api("/api/definitions/"+d.id+"/reauthorise",{method:"POST",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify({operator:who,confirmed:true})});
        if(!rr.ok){ alert((rr.body&&rr.body.error)||"Could not re-authorise"); return; }
        loadDefs();
      };
      acts.appendChild(re);
    }
    if(d.last_run_id){
      const rep=el("button","mini","Change report");
      rep.onclick=()=>window.open("/api/jobs/"+d.last_run_id+"/report/delta","_blank");
      acts.appendChild(rep);
    }
    const del=el("button","mini","Remove");
    del.onclick=async()=>{
      if(!confirm("Remove \""+d.name+"\"? Past runs and their reports are kept.")) return;
      await api("/api/definitions/"+d.id,{method:"DELETE"});
      loadDefs();
    };
    acts.appendChild(del);
    row.appendChild(acts);
    box.appendChild(row);
  });
}
$("#openProcess").onclick=()=>window.open("/api/jobs/"+state.job+"/report/process","_blank");
/*EXPLORER-JS*/
$("#again").onclick=()=>{ state.job=null; $("#confirmed").checked=false; $("#confirm").value=""; step(1); };

boot().then(loadDefs);
</script></body></html>`

// indexHTML is the dashboard with the explorer's markup, style and behaviour
// folded in. Keeping the explorer in its own file keeps a 400-line renderer out
// of the middle of the page, and the document served is still one string with
// no fetch of any kind.
var indexHTML = strings.NewReplacer(
	"/*EXPLORER-CSS*/", explorerCSS,
	"<!--EXPLORER-->", explorerSection,
	"/*EXPLORER-JS*/", explorerScript,
).Replace(indexTemplateHTML)
