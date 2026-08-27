package webui

// The Surface Explorer.
//
// This is the one place in the product where three dimensions earn their
// keep. The reports print a flat tree, because paper cannot be rotated and a
// picture that needs rotating to be read is a picture that fails on paper. On
// screen the opposite is true: a surface with a few dozen services is a
// hairball in two dimensions, and parallax from a dragged rotation separates
// it in a way no static layout can.
//
// It is drawn with a hand-written perspective projection and a painter's
// algorithm on a plain 2D canvas. Two reasons, both deliberate:
//
//   - a 3D library would be the only third-party code in a product whose
//     entire pitch is that it has none, and would add several hundred kilobytes
//     to a binary that currently fetches nothing and links nothing;
//   - WebGL in a headless browser depends on a software rasteriser and fails in
//     exactly the environments used to capture screenshots and demos. Canvas 2D
//     renders identically everywhere.
//
// Deterministic layout matters here for the same reason it matters in the
// report: two people looking at the same assessment must see the same shape.
// Nothing in this file is random.

const explorerSection = `
<section class="card hidden" id="pexp">
  <h2>Surface explorer</h2>
  <p class="sub">The same surface the report prints, with the third dimension put back.
  Drag to rotate, scroll to zoom, click a node to see what was recorded there.</p>
  <div class="expwrap">
    <canvas id="sxc" aria-label="Interactive attack surface"></canvas>
    <aside class="expside" id="sxside"></aside>
  </div>
  <div class="explegend" id="sxlegend"></div>
  <p class="small muted" id="sxnote">Nothing here is inferred topology. A host hangs beneath the
  declared target its name belongs to, and a service beneath the host a check actually reached.
  AuditLight does not probe how hosts connect to one another, so it does not draw it.</p>
</section>
`

const explorerScript = `
/* ---- Surface explorer ------------------------------------------------- */
const SX = (function(){
  const SEV=["critical","high","medium","low","info"];
  let cv=null, ctx=null, W=0, H=0, dpr=1;
  let nodes=[], links=[], byId={};
  let yaw=0.7, pitch=-0.34, zoom=1, spin=true, resumeAt=0;
  let drag=false, dx=0, dy=0, sel=null, hover=null, raf=0;
  let pal={}, findings={}, notice="";

  function v(n){ return getComputedStyle(document.documentElement).getPropertyValue(n).trim()||"#888"; }
  function palette(){
    pal={critical:v("--crit"),high:v("--high"),medium:v("--med"),low:v("--low"),info:v("--info"),
         none:v("--line"),ink:v("--ink"),muted:v("--muted"),line:v("--line"),
         bg:v("--bg"),panel:v("--panel"),accent:v("--accent")};
  }
  function colour(s){ return pal[s]||pal.none; }

  function leaves(n){
    if(!n.children||!n.children.length) return 1;
    let t=0; n.children.forEach(c=>t+=leaves(c)); return t;
  }
  function sph(az,el,r){
    return {x:r*Math.cos(el)*Math.cos(az), y:r*Math.sin(el), z:r*Math.cos(el)*Math.sin(az)};
  }

  /* Layout: roots share the full circle in proportion to how much hangs off
     them, children fan out inside their parent's wedge, and depth becomes
     radius. Elevation fans siblings apart so the shells are not flat discs —
     a flat disc drawn in perspective is just a 2D chart wearing a hat. */
  function layout(g){
    nodes=[]; links=[]; byId={};
    const roots=g.roots||[];
    let total=0; roots.forEach(r=>total+=leaves(r));
    if(!total) total=1;
    const R=[0,120,225,300];

    const centre={id:"__c",label:"assessment",kind:"centre",depth:0,p:{x:0,y:0,z:0},
                  sev:"",total:{total:0},node:null};
    nodes.push(centre); byId[centre.id]=centre;

    let acc=0;
    roots.forEach(r=>{
      const w=leaves(r)/total;
      const a0=acc*Math.PI*2, a1=(acc+w)*Math.PI*2; acc+=w;
      place(r,1,a0,a1,0,centre);
    });

    function place(n,depth,a0,a1,el,parent){
      const am=(a0+a1)/2;
      const nd={id:n.id,label:n.label,kind:n.kind,depth:depth,
                p:sph(am,el,R[Math.min(depth,3)]),
                sev:n.severity||"", total:n.total||{total:0}, own:n.own||{total:0},
                ids:n.finding_ids||[], skipped:!!n.skipped, reason:n.reason||"",
                hidden:n.hidden||0, node:n};
      nodes.push(nd); byId[nd.id]=nd;
      links.push([parent,nd]);
      const kids=n.children||[];
      if(!kids.length) return;
      // Keep a margin inside the wedge so neighbouring branches stay distinct.
      const pad=(a1-a0)*0.08, b0=a0+pad, b1=a1-pad;
      const spread=depth===1?0.95:0.62;
      let ka=0;
      kids.forEach((c,i)=>{
        const cw=leaves(c)/leaves(n);
        const c0=b0+ka*(b1-b0), c1=b0+(ka+cw)*(b1-b0); ka+=cw;
        const cel=el+(((i+0.5)/kids.length)-0.5)*spread;
        place(c,depth+1,c0,c1,cel,nd);
      });
    }
  }

  function project(p){
    const cy=Math.cos(yaw), sy=Math.sin(yaw), cp=Math.cos(pitch), sp=Math.sin(pitch);
    const x1=p.x*cy-p.z*sy, z1=p.x*sy+p.z*cy;
    const y2=p.y*cp-z1*sp,  z2=p.y*sp+z1*cp;
    const d=760, s=d/(d+z2)*zoom;
    return {x:W/2+x1*s, y:H/2+y2*s, s:s, z:z2};
  }

  function radius(n,s){
    const base=n.kind==="centre"?7:n.depth===1?6.5:n.depth===2?5:3.8;
    return Math.max(1.6,base*s);
  }

  function draw(){
    raf=0;
    if(!ctx) return;
    ctx.setTransform(dpr,0,0,dpr,0,0);
    ctx.clearRect(0,0,W,H);

    nodes.forEach(n=>{ n.pr=project(n.p); });

    // Edges first, faded with distance so depth reads without any shading.
    ctx.lineWidth=1;
    links.forEach(([a,b])=>{
      const t=(a.pr.s+b.pr.s)/2;
      ctx.globalAlpha=Math.max(0.10,Math.min(0.55,t*0.5));
      ctx.strokeStyle=pal.line;
      ctx.beginPath(); ctx.moveTo(a.pr.x,a.pr.y); ctx.lineTo(b.pr.x,b.pr.y); ctx.stroke();
    });
    ctx.globalAlpha=1;

    // Painter's algorithm: far to near, so near nodes occlude far ones.
    const order=nodes.slice().sort((a,b)=>b.pr.z-a.pr.z);
    order.forEach(n=>{
      const r=radius(n,n.pr.s);
      const active=(sel&&sel.id===n.id)||(hover&&hover.id===n.id);
      ctx.globalAlpha=Math.max(0.35,Math.min(1,n.pr.s));
      ctx.beginPath(); ctx.arc(n.pr.x,n.pr.y,r,0,6.2832);
      ctx.fillStyle=n.kind==="centre"?pal.accent:(n.skipped?pal.none:colour(n.sev));
      ctx.fill();
      if(n.skipped){ ctx.strokeStyle=pal.muted; ctx.lineWidth=1.2; ctx.stroke(); }
      if(active){
        ctx.globalAlpha=1; ctx.strokeStyle=pal.accent; ctx.lineWidth=2;
        ctx.beginPath(); ctx.arc(n.pr.x,n.pr.y,r+4,0,6.2832); ctx.stroke();
      }
      const label=n.kind==="centre"?"":n.label;
      if(label && (active || (n.depth<=1 && n.pr.s>0.55) || (n.depth===2&&n.pr.s>0.95))){
        ctx.globalAlpha=1;
        ctx.font=(active?"600 ":"")+Math.round(11.5)+"px "+
          "ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif";
        ctx.fillStyle=active?pal.ink:pal.muted;
        ctx.fillText(label,n.pr.x+r+5,n.pr.y+4);
      }
    });
    ctx.globalAlpha=1;
  }

  function tick(){
    if(spin && !drag && Date.now()>resumeAt) yaw+=0.0032;
    schedule();
    requestAnimationFrame(tick);
  }
  function schedule(){ if(!raf) raf=requestAnimationFrame(draw); }

  function pick(mx,my){
    let best=null, bd=16;
    nodes.forEach(n=>{
      if(!n.pr||n.kind==="centre") return;
      const d=Math.hypot(n.pr.x-mx,n.pr.y-my);
      if(d<bd+radius(n,n.pr.s)){ bd=d; best=n; }
    });
    return best;
  }

  function side(n){
    const box=document.getElementById("sxside");
    if(!box) return;
    box.innerHTML="";
    if(!n){
      const d=el("div","small muted",
        "Click any node to see what was recorded there. Drag to rotate.");
      box.appendChild(d);
      if(notice) box.appendChild(el("div","notice",notice));
      return;
    }
    box.appendChild(el("div","sxtitle",n.label));
    const kind=n.kind==="more"?"folded group":n.kind;
    box.appendChild(el("div","small muted",kind+(n.hidden?" · "+n.hidden+" hidden":"")));
    if(n.skipped){
      box.appendChild(el("div","notice","Not assessed — "+(n.reason||"no reason recorded")));
      return;
    }
    const t=n.total||{};
    const row=el("div","sxcounts");
    SEV.forEach(s=>{
      const val=t[s]||0;
      if(!val) return;
      row.appendChild(el("span","sxpill "+s,val+" "+s));
    });
    if(!row.childNodes.length) row.appendChild(el("span","small muted","No findings recorded here."));
    box.appendChild(row);
    const list=el("div","sxlist");
    (n.ids||[]).forEach(id=>{
      const f=findings[id];
      const li=el("div","sxitem");
      li.appendChild(el("span","sev "+((f&&f.severity)||"info"),(f&&f.severity)||"—"));
      li.appendChild(el("span","",f?f.title:"finding "+id+" (not shown under this licence)"));
      list.appendChild(li);
    });
    if((n.ids||[]).length) box.appendChild(list);
    else if(n.total&&n.total.total)
      box.appendChild(el("div","small muted","Findings sit on the services beneath this node."));
  }

  function legend(){
    const box=document.getElementById("sxlegend");
    if(!box) return;
    box.innerHTML="";
    SEV.forEach(s=>{
      const w=el("span","sxkey");
      const d=el("span","sxdot"); d.style.background=colour(s);
      w.appendChild(d); w.appendChild(el("span","",s)); box.appendChild(w);
    });
    const w=el("span","sxkey");
    const d=el("span","sxdot"); d.style.background=pal.none; d.style.outline="1px solid "+pal.muted;
    w.appendChild(d); w.appendChild(el("span","","skipped target")); box.appendChild(w);
  }

  /* The backing store has to match the element's real laid-out width, not a
     guess at it. Guessing stretches the bitmap, and a stretched bitmap turns
     every node from a circle into an ellipse — which reads as meaning, because
     in a chart a different shape usually is one. Measure, never assume. */
  function resize(){
    if(!cv) return;
    const r=cv.getBoundingClientRect();
    if(r.width<2) return;                 // laid out but not visible yet
    dpr=Math.min(2,window.devicePixelRatio||1);
    W=Math.round(r.width);
    H=Math.max(320,Math.min(540,Math.round(W*0.62)));
    cv.style.height=H+"px";
    cv.width=Math.round(W*dpr); cv.height=Math.round(H*dpr);
    schedule();
  }

  function bind(){
    cv.addEventListener("mousedown",e=>{drag=true;dx=e.clientX;dy=e.clientY;});
    window.addEventListener("mouseup",()=>{ if(drag){drag=false;resumeAt=Date.now()+4000;} });
    window.addEventListener("mousemove",e=>{
      if(drag){
        yaw+=(e.clientX-dx)*0.008; pitch+=(e.clientY-dy)*0.006;
        pitch=Math.max(-1.2,Math.min(1.2,pitch));
        dx=e.clientX; dy=e.clientY; schedule(); return;
      }
      const r=cv.getBoundingClientRect();
      if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom){
        if(hover){hover=null;schedule();} return;
      }
      const h=pick(e.clientX-r.left,e.clientY-r.top);
      if(h!==hover){ hover=h; cv.style.cursor=h?"pointer":"grab"; schedule(); }
    });
    cv.addEventListener("wheel",e=>{
      e.preventDefault();
      zoom=Math.max(0.45,Math.min(2.6,zoom*(e.deltaY>0?0.92:1.08)));
      resumeAt=Date.now()+4000; schedule();
    },{passive:false});
    cv.addEventListener("click",e=>{
      const r=cv.getBoundingClientRect();
      sel=pick(e.clientX-r.left,e.clientY-r.top);
      resumeAt=Date.now()+6000; side(sel); schedule();
    });
    window.addEventListener("resize",resize);
    if(window.ResizeObserver) new ResizeObserver(resize).observe(cv);
    const mq=window.matchMedia("(prefers-color-scheme:dark)");
    if(mq.addEventListener) mq.addEventListener("change",()=>{palette();legend();schedule();});
  }

  async function load(jobId, findingList){
    cv=document.getElementById("sxc");
    if(!cv) return false;
    findings={};
    (findingList||[]).forEach(f=>{findings[f.id]=f;});
    const r=await api("/api/jobs/"+jobId+"/surface.json");
    if(!r.ok||!r.body||!r.body.graph) return false;
    const g=r.body.graph;
    notice=r.body.notice||"";
    if(!g.roots||!g.roots.length) return false;
    if(!ctx){ ctx=cv.getContext("2d"); bind(); requestAnimationFrame(tick); }
    palette(); layout(g); sel=null; hover=null; zoom=1;
    legend(); side(null);
    // Measure once now and once after the browser has laid the section out;
    // the first call is a no-op while the card is still hidden.
    resize(); requestAnimationFrame(resize);
    return true;
  }

  return {load:load};
})();
`

// explorerCSS is appended to the dashboard stylesheet.
const explorerCSS = `
.expwrap{display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap}
#sxc{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  cursor:grab;touch-action:none;flex:1 1 420px}
#sxc:active{cursor:grabbing}
.expside{width:284px;flex:none;background:var(--panel);border:1px solid var(--line);
  border-radius:var(--r);padding:14px;max-height:520px;overflow:auto}
.sxtitle{font-weight:660;letter-spacing:-.01em;word-break:break-all}
.sxcounts{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.sxpill{font-size:11.5px;padding:2px 9px;border-radius:999px;border:1px solid var(--line);
  text-transform:uppercase;letter-spacing:.05em;font-weight:640}
.sxpill.critical{color:var(--crit)}.sxpill.high{color:var(--high)}
.sxpill.medium{color:var(--med)}.sxpill.low{color:var(--low)}.sxpill.info{color:var(--info)}
.sxlist{display:flex;flex-direction:column;gap:8px;margin-top:6px}
.sxitem{display:flex;gap:8px;align-items:flex-start;font-size:13px;line-height:1.45}
.explegend{display:flex;gap:14px;flex-wrap:wrap;margin-top:12px;font-size:12px;color:var(--muted)}
.sxkey{display:inline-flex;align-items:center;gap:6px}
.sxdot{width:9px;height:9px;border-radius:50%;display:inline-block}
@media (max-width:860px){ .expside{width:100%;max-height:320px} }
`
