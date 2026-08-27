package report

// baseCSS is inlined into every report. Reports must open from a USB stick on
// a machine with no network, so nothing here may reference an external asset.
const baseCSS = `
:root{
  --bg:#f7f8fa; --panel:#ffffff; --ink:#12161d; --muted:#5a6472; --line:#e3e7ee;
  --accent:#2f6df6; --accent-soft:#eaf1ff;
  --crit:#b3261e; --crit-bg:#fdeceb;
  --high:#c2410c; --high-bg:#fef0e7;
  --med:#a16207; --med-bg:#fdf6e3;
  --low:#1d6b57; --low-bg:#e9f6f1;
  --info:#475569; --info-bg:#eef1f5;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d1117; --panel:#151b23; --ink:#e6edf3; --muted:#9aa7b4; --line:#232c37;
    --accent:#6ea8ff; --accent-soft:#16233b;
    --crit:#ff7b72; --crit-bg:#2d1618;
    --high:#ffa657; --high-bg:#2b1d12;
    --med:#e3b341; --med-bg:#272016;
    --low:#56d4a0; --low-bg:#122420;
    --info:#9aa7b4; --info-bg:#1b222b;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.62;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
header.doc{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;
  padding-bottom:22px;border-bottom:2px solid var(--line);margin-bottom:32px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:13px}
.hex{width:34px;height:34px;flex:none}
.brandname{font-size:19px;font-weight:680;letter-spacing:-.015em}
.brandsub{font-size:12.5px;color:var(--muted);margin-top:1px}
.docmeta{text-align:right;font-size:12.5px;color:var(--muted);line-height:1.75}
.docmeta b{color:var(--ink);font-weight:620}
h1{font-size:27px;line-height:1.25;margin:0 0 6px;letter-spacing:-.022em;font-weight:700}
h2{font-size:18px;margin:38px 0 14px;letter-spacing:-.012em;font-weight:660;
  padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:0 0 6px;font-weight:640}
p{margin:0 0 12px}
.lede{color:var(--muted);font-size:14.5px;margin-bottom:26px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:20px 22px;margin-bottom:16px}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:repeat(auto-fit,minmax(250px,1fr))}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(104px,1fr));gap:10px;margin:4px 0 8px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 12px;text-align:center}
.tile .n{font-size:26px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.tile .l{font-size:11px;text-transform:uppercase;letter-spacing:.075em;color:var(--muted);margin-top:5px}
.tile.crit .n{color:var(--crit)} .tile.high .n{color:var(--high)}
.tile.med .n{color:var(--med)} .tile.low .n{color:var(--low)} .tile.info .n{color:var(--info)}
.badge{display:inline-block;padding:2.5px 9px;border-radius:999px;font-size:11px;
  font-weight:660;text-transform:uppercase;letter-spacing:.055em;white-space:nowrap}
.b-crit{background:var(--crit-bg);color:var(--crit)}
.b-high{background:var(--high-bg);color:var(--high)}
.b-med{background:var(--med-bg);color:var(--med)}
.b-low{background:var(--low-bg);color:var(--low)}
.b-info{background:var(--info-bg);color:var(--info)}
.chip{display:inline-block;padding:2px 8px;border-radius:6px;background:var(--info-bg);
  color:var(--muted);font-size:11.5px;font-family:var(--mono)}
.chip.ok{background:var(--low-bg);color:var(--low)}
.chip.no{background:var(--crit-bg);color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:2px 0 6px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:640}
tbody tr:last-child td{border-bottom:none}
.tblwrap{overflow-x:auto}
.f{background:var(--panel);border:1px solid var(--line);border-radius:11px;
  padding:18px 20px;margin-bottom:13px;break-inside:avoid}
.f-head{display:flex;align-items:flex-start;gap:11px;margin-bottom:9px;flex-wrap:wrap}
.f-num{font-family:var(--mono);font-size:12px;color:var(--muted);padding-top:3px;min-width:28px}
.f-title{flex:1;min-width:220px;font-size:15.5px;font-weight:640;letter-spacing:-.01em}
.f-meta{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:11px;align-items:center}
.f-body p{margin:0 0 10px;font-size:14px}
.f-body p:last-child{margin-bottom:0}
.ev{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px 13px;margin-top:11px}
.ev-h{font-size:10.5px;text-transform:uppercase;letter-spacing:.075em;color:var(--muted);margin-bottom:7px;font-weight:640}
.ev-row{font-family:var(--mono);font-size:12px;line-height:1.6;margin-bottom:4px;word-break:break-word;white-space:pre-wrap}
.ev-row:last-child{margin-bottom:0}
.ev-k{color:var(--muted)}
.fix{border-left:3px solid var(--accent);background:var(--accent-soft);
  border-radius:0 8px 8px 0;padding:11px 14px;margin-top:11px;font-size:13.5px}
.fix b{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.075em;
  color:var(--accent);margin-bottom:4px}
.note{border-left:3px solid var(--med);background:var(--med-bg);color:var(--ink);
  border-radius:0 8px 8px 0;padding:13px 16px;margin:14px 0;font-size:13.5px}
.note b{color:var(--med)}
.muted{color:var(--muted)}
.small{font-size:12.5px}
footer.doc{margin-top:44px;padding-top:20px;border-top:1px solid var(--line);
  color:var(--muted);font-size:12px;line-height:1.75}
.wm{position:fixed;inset:0;pointer-events:none;z-index:9;display:flex;
  align-items:center;justify-content:center;overflow:hidden}
.wm span{font-size:82px;font-weight:800;color:var(--ink);opacity:.055;
  transform:rotate(-28deg);white-space:nowrap;letter-spacing:.06em}
ul.clean{margin:0;padding-left:19px}
ul.clean li{margin-bottom:5px}
.kv{display:grid;grid-template-columns:170px 1fr;gap:5px 16px;font-size:13.5px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.hash{font-family:var(--mono);font-size:11.5px;color:var(--muted);word-break:break-all}
@media print{
  body{background:#fff}
  .wrap{max-width:none;padding:0}
  .panel,.f,.tile{break-inside:avoid}
  h2{break-after:avoid}
  .wm{display:none}
  a{text-decoration:none;color:inherit}
}
@media (max-width:640px){
  .wrap{padding:26px 15px 60px}
  h1{font-size:22px}
  .kv{grid-template-columns:1fr}
  .docmeta{text-align:left}
}

/* Attack surface map. Colours come from the same variables as the rest of the
   report, so the picture follows the reader's theme and prints in either. */
.smapwrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:14px 16px 10px;overflow-x:auto}
.smap{display:block;width:100%;min-width:760px;height:auto}
.smap .lnk{fill:none;stroke:var(--line);stroke-width:1.4}
.smap .rule{stroke:var(--line);stroke-width:1}
.smap .lbl{font-family:var(--sans);font-size:12.5px;fill:var(--ink)}
.smap .sub,.smap .cnt{font-family:var(--mono);font-size:11px;fill:var(--muted)}
.smap .hdr{font-family:var(--sans);font-size:10px;fill:var(--muted);
  letter-spacing:.1em;text-transform:uppercase}
.smap .skip .lbl{fill:var(--muted)}
.smap .d-crit{fill:var(--crit)}
.smap .d-high{fill:var(--high)}
.smap .d-med{fill:var(--med)}
.smap .d-low{fill:var(--low)}
.smap .d-info{fill:var(--info)}
.smap .d-none{fill:var(--line)}
.smap .s-crit{fill:var(--crit)}
.smap .s-high{fill:var(--high)}
.smap .s-med{fill:var(--med)}
.smap .s-low{fill:var(--low)}
.smap .s-info{fill:var(--info)}

/* Assessment timeline heatmap. */
.tlwrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:14px 16px 10px;overflow-x:auto}
.tl{display:block;max-width:100%;height:auto}
.tl .lbl{font-family:var(--sans);font-size:12px;fill:var(--ink)}
.tl .hdr{font-family:var(--mono);font-size:10px;fill:var(--muted)}
.tl .cell{stroke:var(--panel);stroke-width:2}
.tl .c-crit{fill:var(--crit)}
.tl .c-high{fill:var(--high)}
.tl .c-med{fill:var(--med)}
.tl .c-low{fill:var(--low)}
.tl .c-info{fill:var(--info)}
.tl .c-clear{fill:var(--low-bg)}
.tl .c-absent{fill:var(--line)}
.tl .na{stroke:var(--muted);stroke-width:1.6;stroke-linecap:round;opacity:.85}
.tl .key{font-family:var(--sans);font-size:10.5px;fill:var(--muted)}
`

// hexMark is the Hexward family mark, inlined as SVG so the report stays
// self-contained.
const hexMark = `<svg class="hex" viewBox="0 0 48 48" fill="none" aria-hidden="true">
<path d="M24 2.6 44 14v22L24 47.4 4 36V14z" stroke="currentColor" stroke-width="2.6"
 stroke-linejoin="round" opacity=".92"/>
<path d="M24 13.4 34.6 19.5v12.2L24 37.8l-10.6-6.1V19.5z" fill="currentColor" opacity=".18"/>
<path d="M17.6 24.4l4.4 4.5 8.6-9.1" stroke="currentColor" stroke-width="2.9"
 stroke-linecap="round" stroke-linejoin="round"/>
</svg>`
