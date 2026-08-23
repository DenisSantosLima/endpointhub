import React, { useState, useMemo, useCallback, useRef } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

/* ============================================================
   Endpoint Analytics (Intune) — EndpointHub
   Upload do export de dispositivos do Intune → visões:
   Devices · Applications · Compliance · Configuration ·
   Operating Systems · Windows Update
   Processamento local; nenhum dado sai do navegador.
   ============================================================ */

const C = {
  bg: "var(--bg)", panel: "var(--panel)", panel2: "var(--panel2)", line: "var(--line)",
  ink: "var(--ink)", dim: "var(--dim)", faint: "var(--faint)",
  crit: "var(--crit)", warn: "var(--warn)", info: "var(--accent)", ok: "var(--ok)",
  cyan: "var(--cyan)", violet: "var(--violet)", pink: "var(--pink)",
};
// Cores dos gráficos (donuts): hex fixos — SVG fill não resolve var() de forma
// confiável, e estas cores vivas funcionam sobre card em ambos os temas.
const DONUT = ["#3b82f6", "#e3a008", "#f2545b", "#2ea043", "#a371f7", "#39c5cf", "#ec4899", "#8b98a5"];

/* ---------- CSV parsing ---------- */
function parseCSV(text, delim) {
  const rows = []; let field = "", row = [], inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; } else field += c; }
    else { if (c === '"') inQ = true; else if (c === delim) { row.push(field); field = ""; } else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; } else if (c === "\r") {} else field += c; }
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function toObjects(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const nl = clean.indexOf("\n");
  const first = nl === -1 ? clean : clean.slice(0, nl);
  const delim = (first.split(";").length > first.split(",").length) ? ";" : ",";
  const rows = parseCSV(clean, delim).filter((r) => r.some((c) => c.trim() !== ""));
  if (!rows.length) return { headers: [], data: [] };
  const headers = rows[0].map((h) => h.trim());
  const data = rows.slice(1).map((r) => { const o = {}; headers.forEach((h, i) => (o[h] = (r[i] ?? "").trim())); return o; });
  return { headers, data };
}
function isIntune(headers) {
  const s = new Set(headers.map((h) => h.trim()));
  return ['Serial number', 'Compliance', 'Encrypted', 'OS'].every((k) => s.has(k));
}

const num = (s) => { const n = parseFloat(String(s).replace(",", ".")); return isNaN(n) ? 0 : n; };
const gb = (mb) => mb / 1024;
function osNorm(o) { o = (o || "").toLowerCase(); if (o.includes("ios") || o.includes("ipad")) return "iOS/iPadOS"; if (o.includes("android")) return "Android"; if (o.includes("mac")) return "macOS"; if (o.includes("windows")) return "Windows"; return "Outro"; }

/* ---------- Análise ---------- */
function analyze(devices) {
  const N = devices.length;
  const now = new Date();
  const daysSince = (x) => { const t = new Date(x["Last check-in"]); return isNaN(t) ? 99999 : (now - t) / 864e5; };

  const enc = devices.filter((x) => x["Encrypted"] === "True").length;
  const nonComp = devices.filter((x) => x["Compliance"] === "Noncompliant").length;
  let lowPct = 0, low10 = 0;
  devices.forEach((x) => { const tot = num(x["Total storage"]), free = num(x["Free storage"]); if (tot > 0) { if (free / tot < 0.20) lowPct++; if (gb(free) < 10) low10++; } });
  const over45 = devices.filter((x) => daysSince(x) > 45).length;
  const over30 = devices.filter((x) => daysSince(x) > 30).length;

  const count = (fn) => devices.reduce((m, x) => { const k = fn(x) || "—"; m[k] = (m[k] || 0) + 1; return m; }, {});
  const toPairs = (obj, limit) => { let e = Object.entries(obj).sort((a, b) => b[1] - a[1]); if (limit && e.length > limit) { const head = e.slice(0, limit - 1); const rest = e.slice(limit - 1).reduce((s, [, v]) => s + v, 0); head.push(["Outros", rest]); e = head; } return e.map(([name, value]) => ({ name, value })); };

  const byOS = count((x) => osNorm(x["OS"]));
  const byMfr = count((x) => x["Manufacturer"] || "—");
  const byCheckin = { "0-30 dias": 0, "31-45 dias": 0, "Mais de 45 dias": 0 };
  devices.forEach((x) => { const d = daysSince(x); if (d <= 30) byCheckin["0-30 dias"]++; else if (d <= 45) byCheckin["31-45 dias"]++; else byCheckin["Mais de 45 dias"]++; });
  const byOwnership = count((x) => x["Ownership"] || "—");
  const bySupervised = count((x) => x["Supervised"] === "True" ? "Supervisionado" : "Não supervisionado");
  const byJoin = count((x) => x["JoinType"] || "—");
  const byOSVer = count((x) => x["OS version"] || "—");
  const byComp = count((x) => x["Compliance"] || "—");
  const encByOS = {};
  devices.forEach((x) => { const o = osNorm(x["OS"]); if (!encByOS[o]) encByOS[o] = { enc: 0, total: 0 }; encByOS[o].total++; if (x["Encrypted"] === "True") encByOS[o].enc++; });

  const rowBase = (x) => {
    const lastRaw = x["Last check-in"] || "";
    const lastDate = new Date(lastRaw);
    const dias = isNaN(lastDate) ? null : Math.floor((now - lastDate) / 864e5);
    return {
      name: x["Device name"], serial: x["Serial number"] || "—",
      upn: x["Primary user UPN"], os: osNorm(x["OS"]), osver: x["OS version"],
      owner: x["Ownership"] || "—", comp: x["Compliance"] || "—",
      enc: x["Encrypted"] || "—", last: lastRaw ? lastRaw.slice(0, 10) : "—", dias,
    };
  };
  const allDevices = devices.map(rowBase).sort((a, b) => (a.name || "").localeCompare(b.name || ""));
  const noCheckin45 = devices.filter((x) => daysSince(x) > 45).map(rowBase).sort((a, b) => (b.dias || 0) - (a.dias || 0));

  const notEncrypted = devices.filter((x) => x["Encrypted"] !== "True").map((x) => {
    const lastRaw = x["Last check-in"] || "";
    const lastDate = new Date(lastRaw);
    const dias = isNaN(lastDate) ? null : Math.floor((now - lastDate) / 864e5);
    return {
      name: x["Device name"],
      serial: x["Serial number"] || "—",
      upn: x["Primary user UPN"],
      os: x["OS"],
      osver: x["OS version"],
      enc: x["Encrypted"],
      comp: x["Compliance"],
      last: lastRaw ? lastRaw.slice(0, 10) : "—",
      dias,
    };
  });
  const nonCompliant = devices.filter((x) => x["Compliance"] === "Noncompliant").map((x) => ({
    name: x["Device name"], upn: x["Primary user UPN"], os: osNorm(x["OS"]), osver: x["OS version"], own: x["Ownership"], last: x["Last check-in"],
  }));
  const lowDisk = devices.filter((x) => { const t = num(x["Total storage"]); return t > 0 && num(x["Free storage"]) / t < 0.20; })
    .map((x) => ({ name: x["Device name"], upn: x["Primary user UPN"], totalGB: Math.round(gb(num(x["Total storage"]))), freeGB: Math.round(gb(num(x["Free storage"]))), pct: Math.round(num(x["Free storage"]) / num(x["Total storage"]) * 100) }))
    .sort((a, b) => a.pct - b.pct);

  return {
    N, enc, nonComp, lowPct, low10, over45, over30,
    byOS: toPairs(byOS), byMfr: toPairs(byMfr, 6), byCheckin: toPairs(byCheckin),
    byOwnership: toPairs(byOwnership), bySupervised: toPairs(bySupervised), byJoin: toPairs(byJoin),
    byOSVer: toPairs(byOSVer, 8), byComp: toPairs(byComp), encByOS,
    notEncrypted, nonCompliant, lowDisk, allDevices, noCheckin45,
  };
}

/* ---------- UI helpers ---------- */
function KPI({ label, sub, value, pct, accent, bar, onClick }) {
  return (
    <div onClick={onClick} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16, flex: 1, minWidth: 200, cursor: onClick ? "pointer" : "default", transition: "border-color .15s" }}
      onMouseEnter={(e) => { if (onClick) e.currentTarget.style.borderColor = "#3a4655"; }}
      onMouseLeave={(e) => { if (onClick) e.currentTarget.style.borderColor = C.line; }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 600 }}>{label}</div>
          {sub && <div style={{ fontSize: 11.5, color: C.faint, marginTop: 2, maxWidth: 200 }}>{sub}</div>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ fontSize: 34, fontWeight: 700, color: accent || C.ink, fontVariantNumeric: "tabular-nums", lineHeight: 1 }}>{value}</div>
          {onClick && <span style={{ fontSize: 11, color: C.faint, marginTop: 8 }}>↗</span>}
        </div>
      </div>
      {bar != null && (
        <div style={{ marginTop: 14 }}>
          <div style={{ height: 4, borderRadius: 2, background: C.line, overflow: "hidden" }}>
            <div style={{ width: `${bar}%`, height: "100%", background: accent || C.info }} />
          </div>
        </div>
      )}
      {pct && <div style={{ marginTop: 8, fontSize: 11.5, color: C.dim, background: C.panel2, borderRadius: 6, padding: "6px 8px" }}>{pct}</div>}
    </div>
  );
}

function Donut({ title, sub, data, center, focus }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const pct = (v) => total > 0 ? ((v / total) * 100).toFixed(1).replace(".", ",") : "0";
  // Centro: fatia em foco (se informada), senão a maior fatia.
  const focused = focus ? data.find((d) => d.name === focus) : null;
  const biggest = data.reduce((m, d) => (d.value > (m?.value ?? -1) ? d : m), null);
  const centerSlice = focused ?? biggest;
  const centerLabel = center?.label ?? centerSlice?.name ?? "";
  const centerPct = pct(centerSlice?.value ?? 0);
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 600 }}>{title}</div>
      {sub && <div style={{ fontSize: 11.5, color: C.faint, marginTop: 2, marginBottom: 4 }}>{sub}</div>}
      <div style={{ position: "relative", height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={62} outerRadius={90} paddingAngle={2} stroke="none">
              {data.map((_, i) => <Cell key={i} fill={DONUT[i % DONUT.length]} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}>
          <div style={{ fontSize: 24, fontWeight: 700, lineHeight: 1, color: C.ink }}>{centerPct}%</div>
          <div style={{ fontSize: 11.5, color: C.dim, marginTop: 4 }}>{centerLabel}</div>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 5, marginTop: 8 }}>
        {data.map((d, i) => (
          <span key={i} style={{ fontSize: 11.5, color: C.dim, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: DONUT[i % DONUT.length], flexShrink: 0 }} />
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.name}</span>
            <span style={{ marginLeft: "auto", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{d.value} · <b style={{ color: C.ink }}>{pct(d.value)}%</b></span>
          </span>
        ))}
      </div>
    </div>
  );
}

function DataTable({ title, sub, cols, rows, filter, setFilter }) {
  const f = rows.filter((r) => !filter || Object.values(r).some((v) => String(v).toLowerCase().includes(filter.toLowerCase())));
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16, marginTop: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 600 }}>{title}</div>
          {sub && <div style={{ fontSize: 11.5, color: C.faint, marginTop: 2 }}>{sub}</div>}
        </div>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filtrar…"
          style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 8, padding: "7px 11px", color: C.ink, fontSize: 12.5, minWidth: 200, outline: "none" }} />
      </div>
      <div style={{ overflow: "auto", maxHeight: 420, border: `1px solid ${C.line}`, borderRadius: 8 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
          <thead><tr>{cols.map((c) => (
            <th key={c.k} style={{ textAlign: "left", padding: "9px 12px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap", position: "sticky", top: 0 }}>{c.h}</th>
          ))}</tr></thead>
          <tbody>
            {f.map((r, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${C.line}` }}>
                {cols.map((c) => {
                  const raw = r[c.k]; const val = c.r ? c.r(raw) : raw;
                  let color = C.ink;
                  if (c.k === "enc") color = raw === "True" ? C.ok : C.crit;
                  if (c.k === "comp") color = raw === "Compliant" ? C.ok : C.warn;
                  if (c.k === "pct") color = raw < 10 ? C.crit : raw < 20 ? C.warn : C.ink;
                  if (c.k === "dias") color = raw == null ? C.faint : raw > 45 ? C.crit : raw > 30 ? C.warn : C.ok;
                  return <td key={c.k} style={{ padding: "8px 12px", color, whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{val ?? "—"}{c.k === "pct" ? "%" : ""}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
        {f.length === 0 && <div style={{ padding: 20, textAlign: "center", color: C.faint, fontSize: 13 }}>Nenhum registro.</div>}
      </div>
    </div>
  );
}


/* ---- KPI Modal ---- */
function exportCSV(rows, cols, title) {
  const header = cols.map((c) => c.h).join(',');
  const body = rows.map((r) => cols.map((c) => {
    const v = c.r ? c.r(r[c.k]) : (r[c.k] ?? '');
    return `"${String(v).replace(/"/g, '""')}"`;
  }).join(',')).join('\n');
  const blob = new Blob([header + '\n' + body], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url;
  a.download = `${title.replace(/\s+/g, '_')}.csv`; a.click();
  URL.revokeObjectURL(url);
}

function KpiModal({ modal, onClose }) {
  const [filter, setFilter] = React.useState('');
  React.useEffect(() => { setFilter(''); }, [modal]);
  React.useEffect(() => {
    if (!modal) return;
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [modal, onClose]);
  if (!modal) return null;
  const { title, sub, rows, cols } = modal;
  const filtered = rows.filter((r) => !filter || Object.values(r).some((v) => String(v).toLowerCase().includes(filter.toLowerCase())));
  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 200, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '60px 24px 24px', overflowY: 'auto' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 14, width: '100%', maxWidth: 1200, boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: `1px solid ${C.line}` }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>{title}</div>
            {sub && <div style={{ fontSize: 12.5, color: C.dim, marginTop: 2 }}>{sub}</div>}
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filtrar…"
              style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 8, padding: '7px 12px', color: C.ink, fontSize: 12.5, width: 200, outline: 'none' }} />
            <button onClick={() => exportCSV(filtered, cols, title)}
              style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 8, padding: '7px 14px', color: C.ink, fontSize: 12.5, cursor: 'pointer', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              ↓ Exportar CSV
            </button>
            <button onClick={onClose} aria-label="Fechar"
              style={{ background: 'none', border: `1px solid ${C.line}`, borderRadius: 8, padding: '7px 12px', color: C.dim, fontSize: 16, cursor: 'pointer', lineHeight: 1 }}>✕</button>
          </div>
        </div>
        <div style={{ overflowX: 'auto', maxHeight: '65vh', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
            <thead style={{ position: 'sticky', top: 0, zIndex: 1 }}>
              <tr>{cols.map((c) => (
                <th key={c.k} style={{ textAlign: 'left', padding: '9px 14px', color: C.dim, fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: 'nowrap' }}>{c.h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.line}` }}>
                  {cols.map((c) => {
                    const raw = r[c.k]; const val = c.r ? c.r(raw) : raw;
                    let color = C.ink;
                    if (c.k === 'enc') color = raw === 'True' ? C.ok : C.crit;
                    if (c.k === 'comp') color = raw === 'Compliant' ? C.ok : C.warn;
                    if (c.k === 'pct') color = raw < 10 ? C.crit : raw < 20 ? C.warn : C.ok;
                    if (c.k === 'dias') color = raw == null ? C.faint : raw > 45 ? C.crit : raw > 30 ? C.warn : C.ok;
                    return <td key={c.k} style={{ padding: '8px 14px', color, whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>{val ?? '—'}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && <div style={{ padding: 24, textAlign: 'center', color: C.faint, fontSize: 13 }}>Nenhum registro.</div>}
        </div>
        <div style={{ padding: '10px 20px', borderTop: `1px solid ${C.line}`, fontSize: 12, color: C.faint, display: 'flex', justifyContent: 'space-between' }}>
          <span>{filtered.length} de {rows.length} {filter ? 'registros filtrados' : 'registros'}</span>
          <span>Clique fora ou ESC para fechar</span>
        </div>
      </div>
    </div>
  );
}


function Placeholder({ title, exportName, path }) {
  return (
    <div style={{ background: C.panel, border: `1px dashed ${C.line}`, borderRadius: 12, padding: "40px 24px", textAlign: "center", marginTop: 8 }}>
      <div style={{ fontSize: 16, fontWeight: 600 }}>{title}</div>
      <div style={{ fontSize: 13.5, color: C.dim, marginTop: 10, maxWidth: 560, marginLeft: "auto", marginRight: "auto", lineHeight: 1.6 }}>
        Esta visão precisa de um export adicional do Intune que não vem no relatório de dispositivos.
        Exporte <b style={{ color: C.ink }}>{exportName}</b> e envie na área de upload acima — a aba será preenchida automaticamente.
      </div>
      <div style={{ fontSize: 12, color: C.faint, marginTop: 12, fontFamily: "ui-monospace, monospace" }}>{path}</div>
    </div>
  );
}

const TABS = ["Devices", "Applications", "Compliance", "Configuration", "Operating Systems", "Windows Update"];

export default function EndpointAnalytics() {
  const [devices, setDevices] = useState([]);
  const [loaded, setLoaded] = useState(null);
  const [tab, setTab] = useState("Devices");
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState("");
  const [tFilter, setTFilter] = useState("");
  const [modal, setModal] = useState(null);
  const openModal = useCallback((cfg) => setModal(cfg), []);
  const closeModal = useCallback(() => setModal(null), []);
  const inputRef = useRef(null);

  const ingest = useCallback((fileList) => {
    const file = Array.from(fileList).find((f) => /\.csv$/i.test(f.name));
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const { headers, data } = toObjects(reader.result);
        if (!isIntune(headers)) { setErr(`"${file.name}" não parece um export de dispositivos do Intune (colunas esperadas ausentes).`); return; }
        setErr(""); setDevices(data); setLoaded({ name: file.name, count: data.length });
      } catch (e) { setErr("Falha ao ler o arquivo: " + e.message); }
    };
    reader.readAsText(file, "UTF-8");
  }, []);
  const onDrop = useCallback((e) => { e.preventDefault(); setDrag(false); ingest(e.dataTransfer.files); }, [ingest]);

  const A = useMemo(() => (devices.length ? analyze(devices) : null), [devices]);
  const pctOf = (n) => A ? `${((n / A.N) * 100).toFixed(1)}%` : "";

  return (
    <div style={{ color: C.ink, fontFamily: "'Inter', system-ui, sans-serif", padding: "8px 0 40px" }}>
      <div>

        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: C.info, fontWeight: 700 }}>Endpoint Analytics</div>
            <h1 style={{ fontSize: 26, fontWeight: 700, margin: "4px 0 0", letterSpacing: -0.5 }}>Visão do Intune</h1>
          </div>
          <div style={{ fontSize: 12, color: C.faint, textAlign: "right" }}>Export de dispositivos do Intune · processamento local</div>
        </div>

        {/* Upload */}
        <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()}
          style={{ marginTop: 20, border: `1.5px dashed ${drag ? C.info : C.line}`, background: drag ? "rgba(59,130,246,0.06)" : C.panel, borderRadius: 12, padding: "20px", cursor: "pointer" }}>
          <input ref={inputRef} type="file" accept=".csv" style={{ display: "none" }} onChange={(e) => ingest(e.target.files)} />
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>{drag ? "Solte o arquivo aqui" : "Arraste o export de dispositivos do Intune — ou clique"}</div>
              <div style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>Devices → Export no Intune. Processamento 100% local — nenhum dado é enviado.</div>
            </div>
            {loaded && <span style={{ fontSize: 12, color: C.dim, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 6, padding: "5px 10px" }}>{loaded.name} · <b style={{ color: C.ink }}>{loaded.count}</b> devices</span>}
          </div>
          {err && <div style={{ marginTop: 10, fontSize: 12.5, color: C.crit }}>⚠ {err}</div>}
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginTop: 20, marginBottom: 18, borderBottom: `1px solid ${C.line}`, flexWrap: "wrap" }}>
          {TABS.map((tb) => (
            <button key={tb} onClick={() => { setTab(tb); setTFilter(""); }}
              style={{ background: "none", border: "none", borderBottom: `2px solid ${tab === tb ? C.info : "transparent"}`, color: tab === tb ? C.ink : C.dim, padding: "8px 14px", fontSize: 13.5, fontWeight: 600, cursor: "pointer", marginBottom: -1 }}>{tb}</button>
          ))}
        </div>

        {!A && (
          <div style={{ marginTop: 40, textAlign: "center", color: C.faint, fontSize: 14 }}>Carregue o export de dispositivos do Intune para ver as análises.</div>
        )}

        {A && tab === "Devices" && (
          <>
            {(() => {
              const colsDevice = [
                { k: "name", h: "Device" }, { k: "serial", h: "Serial" },
                { k: "upn", h: "UPN" }, { k: "os", h: "OS" }, { k: "osver", h: "Versão" },
                { k: "owner", h: "Ownership" }, { k: "comp", h: "Compliance" },
                { k: "enc", h: "Criptografado" }, { k: "last", h: "Últ. check-in" },
                { k: "dias", h: "Dias s/ check-in", r: (v) => v == null ? "—" : `${v}d` },
              ];
              const colsDisk = [
                { k: "name", h: "Device" }, { k: "upn", h: "UPN" },
                { k: "totalGB", h: "Total (GB)" }, { k: "freeGB", h: "Livre (GB)" },
                { k: "pct", h: "% livre" },
              ];
              const colsNotEnc = [
                { k: "name", h: "Device" }, { k: "serial", h: "Serial" }, { k: "upn", h: "UPN" },
                { k: "os", h: "OS" }, { k: "osver", h: "Versão" }, { k: "last", h: "Últ. check-in" },
                { k: "dias", h: "Dias s/ check-in", r: (v) => v == null ? "—" : `${v}d` },
                { k: "enc", h: "Criptografado" }, { k: "comp", h: "Compliance" },
              ];
              return (
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
                  <KPI label="Dispositivos gerenciados" sub="Total no Intune" value={A.N} accent={C.ink} bar={100}
                    pct="Todos gerenciados por Intune"
                    onClick={() => openModal({ title: "Dispositivos gerenciados", sub: `${A.N} devices no Intune`, rows: A.allDevices, cols: colsDevice })} />
                  <KPI label="Pouco espaço em disco" sub="Menos de 20% livre" value={A.lowPct} accent={C.warn} bar={(A.lowPct / A.N) * 100}
                    pct={`${A.lowPct} de ${A.N} · ${pctOf(A.lowPct)}`}
                    onClick={() => openModal({ title: "Pouco espaço em disco", sub: `${A.lowPct} devices com menos de 20% livre`, rows: A.lowDisk, cols: colsDisk })} />
                  <KPI label="Criptografia" sub="Não criptografados" value={A.N - A.enc} accent={C.crit}
                    pct={`${A.N - A.enc} de ${A.N} sem encryption`}
                    onClick={() => openModal({ title: "Não criptografados", sub: `${A.notEncrypted.length} devices sem encryption — priorize a remediação`, rows: A.notEncrypted, cols: colsNotEnc })} />
                  <KPI label="Sem check-in" sub="Mais de 45 dias" value={A.over45} accent={C.crit}
                    pct={`${A.over45} de ${A.N} no total`}
                    onClick={() => openModal({ title: "Sem check-in há 45+ dias", sub: `${A.over45} devices inativos — validar se ainda em uso`, rows: A.noCheckin45, cols: colsDevice })} />
                </div>
              );
            })()}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
              <Donut title="Tipos de dispositivo" sub="Por sistema operacional" data={A.byOS} />
              <Donut title="Fabricante" sub="Manufacturer" data={A.byMfr} />
              <Donut title="Último check-in" sub="Janelas de tempo" data={A.byCheckin} />
              <Donut title="Espaço em disco" sub="Menos de 10 GB livres" data={[{ name: "< 10 GB", value: A.low10 }, { name: "OK", value: A.N - A.low10 }]} focus="< 10 GB" />
            </div>
            <DataTable title="Dispositivos com pouco disco" sub="Menos de 20% de espaço livre, ordenados pelos mais críticos"
              cols={[{ k: "name", h: "Device" }, { k: "upn", h: "UPN" }, { k: "totalGB", h: "Total (GB)" }, { k: "freeGB", h: "Livre (GB)" }, { k: "pct", h: "% livre" }]}
              rows={A.lowDisk} filter={tFilter} setFilter={setTFilter} />
          </>
        )}

        {A && tab === "Compliance" && (
          <>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
              <KPI label="Compliant" sub="Em conformidade" value={A.N - A.nonComp} accent={C.ok} bar={((A.N - A.nonComp) / A.N) * 100} pct={pctOf(A.N - A.nonComp)} />
              <KPI label="Non-compliant" sub="Fora de conformidade" value={A.nonComp} accent={C.warn} bar={(A.nonComp / A.N) * 100} pct={`${A.nonComp} de ${A.N} · ${pctOf(A.nonComp)}`} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
              <Donut title="Conformidade" sub="Compliant vs Noncompliant" data={A.byComp} />
              <Donut title="Por plataforma" sub="Distribuição por OS" data={A.byOS} />
              <Donut title="Propriedade" sub="Corporate vs Personal" data={A.byOwnership} />
            </div>
            <DataTable title="Dispositivos não conformes" sub="Lista dos Noncompliant para ação"
              cols={[{ k: "name", h: "Device" }, { k: "upn", h: "UPN" }, { k: "os", h: "OS" }, { k: "osver", h: "Versão" }, { k: "own", h: "Ownership" }, { k: "last", h: "Últ. check-in", r: (v) => (v || "").slice(0, 10) }]}
              rows={A.nonCompliant} filter={tFilter} setFilter={setTFilter} />
          </>
        )}

        {A && tab === "Configuration" && (
          <>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
              <KPI label="Criptografados" sub="Encryption habilitada" value={A.enc} accent={C.pink} bar={(A.enc / A.N) * 100} pct={pctOf(A.enc)} />
              <KPI label="Não criptografados" sub="Sem encryption" value={A.N - A.enc} accent={C.crit} pct={`${A.N - A.enc} de ${A.N}`} />
              <KPI label="Supervisionados" sub="Supervised = true" value={A.bySupervised.find((x) => x.name === "Supervisionado")?.value || 0} accent={C.info} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
              <Donut title="Criptografia" sub="Encrypted" data={[{ name: "Criptografado", value: A.enc }, { name: "Não", value: A.N - A.enc }]} />
              <Donut title="Propriedade" sub="Ownership" data={A.byOwnership} />
              <Donut title="Supervisão" sub="Supervised" data={A.bySupervised} />
              <Donut title="Tipo de join" sub="JoinType" data={A.byJoin} />
            </div>
            <DataTable title="Dispositivos não criptografados" sub="Status de criptografia — priorize a remediação"
              cols={[
                { k: "name", h: "Device" },
                { k: "serial", h: "Serial" },
                { k: "upn", h: "UPN" },
                { k: "os", h: "OS" },
                { k: "osver", h: "Versão" },
                { k: "last", h: "Últ. check-in" },
                { k: "dias", h: "Dias s/ check-in", r: (v) => v == null ? "—" : v > 45 ? `${v}d ⚠` : `${v}d` },
                { k: "enc", h: "Criptografado" },
                { k: "comp", h: "Compliance" },
              ]}
              rows={A.notEncrypted} filter={tFilter} setFilter={setTFilter} />
          </>
        )}

        {A && tab === "Operating Systems" && (
          <>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
              {A.byOS.slice(0, 4).map((o, i) => (
                <KPI key={o.name} label={o.name} sub="Dispositivos" value={o.value} accent={DONUT[i % DONUT.length]} bar={(o.value / A.N) * 100} pct={pctOf(o.value)} />
              ))}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 12 }}>
              <Donut title="Sistemas operacionais" sub="Distribuição por OS" data={A.byOS} />
              <Donut title="Versões de OS" sub="Top versões (agrupadas)" data={A.byOSVer} />
            </div>
            <DataTable title="Versões de sistema operacional" sub="Contagem por versão exata"
              cols={[{ k: "name", h: "Versão de OS" }, { k: "value", h: "Dispositivos" }]}
              rows={A.byOSVer} filter={tFilter} setFilter={setTFilter} />
          </>
        )}

        {A && tab === "Applications" && (
          <Placeholder title="Applications" exportName="relatório de Apps Descobertos (Discovered apps)" path="Intune → Apps → Monitor → Discovered apps → Export" />
        )}

        {A && tab === "Windows Update" && (
          <Placeholder title="Windows Update" exportName="relatório do Windows Update for Business (Feature/Quality update)" path="Intune → Reports → Windows updates → Export" />
        )}
      </div>
      <KpiModal modal={modal} onClose={closeModal} />
    </div>
  );
}
