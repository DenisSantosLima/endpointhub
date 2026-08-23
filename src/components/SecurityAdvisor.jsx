import React, { useState, useMemo, useCallback, useRef } from "react";
import { getKB, KB_NAMES } from "../data/advisor-kb.js";

/* ============================================================
   Security Advisor — EndpointHub
   Processa exports do Defender:
   1. Security Recommendations (CSV do portal)
   2. Vulnerabilities / CVEs (CSV do TVM)
   Processamento 100% local; nenhum dado sai do navegador.
   ============================================================ */

const C = {
  bg: "var(--bg)", panel: "var(--panel)", panel2: "var(--panel2)", line: "var(--line)",
  ink: "var(--ink)", dim: "var(--dim)", faint: "var(--faint)",
  crit: "var(--crit)", warn: "var(--warn)", info: "var(--accent)", ok: "var(--ok)",
  cyan: "var(--cyan)", violet: "var(--violet)", pink: "var(--pink)",
};

const SEV_COLOR = { Critical: "var(--crit)", High: "var(--warn)", Medium: "var(--info)", Low: "var(--ok)", Unknown: "var(--faint)" };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

/* ---------- CSV parsing ---------- */
function parseCSV(text, delim) {
  const rows = []; let field = "", row = [], inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; } else field += c; }
    else { if (c === '"') inQ = true; else if (c === delim) { row.push(field); field = ""; } else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; } else if (c !== "\r") field += c; }
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function toObjects(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const rows = parseCSV(clean, ",").filter((r) => r.some((c) => c.trim() !== ""));
  if (!rows.length) return { headers: [], data: [] };
  const headers = rows[0].map((h) => h.trim());
  const data = rows.slice(1).map((r) => { const o = {}; headers.forEach((h, i) => (o[h] = (r[i] ?? "").trim())); return o; });
  return { headers, data };
}

function isRecommendations(headers) {
  const s = new Set(headers.map((h) => h.trim()));
  return ["Name", "Devices Score impact", "Category", "Exposed devices"].every((k) => s.has(k));
}
function isVulnerabilities(headers) {
  const s = new Set(headers.map((h) => h.trim()));
  return ["Name", "Severity", "CVSS v3", "Has Exploit", "Exposed Machines"].every((k) => s.has(k));
}

/* ---------- Parsers ---------- */
function parseNum(s) {
  if (!s) return 0;
  s = s.toString().replace(/,/g, "");
  const m = s.match(/([\d.]+)\s*k/i);
  if (m) return parseFloat(m[1]) * 1000;
  const n = parseFloat(s);
  return isNaN(n) ? 0 : n;
}
function parseImpact(s) {
  if (!s) return 0;
  return parseFloat(s.replace("%", "").replace("+", "")) || 0;
}
function parseExposed(s) {
  if (!s) return { exposed: 0, total: 0 };
  const parts = s.split(" out of ");
  return { exposed: parseNum(parts[0]), total: parseNum(parts[1] || parts[0]) };
}
function catGroup(cat) {
  if (!cat || cat === "-") return "Outros";
  if (cat.startsWith("Security controls")) return "Security Controls";
  if (cat.startsWith("Operating system")) return "Sistema Operacional";
  if (cat.startsWith("Application")) return "Aplicativos";
  if (cat === "Network" || cat.startsWith("Network")) return "Rede";
  if (cat === "Accounts") return "Contas";
  return cat;
}

/* ---------- Análise ---------- */
function analyzeRec(data) {
  const recs = data.map((r) => ({
    name: r["Name"] || "—",
    impact: parseImpact(r["Devices Score impact"]),
    impactRaw: r["Devices Score impact"] || "—",
    points: r["Points achieved"] || "—",
    os: (r["OS platform"] || "").toLowerCase(),
    critical: parseInt(r["Exposed critical device"] || "0", 10),
    cat: r["Category"] || "—",
    catGroup: catGroup(r["Category"]),
    threats: r["Threats"] || "",
    tags: r["Tags"] || "",
    ...parseExposed(r["Exposed devices"]),
    remediation: parseInt(r["Remediation activities"] || "0", 10),
  })).sort((a, b) => b.impact - a.impact);

  const byGroup = recs.reduce((m, r) => { m[r.catGroup] = (m[r.catGroup] || 0) + 1; return m; }, {});
  const byOS = recs.reduce((m, r) => { const k = r.os || "other"; m[k] = (m[k] || 0) + 1; return m; }, {});
  const totalImpact = recs.reduce((s, r) => s + r.impact, 0);
  const withCritical = recs.filter((r) => r.critical > 0).length;
  const withRemediation = recs.filter((r) => r.remediation > 0).length;
  const withThreats = recs.filter((r) => r.threats).length;

  return { recs, byGroup, byOS, totalImpact, withCritical, withRemediation, withThreats, N: recs.length };
}

function analyzeVuln(data) {
  // pula linhas de cabeçalho extra (título do export)
  const vulns = data.filter((r) => r["Name"] && r["Severity"]).map((r) => ({
    name: r["Name"] || "—",
    sev: r["Severity"] || "Unknown",
    cvss: parseFloat(r["CVSS v3"] || "0") || 0,
    epss: parseFloat(r["Epss score"] || "0") || 0,
    age: parseInt(r["Age (days)"] || "0", 10) || 0,
    published: r["Published"] || "—",
    firstDetected: r["First detected"] || "—",
    hasExploit: r["Has Exploit"] === "True",
    hasThreats: r["Has Known Threats"] === "True",
    hasAlerts: r["Has Associated Alerts"] === "True",
    software: r["Related Software"] || "—",
    exposed: parseInt(r["Exposed Machines"] || "0", 10) || 0,
    description: r["Description"] || "",
    status: r["Status"] || "—",
  })).sort((a, b) => (SEV_ORDER[a.sev] ?? 9) - (SEV_ORDER[b.sev] ?? 9) || b.cvss - a.cvss);

  const bySev = vulns.reduce((m, v) => { m[v.sev] = (m[v.sev] || 0) + 1; return m; }, {});
  const withExploit = vulns.filter((v) => v.hasExploit);
  const remReq = vulns.filter((v) => v.status === "RemediationRequired");
  const top5 = vulns.filter((v) => v.status === "RemediationRequired").slice(0, 5);

  return { vulns, bySev, withExploit, remReq, top5, N: vulns.length };
}

/* ---------- UI helpers ---------- */
function KPI({ label, sub, value, accent, pct, bar, onClick }) {
  return (
    <div onClick={onClick} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16, flex: 1, minWidth: 180, cursor: onClick ? "pointer" : "default", transition: "border-color .15s" }}
      onMouseEnter={(e) => { if (onClick) e.currentTarget.style.borderColor = "#3a4655"; }}
      onMouseLeave={(e) => { if (onClick) e.currentTarget.style.borderColor = C.line; }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: 13.5, fontWeight: 600 }}>{label}</div>
          {sub && <div style={{ fontSize: 11.5, color: C.faint, marginTop: 2 }}>{sub}</div>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <div style={{ fontSize: 30, fontWeight: 700, color: accent || C.ink, fontVariantNumeric: "tabular-nums", lineHeight: 1 }}>{value}</div>
          {onClick && <span style={{ fontSize: 11, color: C.faint, marginTop: 8 }}>↗</span>}
        </div>
      </div>
      {bar != null && <div style={{ marginTop: 12, height: 4, borderRadius: 2, background: C.line, overflow: "hidden" }}><div style={{ width: `${Math.min(bar, 100)}%`, height: "100%", background: accent || C.info }} /></div>}
      {pct && <div style={{ marginTop: 8, fontSize: 11.5, color: C.dim, background: C.panel2, borderRadius: 6, padding: "5px 8px" }}>{pct}</div>}
    </div>
  );
}

function SevBadge({ sev }) {
  return <span style={{ fontSize: 11, fontWeight: 700, color: SEV_COLOR[sev] || C.faint, border: `1px solid ${SEV_COLOR[sev] || C.faint}`, borderRadius: 4, padding: "1px 7px", whiteSpace: "nowrap" }}>{sev}</span>;
}

function exportCSV(rows, cols, title) {
  const header = cols.map((c) => c.h).join(",");
  const body = rows.map((r) => cols.map((c) => `"${String(c.r ? c.r(r[c.k]) : (r[c.k] ?? "")).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([header + "\n" + body], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url;
  a.download = `${title.replace(/\s+/g, "_")}.csv`; a.click();
  URL.revokeObjectURL(url);
}

function Modal({ modal, onClose }) {
  const [filter, setFilter] = useState("");
  React.useEffect(() => { setFilter(""); }, [modal]);
  React.useEffect(() => {
    if (!modal) return;
    const h = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [modal, onClose]);
  if (!modal) return null;
  const { title, sub, rows, cols } = modal;
  const f = rows.filter((r) => !filter || Object.values(r).some((v) => String(v).toLowerCase().includes(filter.toLowerCase())));
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)", zIndex: 300, display: "flex", alignItems: "flex-start", justifyContent: "center", padding: "60px 24px 24px", overflowY: "auto" }}>
      <div onClick={(e) => e.stopPropagation()} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 14, width: "100%", maxWidth: 1300, boxShadow: "0 24px 60px rgba(0,0,0,0.5)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 20px", borderBottom: `1px solid ${C.line}` }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>{title}</div>
            {sub && <div style={{ fontSize: 12.5, color: C.dim, marginTop: 2 }}>{sub}</div>}
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filtrar…"
              style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 8, padding: "7px 12px", color: C.ink, fontSize: 12.5, width: 200, outline: "none" }} />
            <button onClick={() => exportCSV(f, cols, title)} style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 8, padding: "7px 14px", color: C.ink, fontSize: 12.5, cursor: "pointer", fontWeight: 600 }}>↓ Exportar CSV</button>
            <button onClick={onClose} style={{ background: "none", border: `1px solid ${C.line}`, borderRadius: 8, padding: "7px 12px", color: C.dim, fontSize: 16, cursor: "pointer", lineHeight: 1 }}>✕</button>
          </div>
        </div>
        <div style={{ overflowX: "auto", maxHeight: "65vh", overflowY: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
              <tr>{cols.map((c) => <th key={c.k} style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>{c.h}</th>)}</tr>
            </thead>
            <tbody>
              {f.map((r, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.line}` }}>
                  {cols.map((c) => {
                    const raw = r[c.k];
                    const val = c.r ? c.r(raw, r) : raw;
                    return <td key={c.k} style={{ padding: "8px 14px", whiteSpace: c.wrap ? "normal" : "nowrap", maxWidth: c.wrap ? 400 : undefined, color: C.ink, fontVariantNumeric: "tabular-nums" }}>{val ?? "—"}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          {f.length === 0 && <div style={{ padding: 24, textAlign: "center", color: C.faint }}>Nenhum registro.</div>}
        </div>
        <div style={{ padding: "10px 20px", borderTop: `1px solid ${C.line}`, fontSize: 12, color: C.faint, display: "flex", justifyContent: "space-between" }}>
          <span>{f.length} de {rows.length} registros{filter ? " filtrados" : ""}</span>
          <span>ESC ou clique fora para fechar</span>
        </div>
      </div>
    </div>
  );
}

const TABS = ["Resumo", "Recomendações", "Vulnerabilidades", "Com Exploit"];

/* ---- Syntax highlight simples para code blocks ---- */
function CodeBlock({ code, lang }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };
  return (
    <div style={{ position: "relative", marginTop: 10 }}>
      <div style={{ background: "#0d1117", border: `1px solid ${C.line}`, borderRadius: 8, padding: "14px 16px", fontFamily: "ui-monospace, 'Cascadia Code', monospace", fontSize: 12.5, lineHeight: 1.6, color: "#e6edf3", overflowX: "auto", whiteSpace: "pre" }}>
        {code}
      </div>
      <button onClick={copy} style={{ position: "absolute", top: 8, right: 8, background: copied ? C.ok : C.panel2, border: `1px solid ${C.line}`, borderRadius: 6, padding: "3px 10px", fontSize: 11, color: copied ? "#fff" : C.dim, cursor: "pointer", fontWeight: 600 }}>
        {copied ? "✓ Copiado" : "Copiar"}
      </button>
      {lang && <span style={{ position: "absolute", bottom: 8, right: 8, fontSize: 10, color: C.faint, textTransform: "uppercase", letterSpacing: 1 }}>{lang}</span>}
    </div>
  );
}

function MarkdownText({ text }) {
  // Renderiza **bold**, `code inline` e quebras de linha
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <span>
      {parts.map((p, i) => {
        if (p.startsWith("**") && p.endsWith("**")) return <strong key={i}>{p.slice(2, -2)}</strong>;
        if (p.startsWith("`") && p.endsWith("`")) return <code key={i} style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 4, padding: "1px 5px", fontSize: "0.9em", fontFamily: "ui-monospace, monospace" }}>{p.slice(1, -1)}</code>;
        return <span key={i}>{p.split("\n").map((line, j) => j === 0 ? line : <span key={j}><br />{line}</span>)}</span>;
      })}
    </span>
  );
}

/* ---- Drawer de implementação ---- */
function ImplementationDrawer({ rec, onClose }) {
  const [activeMethod, setActiveMethod] = useState(0);
  const [activeStep, setActiveStep] = useState(0);
  const kb = rec ? getKB(rec.name) : null;

  React.useEffect(() => {
    if (!rec) return;
    setActiveMethod(0);
    setActiveStep(0);
    const h = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [rec, onClose]);

  if (!rec) return null;

  const method = kb?.methods?.[activeMethod];
  const step = method?.steps?.[activeStep];

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 400, display: "flex" }}>
      {/* Backdrop */}
      <div onClick={onClose} style={{ flex: 1, background: "rgba(0,0,0,0.45)", backdropFilter: "blur(2px)" }} />

      {/* Drawer */}
      <div style={{ width: "min(720px, 90vw)", background: C.panel, borderLeft: `1px solid ${C.line}`, display: "flex", flexDirection: "column", height: "100vh", overflowY: "auto", boxShadow: "-8px 0 32px rgba(0,0,0,0.4)" }}>

        {/* Header */}
        <div style={{ padding: "20px 24px 16px", borderBottom: `1px solid ${C.line}`, position: "sticky", top: 0, background: C.panel, zIndex: 1 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: C.info, textTransform: "uppercase", letterSpacing: 1 }}>{rec.catGroup}</span>
                <span style={{ fontSize: 11, color: C.faint }}>·</span>
                <span style={{ fontSize: 11, color: C.faint }}>{rec.os || "all platforms"}</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.ok, marginLeft: 4 }}>{rec.impactRaw}</span>
              </div>
              <div style={{ fontSize: 16, fontWeight: 700, lineHeight: 1.3, color: C.ink }}>{rec.name}</div>
            </div>
            <button onClick={onClose} style={{ background: "none", border: `1px solid ${C.line}`, borderRadius: 8, padding: "6px 12px", color: C.dim, fontSize: 18, cursor: "pointer", lineHeight: 1, flexShrink: 0 }}>✕</button>
          </div>
          {rec.critical > 0 && (
            <div style={{ marginTop: 10, background: "rgba(242,84,91,0.08)", border: "1px solid rgba(242,84,91,0.25)", borderRadius: 8, padding: "8px 12px", fontSize: 12.5, color: C.crit }}>
              ⚠ <strong>{rec.critical} device{rec.critical > 1 ? "s" : ""} crítico{rec.critical > 1 ? "s" : ""}</strong> exposto{rec.critical > 1 ? "s" : ""} · {rec.exposed?.toLocaleString("pt-BR")} devices no total
            </div>
          )}
        </div>

        <div style={{ flex: 1, padding: "20px 24px" }}>

          {/* Sem KB — view genérica */}
          {!kb && (
            <div style={{ textAlign: "center", padding: "40px 20px", color: C.faint }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>📋</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: C.dim, marginBottom: 8 }}>Guia de implementação em construção</div>
              <div style={{ fontSize: 13, lineHeight: 1.6, marginBottom: 20 }}>
                Esta recomendação ainda não tem guia passo a passo no EndpointHub.<br />
                Consulte a documentação oficial do Microsoft Defender para os passos de remediação.
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "center" }}>
                <a href={`https://security.microsoft.com`} target="_blank" rel="noopener noreferrer"
                  style={{ color: C.info, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                  ↗ Abrir no Microsoft Defender portal
                </a>
                <a href="https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-security-recommendation" target="_blank" rel="noopener noreferrer"
                  style={{ color: C.info, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                  ↗ Documentação de Security Recommendations
                </a>
              </div>
              {/* dados do CSV */}
              <div style={{ marginTop: 28, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: 16, textAlign: "left" }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: C.dim, marginBottom: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>Dados do Defender</div>
                {[
                  ["Impacto no score", rec.impactRaw],
                  ["Categoria", rec.cat],
                  ["OS platform", rec.os || "—"],
                  ["Devices expostos", rec.exposed?.toLocaleString("pt-BR")],
                  ["Devices críticos", rec.critical],
                  ["Remediações abertas", rec.remediation],
                  ["Tags", rec.tags || "—"],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: `1px solid ${C.line}`, fontSize: 12.5 }}>
                    <span style={{ color: C.faint }}>{k}</span>
                    <span style={{ color: C.ink, fontWeight: 500 }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Com KB */}
          {kb && (
            <>
              {/* Resumo */}
              <div style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: 16, marginBottom: 20 }}>
                <div style={{ fontSize: 13, color: C.dim, lineHeight: 1.65, marginBottom: 10 }}>{kb.summary}</div>
                {kb.risk && (
                  <div style={{ background: "rgba(227,160,8,0.08)", border: "1px solid rgba(227,160,8,0.25)", borderRadius: 7, padding: "8px 12px", fontSize: 12.5, color: C.warn }}>
                    <strong>Risco:</strong> {kb.risk}
                  </div>
                )}
              </div>

              {/* Links */}
              {kb.links?.length > 0 && (
                <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
                  {kb.links.map((l, i) => (
                    <a key={i} href={l.url} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 12, color: C.info, border: `1px solid ${C.line}`, borderRadius: 6, padding: "4px 10px", textDecoration: "none", display: "flex", alignItems: "center", gap: 4 }}>
                      ↗ {l.label}
                    </a>
                  ))}
                </div>
              )}

              {/* Método selector */}
              <div style={{ fontSize: 12, fontWeight: 700, color: C.faint, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Como implementar</div>
              <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
                {kb.methods.map((m, i) => (
                  <button key={m.id} onClick={() => { setActiveMethod(i); setActiveStep(0); }}
                    style={{ background: activeMethod === i ? C.info : C.panel2, color: activeMethod === i ? "#fff" : C.dim, border: `1px solid ${activeMethod === i ? C.info : C.line}`, borderRadius: 8, padding: "8px 16px", fontSize: 13, fontWeight: 600, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                    <span>{m.icon}</span> {m.label}
                  </button>
                ))}
              </div>

              {/* Steps do método */}
              {method && (
                <div style={{ display: "flex", gap: 16 }}>
                  {/* Sidebar de steps */}
                  <div style={{ width: 180, flexShrink: 0 }}>
                    {method.steps.map((s, i) => (
                      <div key={i} onClick={() => setActiveStep(i)}
                        style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "10px 12px", borderRadius: 8, cursor: "pointer", background: activeStep === i ? "rgba(59,130,246,0.1)" : "transparent", border: activeStep === i ? `1px solid rgba(59,130,246,0.3)` : "1px solid transparent", marginBottom: 4 }}>
                        <div style={{ width: 22, height: 22, borderRadius: "50%", background: activeStep === i ? C.info : (i < activeStep ? C.ok : C.panel2), color: activeStep === i || i < activeStep ? "#fff" : C.faint, fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 1 }}>
                          {i < activeStep ? "✓" : i + 1}
                        </div>
                        <span style={{ fontSize: 12, color: activeStep === i ? C.ink : C.dim, lineHeight: 1.4 }}>{s.title}</span>
                      </div>
                    ))}
                  </div>

                  {/* Conteúdo do step */}
                  {step && (
                    <div style={{ flex: 1, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 12, padding: "18px 20px" }}>
                      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 12, color: C.ink }}>
                        <span style={{ color: C.info }}>Passo {activeStep + 1}</span> — {step.title}
                      </div>
                      <div style={{ fontSize: 13.5, color: C.dim, lineHeight: 1.7 }}>
                        <MarkdownText text={step.body} />
                      </div>
                      {step.code && <CodeBlock code={step.code} lang={step.lang} />}
                      {step.note && (
                        <div style={{ marginTop: 12, background: "rgba(59,130,246,0.07)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 7, padding: "8px 12px", fontSize: 12.5, color: C.info }}>
                          💡 {step.note}
                        </div>
                      )}
                      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 20, paddingTop: 16, borderTop: `1px solid ${C.line}` }}>
                        <button onClick={() => setActiveStep(Math.max(0, activeStep - 1))} disabled={activeStep === 0}
                          style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 16px", color: activeStep === 0 ? C.faint : C.dim, fontSize: 13, cursor: activeStep === 0 ? "default" : "pointer" }}>
                          ← Anterior
                        </button>
                        <span style={{ fontSize: 12, color: C.faint, alignSelf: "center" }}>{activeStep + 1} de {method.steps.length}</span>
                        {activeStep < method.steps.length - 1
                          ? <button onClick={() => setActiveStep(activeStep + 1)} style={{ background: C.info, border: "none", borderRadius: 8, padding: "8px 16px", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>Próximo →</button>
                          : <button style={{ background: C.ok, border: "none", borderRadius: 8, padding: "8px 16px", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "default" }}>✓ Concluído</button>}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function SecurityAdvisor() {
  const [recs, setRecs] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [loadedRec, setLoadedRec] = useState(null);
  const [loadedVuln, setLoadedVuln] = useState(null);
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState("Resumo");
  const [modal, setModal] = useState(null);
  const [drawer, setDrawer] = useState(null);
  const [filterRec, setFilterRec] = useState("");
  const [filterVuln, setFilterVuln] = useState("");
  const [filterCat, setFilterCat] = useState("Todos");
  const [filterOS, setFilterOS] = useState("Todos");
  const [filterSev, setFilterSev] = useState("Todos");
  const inputRef = useRef(null);

  const openModal = useCallback((cfg) => setModal(cfg), []);
  const closeModal = useCallback(() => setModal(null), []);

  const readFile = (file) => new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.onerror = () => rej(new Error("Erro ao ler " + file.name));
    r.readAsText(file, "UTF-8");
  });

  const ingest = useCallback(async (fileList) => {
    const csvs = Array.from(fileList).filter((f) => /\.csv$/i.test(f.name));
    if (!csvs.length) return;
    const errs = [];
    for (const file of csvs) {
      try {
        const text = await readFile(file);
        // Vulnerabilities tem 2 linhas de header — pular linha do título
        const cleanText = text.includes("Vulnerabilities Export") ? text.split("\n").slice(1).join("\n") : text;
        const { headers, data } = toObjects(cleanText);
        if (isRecommendations(headers)) {
          setRecs(data); setLoadedRec({ name: file.name, count: data.length });
        } else if (isVulnerabilities(headers)) {
          setVulns(data); setLoadedVuln({ name: file.name, count: data.length });
        } else {
          errs.push(`"${file.name}": formato não reconhecido.`);
        }
      } catch (e) { errs.push(e.message); }
    }
    setErr(errs.join(" | "));
  }, []);

  const onDrop = useCallback((e) => { e.preventDefault(); setDrag(false); ingest(e.dataTransfer.files); }, [ingest]);
  const R = useMemo(() => recs.length ? analyzeRec(recs) : null, [recs]);
  const V = useMemo(() => vulns.length ? analyzeVuln(vulns) : null, [vulns]);

  // Colunas padrão
  const colsRec = [
    { k: "impactRaw", h: "Impacto no score" },
    { k: "name", h: "Recomendação", wrap: true },
    { k: "catGroup", h: "Categoria" },
    { k: "os", h: "OS" },
    { k: "critical", h: "Críticos expostos" },
    { k: "exposed", h: "Devices expostos", r: (v) => v?.toLocaleString("pt-BR") },
    { k: "remediation", h: "Remediações abertas" },
    { k: "tags", h: "Tags" },
  ];
  const colsVuln = [
    { k: "name", h: "CVE/ID" },
    { k: "sev", h: "Severidade", r: (v) => v },
    { k: "cvss", h: "CVSS v3" },
    { k: "epss", h: "EPSS" },
    { k: "age", h: "Idade (dias)" },
    { k: "hasExploit", h: "Exploit", r: (v) => v ? "Sim ⚠" : "Não" },
    { k: "exposed", h: "Machines expostas" },
    { k: "software", h: "Software afetado", wrap: true },
    { k: "status", h: "Status" },
  ];

  // Filtros
  const filteredRecs = useMemo(() => {
    if (!R) return [];
    return R.recs.filter((r) => {
      if (filterCat !== "Todos" && r.catGroup !== filterCat) return false;
      if (filterOS !== "Todos" && r.os !== filterOS) return false;
      if (filterRec && !r.name.toLowerCase().includes(filterRec.toLowerCase())) return false;
      return true;
    });
  }, [R, filterCat, filterOS, filterRec]);

  const filteredVulns = useMemo(() => {
    if (!V) return [];
    return V.vulns.filter((v) => {
      if (filterSev !== "Todos" && v.sev !== filterSev) return false;
      if (filterVuln && !v.name.toLowerCase().includes(filterVuln.toLowerCase()) && !v.software.toLowerCase().includes(filterVuln.toLowerCase())) return false;
      return true;
    });
  }, [V, filterSev, filterVuln]);

  const hasData = R || V;

  return (
    <div style={{ color: C.ink, fontFamily: "'Inter', system-ui, sans-serif", padding: "8px 0 40px" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: C.info, fontWeight: 700 }}>Security Advisor</div>
          <h1 style={{ fontSize: 26, fontWeight: 700, margin: "4px 0 0", letterSpacing: -0.5 }}>Recomendações e Vulnerabilidades</h1>
        </div>
        <div style={{ fontSize: 12, color: C.faint }}>Microsoft Defender · processamento local</div>
      </div>

      {/* Upload */}
      <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop} onClick={() => inputRef.current?.click()}
        style={{ marginTop: 20, border: `1.5px dashed ${drag ? C.info : C.line}`, background: drag ? "rgba(59,130,246,0.06)" : C.panel, borderRadius: 12, padding: 20, cursor: "pointer" }}>
        <input ref={inputRef} type="file" accept=".csv" multiple style={{ display: "none" }} onChange={(e) => ingest(e.target.files)} />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>{drag ? "Solte os arquivos aqui" : "Arraste os CSVs do Defender — ou clique para selecionar"}</div>
            <div style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>Detecta automaticamente Recommendations e Vulnerabilities. Processamento 100% local.</div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
            {loadedRec
              ? <span style={{ fontSize: 12, color: C.ok, background: "rgba(46,160,67,0.1)", border: "1px solid rgba(46,160,67,0.3)", borderRadius: 6, padding: "5px 10px", display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.ok }} />Recommendations · <b>{loadedRec.count}</b>
                </span>
              : <span style={{ fontSize: 12, color: C.faint, border: `1px dashed ${C.line}`, borderRadius: 6, padding: "5px 10px" }}>① Security Recommendations (CSV do Defender portal)</span>}
            {loadedVuln
              ? <span style={{ fontSize: 12, color: C.ok, background: "rgba(46,160,67,0.1)", border: "1px solid rgba(46,160,67,0.3)", borderRadius: 6, padding: "5px 10px", display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.ok }} />Vulnerabilities · <b>{loadedVuln.count}</b>
                </span>
              : <span style={{ fontSize: 12, color: C.faint, border: `1px dashed ${C.line}`, borderRadius: 6, padding: "5px 10px" }}>② Vulnerabilities export <span style={{ color: C.info }}>(opcional)</span></span>}
          </div>
        </div>
        {err && <div style={{ marginTop: 10, fontSize: 12.5, color: C.crit }}>⚠ {err}</div>}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginTop: 20, marginBottom: 18, borderBottom: `1px solid ${C.line}`, flexWrap: "wrap" }}>
        {TABS.map((tb) => (
          <button key={tb} onClick={() => setTab(tb)}
            style={{ background: "none", border: "none", borderBottom: `2px solid ${tab === tb ? C.info : "transparent"}`, color: tab === tb ? C.ink : C.dim, padding: "8px 14px", fontSize: 13.5, fontWeight: 600, cursor: "pointer", marginBottom: -1 }}>{tb}</button>
        ))}
      </div>

      {!hasData && (
        <div style={{ marginTop: 40, textAlign: "center", color: C.faint, fontSize: 14 }}>
          Carregue pelo menos o CSV de <b style={{ color: C.dim }}>Security Recommendations</b> para ver as análises.<br />
          <span style={{ fontSize: 12.5, marginTop: 8, display: "block" }}>Defender portal → Exposure management → Recommendations → Export</span>
        </div>
      )}

      {/* ===== TAB: RESUMO ===== */}
      {hasData && tab === "Resumo" && (
        <>
          {R && (
            <>
              <div style={{ fontSize: 12, color: C.faint, textTransform: "uppercase", letterSpacing: 1, marginBottom: 10, fontWeight: 600 }}>Recomendações de Segurança</div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
                <KPI label="Recomendações" sub="Total ativo" value={R.N} accent={C.info} bar={100}
                  onClick={() => openModal({ title: "Todas as Recomendações", sub: `${R.N} recomendações priorizadas por impacto`, rows: R.recs, cols: colsRec })} />
                <KPI label="Impacto acumulado" sub="Score potencial se todas forem aplicadas" value={`${R.totalImpact.toFixed(1)}%`} accent={C.ok} />
                <KPI label="Com devices críticos" sub="Ao menos 1 device crítico exposto" value={R.withCritical} accent={C.crit}
                  onClick={() => openModal({ title: "Recomendações com devices críticos", sub: `${R.withCritical} itens com ao menos 1 device crítico exposto`, rows: R.recs.filter((r) => r.critical > 0), cols: colsRec })} />
                <KPI label="Com remediação aberta" sub="Já tem ticket/atividade no Intune" value={R.withRemediation} accent={C.warn}
                  onClick={() => openModal({ title: "Recomendações com remediação em andamento", sub: `${R.withRemediation} itens com atividade de remediação aberta`, rows: R.recs.filter((r) => r.remediation > 0), cols: colsRec })} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12, marginBottom: 24 }}>
                <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16 }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 12 }}>Por categoria</div>
                  {Object.entries(R.byGroup).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                    <div key={k} onClick={() => openModal({ title: `Categoria: ${k}`, sub: `${n} recomendações`, rows: R.recs.filter((r) => r.catGroup === k), cols: colsRec })}
                      style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, cursor: "pointer" }}
                      onMouseEnter={(e) => e.currentTarget.style.opacity = "0.7"} onMouseLeave={(e) => e.currentTarget.style.opacity = "1"}>
                      <div style={{ flex: 1, height: 6, background: C.line, borderRadius: 3, overflow: "hidden" }}>
                        <div style={{ width: `${(n / R.N) * 100}%`, height: "100%", background: C.info, borderRadius: 3 }} />
                      </div>
                      <span style={{ fontSize: 12, color: C.dim, minWidth: 90, textAlign: "right" }}>{k}</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: C.ink, minWidth: 28, textAlign: "right" }}>{n}</span>
                    </div>
                  ))}
                </div>
                <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, padding: 16 }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 12 }}>Top 10 por impacto no score</div>
                  {R.recs.slice(0, 10).map((r, i) => (
                    <div key={i} onClick={() => setDrawer(r)}
                      style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7, fontSize: 12, cursor: "pointer", borderRadius: 6, padding: "4px 6px", transition: "background .1s" }}
                      onMouseEnter={(e) => e.currentTarget.style.background = C.panel2}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                      <span style={{ color: C.accent, fontWeight: 700, minWidth: 44, fontVariantNumeric: "tabular-nums" }}>{r.impactRaw}</span>
                      <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{r.name}</span>
                      {KB_NAMES.has(r.name) && <span style={{ fontSize: 10, color: C.ok, border: `1px solid ${C.ok}`, borderRadius: 4, padding: "1px 5px", flexShrink: 0 }}>Guia</span>}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {V && (
            <>
              <div style={{ fontSize: 12, color: C.faint, textTransform: "uppercase", letterSpacing: 1, marginBottom: 10, fontWeight: 600, marginTop: 8 }}>Vulnerabilidades (CVEs)</div>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
                {["Critical", "High", "Medium", "Low"].map((sev) => (
                  <KPI key={sev} label={sev} sub="CVEs" value={V.bySev[sev] || 0} accent={SEV_COLOR[sev]} bar={((V.bySev[sev] || 0) / V.N) * 100}
                    pct={`${(((V.bySev[sev] || 0) / V.N) * 100).toFixed(1)}%`}
                    onClick={() => openModal({ title: `CVEs ${sev}`, sub: `${V.bySev[sev] || 0} vulnerabilidades com severidade ${sev}`, rows: V.vulns.filter((v) => v.sev === sev), cols: colsVuln })} />
                ))}
                <KPI label="Com exploit" sub="Exploit público disponível" value={V.withExploit.length} accent={C.crit}
                  onClick={() => openModal({ title: "CVEs com exploit disponível", sub: `${V.withExploit.length} vulnerabilidades com exploit público — prioridade máxima`, rows: V.withExploit, cols: colsVuln })} />
                <KPI label="Remediação necessária" sub="RemediationRequired" value={V.remReq.length} accent={C.warn}
                  onClick={() => openModal({ title: "CVEs que exigem remediação", sub: `${V.remReq.length} vulnerabilidades com status RemediationRequired`, rows: V.remReq, cols: colsVuln })} />
              </div>
            </>
          )}
        </>
      )}

      {/* ===== TAB: RECOMENDAÇÕES ===== */}
      {hasData && tab === "Recomendações" && R && (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14, alignItems: "center" }}>
            <input value={filterRec} onChange={(e) => setFilterRec(e.target.value)} placeholder="Buscar recomendação…"
              style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, minWidth: 260, outline: "none" }} />
            <select value={filterCat} onChange={(e) => setFilterCat(e.target.value)} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, outline: "none" }}>
              <option>Todos</option>
              {Object.keys(R.byGroup).sort().map((c) => <option key={c}>{c}</option>)}
            </select>
            <select value={filterOS} onChange={(e) => setFilterOS(e.target.value)} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, outline: "none" }}>
              <option>Todos</option>
              {Object.keys(R.byOS).sort().map((o) => <option key={o}>{o}</option>)}
            </select>
            <span style={{ fontSize: 12, color: C.faint, marginLeft: "auto" }}>{filteredRecs.length} de {R.N} recomendações</span>
            <button onClick={() => exportCSV(filteredRecs, colsRec, "Security_Recommendations")} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 14px", color: C.ink, fontSize: 12.5, cursor: "pointer", fontWeight: 600 }}>↓ Exportar CSV</button>
          </div>
          <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden" }}>
            <div style={{ overflowX: "auto", maxHeight: "60vh", overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
                  <tr>{colsRec.map((c) => <th key={c.k} style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>{c.h}</th>)}</tr>
                </thead>
                <tbody>
                  {filteredRecs.map((r, i) => {
                    const hasKB = KB_NAMES.has(r.name);
                    return (
                      <tr key={i} onClick={() => setDrawer(r)}
                        style={{ borderBottom: `1px solid ${C.line}`, cursor: "pointer", transition: "background .1s" }}
                        onMouseEnter={(e) => e.currentTarget.style.background = "rgba(59,130,246,0.04)"}
                        onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                        <td style={{ padding: "8px 14px", color: C.ok, fontWeight: 700, whiteSpace: "nowrap" }}>{r.impactRaw}</td>
                        <td style={{ padding: "8px 14px", color: C.ink, maxWidth: 400 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span>{r.name}</span>
                            {hasKB
                              ? <span style={{ fontSize: 10, fontWeight: 700, color: C.ok, border: `1px solid ${C.ok}`, borderRadius: 4, padding: "1px 6px", whiteSpace: "nowrap", flexShrink: 0 }}>✓ Guia</span>
                              : <span style={{ fontSize: 10, color: C.faint, border: `1px solid ${C.line}`, borderRadius: 4, padding: "1px 6px", whiteSpace: "nowrap", flexShrink: 0 }}>Ver detalhes →</span>}
                          </div>
                        </td>
                        <td style={{ padding: "8px 14px", color: C.dim, whiteSpace: "nowrap" }}>{r.catGroup}</td>
                        <td style={{ padding: "8px 14px", color: C.dim, whiteSpace: "nowrap" }}>{r.os || "—"}</td>
                        <td style={{ padding: "8px 14px", color: r.critical > 0 ? C.crit : C.ink, fontWeight: r.critical > 0 ? 700 : 400, whiteSpace: "nowrap" }}>{r.critical}</td>
                        <td style={{ padding: "8px 14px", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{r.exposed?.toLocaleString("pt-BR")}</td>
                        <td style={{ padding: "8px 14px", color: r.remediation > 0 ? C.warn : C.faint, whiteSpace: "nowrap" }}>{r.remediation}</td>
                        <td style={{ padding: "8px 14px", color: C.faint, fontSize: 11 }}>{r.tags || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredRecs.length === 0 && <div style={{ padding: 24, textAlign: "center", color: C.faint }}>Nenhum resultado.</div>}
            </div>
          </div>
        </>
      )}

      {/* ===== TAB: VULNERABILIDADES ===== */}
      {hasData && tab === "Vulnerabilidades" && V && (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14, alignItems: "center" }}>
            <input value={filterVuln} onChange={(e) => setFilterVuln(e.target.value)} placeholder="Buscar CVE ou software…"
              style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, minWidth: 260, outline: "none" }} />
            <select value={filterSev} onChange={(e) => setFilterSev(e.target.value)} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, outline: "none" }}>
              <option>Todos</option>
              {["Critical", "High", "Medium", "Low", "Unknown"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <span style={{ fontSize: 12, color: C.faint, marginLeft: "auto" }}>{filteredVulns.length} de {V.N} CVEs</span>
            <button onClick={() => exportCSV(filteredVulns, colsVuln, "Vulnerabilities")} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 14px", color: C.ink, fontSize: 12.5, cursor: "pointer", fontWeight: 600 }}>↓ Exportar CSV</button>
          </div>
          <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden" }}>
            <div style={{ overflowX: "auto", maxHeight: "60vh", overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
                  <tr>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>CVE / ID</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>Severidade</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>CVSS v3</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>EPSS</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>Exploit</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>Machines</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>Idade</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>Status</th>
                    <th style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2 }}>Software</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredVulns.map((v, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.line}` }}>
                      <td style={{ padding: "8px 14px", color: C.accent, fontWeight: 600, whiteSpace: "nowrap" }}>{v.name}</td>
                      <td style={{ padding: "8px 14px", whiteSpace: "nowrap" }}><SevBadge sev={v.sev} /></td>
                      <td style={{ padding: "8px 14px", color: v.cvss >= 9 ? C.crit : v.cvss >= 7 ? C.warn : C.ink, fontWeight: 600, whiteSpace: "nowrap" }}>{v.cvss || "—"}</td>
                      <td style={{ padding: "8px 14px", color: C.dim, whiteSpace: "nowrap" }}>{v.epss ? v.epss.toFixed(5) : "—"}</td>
                      <td style={{ padding: "8px 14px", whiteSpace: "nowrap", color: v.hasExploit ? C.crit : C.faint, fontWeight: v.hasExploit ? 700 : 400 }}>{v.hasExploit ? "✓ Sim" : "Não"}</td>
                      <td style={{ padding: "8px 14px", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>{v.exposed}</td>
                      <td style={{ padding: "8px 14px", color: v.age > 365 ? C.crit : v.age > 90 ? C.warn : C.ink, whiteSpace: "nowrap" }}>{v.age}d</td>
                      <td style={{ padding: "8px 14px", whiteSpace: "nowrap", color: v.status === "RemediationRequired" ? C.warn : C.faint, fontSize: 11 }}>{v.status}</td>
                      <td style={{ padding: "8px 14px", color: C.faint, fontSize: 11, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.software}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredVulns.length === 0 && <div style={{ padding: 24, textAlign: "center", color: C.faint }}>Nenhum resultado.</div>}
            </div>
          </div>
        </>
      )}

      {/* ===== TAB: COM EXPLOIT ===== */}
      {hasData && tab === "Com Exploit" && (
        <>
          {V && V.withExploit.length > 0 ? (
            <>
              <div style={{ background: "rgba(242,84,91,0.08)", border: "1px solid rgba(242,84,91,0.3)", borderRadius: 10, padding: "14px 18px", marginBottom: 18, display: "flex", gap: 12, alignItems: "center" }}>
                <div style={{ fontSize: 22, lineHeight: 1 }}>⚠</div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: C.crit }}>Prioridade máxima — {V.withExploit.length} CVE{V.withExploit.length > 1 ? "s" : ""} com exploit público disponível</div>
                  <div style={{ fontSize: 12.5, color: C.dim, marginTop: 3 }}>Estas vulnerabilidades têm exploit confirmado e devem ser remediadas imediatamente. Valide se há patches disponíveis e se os devices afetados estão isolados ou monitorados.</div>
                </div>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
                <button onClick={() => exportCSV(V.withExploit, colsVuln, "CVEs_Com_Exploit")} style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 14px", color: C.ink, fontSize: 12.5, cursor: "pointer", fontWeight: 600 }}>↓ Exportar CSV</button>
              </div>
              <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden" }}>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                    <thead><tr>
                      {["CVE / ID", "Severidade", "CVSS v3", "EPSS", "Machines expostas", "Idade (dias)", "Software afetado", "Status", "Publicado"].map((h) => (
                        <th key={h} style={{ textAlign: "left", padding: "9px 14px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap" }}>{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {V.withExploit.map((v, i) => (
                        <tr key={i} style={{ borderBottom: `1px solid ${C.line}`, background: "rgba(242,84,91,0.03)" }}>
                          <td style={{ padding: "8px 14px", color: C.crit, fontWeight: 700 }}>{v.name}</td>
                          <td style={{ padding: "8px 14px" }}><SevBadge sev={v.sev} /></td>
                          <td style={{ padding: "8px 14px", color: v.cvss >= 9 ? C.crit : C.warn, fontWeight: 700 }}>{v.cvss}</td>
                          <td style={{ padding: "8px 14px", color: C.dim }}>{v.epss ? v.epss.toFixed(5) : "—"}</td>
                          <td style={{ padding: "8px 14px", fontVariantNumeric: "tabular-nums" }}>{v.exposed}</td>
                          <td style={{ padding: "8px 14px", color: v.age > 365 ? C.crit : C.warn }}>{v.age}d</td>
                          <td style={{ padding: "8px 14px", color: C.faint, fontSize: 11, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.software}</td>
                          <td style={{ padding: "8px 14px", color: C.warn, fontSize: 11 }}>{v.status}</td>
                          <td style={{ padding: "8px 14px", color: C.dim, whiteSpace: "nowrap" }}>{v.published}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div style={{ marginTop: 40, textAlign: "center", color: C.faint, fontSize: 14 }}>
              {V ? "✓ Nenhum CVE com exploit disponível encontrado nas vulnerabilidades carregadas." : "Carregue o CSV de Vulnerabilities para ver os CVEs com exploit."}
            </div>
          )}
        </>
      )}

      <Modal modal={modal} onClose={closeModal} />
      <ImplementationDrawer rec={drawer} onClose={() => setDrawer(null)} />
    </div>
  );
}
