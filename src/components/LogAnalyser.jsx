import React, { useState, useMemo, useCallback, useRef } from "react";
import { getErrorInfo, extractErrorCode } from "../data/log-error-codes.js";

/* ============================================================
   Log Analyser — EndpointHub
   Lê logs (CMTrace/IntuneManagementExtension.log, Windows Event
   Viewer CSV, Defender/MDE CSV, ou texto genérico), classifica
   cada linha por severidade e enriquece erros conhecidos com
   causa provável e correção — a partir da KB local.
   Processamento 100% local; nenhum dado sai do navegador.
   ============================================================ */

const C = {
  bg: "var(--bg)", panel: "var(--panel)", panel2: "var(--panel2)", line: "var(--line)",
  ink: "var(--ink)", dim: "var(--dim)", faint: "var(--faint)",
  crit: "var(--crit)", warn: "var(--warn)", info: "var(--accent)", ok: "var(--ok)",
  cyan: "var(--cyan)", violet: "var(--violet)",
};

const SEV_COLOR = { critical: C.crit, error: C.crit, warning: C.warn, info: C.dim };
const SEV_ORDER = { critical: 0, error: 1, warning: 2, info: 3 };
const MAX_ROWS = 4000;

/* ---------- CSV parsing (mesmo parser robusto usado no Security Advisor) ---------- */
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
function toObjects(text, delim = ",") {
  const clean = text.replace(/^\uFEFF/, "");
  const rows = parseCSV(clean, delim).filter((r) => r.some((c) => c.trim() !== ""));
  if (!rows.length) return { headers: [], data: [] };
  const headers = rows[0].map((h) => h.trim());
  const data = rows.slice(1).map((r) => { const o = {}; headers.forEach((h, i) => (o[h] = (r[i] ?? "").trim())); return o; });
  return { headers, data };
}
function findCol(headersLower, candidates) {
  for (const cand of candidates) { const i = headersLower.indexOf(cand); if (i >= 0) return i; }
  for (const cand of candidates) { const i = headersLower.findIndex((h) => h.includes(cand)); if (i >= 0) return i; }
  return -1;
}

/* ---------- Detecção de formato ---------- */
function detectFormat(text) {
  const head = text.slice(0, 4000);
  if (head.includes("<![LOG[") && head.includes("]LOG]!>")) return "cmtrace";
  const firstLine = text.split(/\r?\n/, 1)[0] || "";
  if (firstLine.includes(",")) {
    const headers = parseCSV(firstLine, ",")[0]?.map((h) => h.trim().toLowerCase()) || [];
    const hasLevel = headers.some((h) => ["level", "nível", "nivel"].includes(h));
    const hasSeverity = headers.some((h) => h === "severity" || h === "severidad" || h === "gravidade");
    const hasSource = headers.some((h) => ["source", "origem", "fuente"].includes(h));
    const hasMdeCols = headers.some((h) => ["devicename", "alertid", "actiontype", "category"].includes(h));
    if (hasLevel && hasSource) return "eventviewer";
    if (hasSeverity && (hasMdeCols || headers.some((h) => h.includes("title")))) return "defender";
  }
  return "generic";
}

/* ---------- Parsers ---------- */
function parseCMTrace(text) {
  const re = /<!\[LOG\[([\s\S]*?)\]LOG\]!><time="([^"]+)" date="([^"]+)" component="([^"]*)" context="([^"]*)" type="(\d+)" thread="([^"]*)" file="([^"]*)">/g;
  const rows = [];
  let m, id = 0;
  while ((m = re.exec(text)) !== null) {
    const [, msg, time, date, component, , type] = m;
    const sevType = { "1": "info", "2": "warning", "3": "error" }[type] || "info";
    const message = msg.trim();
    rows.push({
      id: id++,
      time: `${date} ${time}`.trim(),
      source: component || "—",
      severity: sevType,
      message,
      code: extractErrorCode(message),
    });
  }
  return rows;
}

function parseEventViewerCSV(text) {
  const { headers, data } = toObjects(text, ",");
  const H = headers.map((h) => h.toLowerCase());
  const levelI = findCol(H, ["level", "nível", "nivel"]);
  const dateI = findCol(H, ["date and time", "logged", "timecreated", "data e hora", "fecha y hora"]);
  const sourceI = findCol(H, ["source", "origem", "fuente"]);
  const idI = findCol(H, ["event id", "id do evento", "id de evento"]);
  const msgI = findCol(H, ["message", "description", "descrição", "descripción", "general"]);
  const catI = findCol(H, ["task category", "categoria da tarefa", "categoría de la tarea"]);

  return data.slice(0, MAX_ROWS).map((row, i) => {
    const vals = headers.map((h) => row[h]);
    const levelRaw = (levelI >= 0 ? vals[levelI] : "").toLowerCase();
    let severity = "info";
    if (levelRaw.includes("critical") || levelRaw.includes("crítico")) severity = "critical";
    else if (levelRaw.includes("error") || levelRaw.includes("erro")) severity = "error";
    else if (levelRaw.includes("warn") || levelRaw.includes("aviso") || levelRaw.includes("advert")) severity = "warning";

    let message = msgI >= 0 ? vals[msgI] : "";
    if (!message) {
      const used = new Set([levelI, dateI, sourceI, idI, catI].filter((x) => x >= 0));
      message = headers.filter((_, hi) => !used.has(hi)).map((h, hi) => vals[hi]).filter(Boolean).join(" | ");
    }
    const eventId = idI >= 0 ? vals[idI] : "";
    return {
      id: i,
      time: dateI >= 0 ? vals[dateI] : "—",
      source: (sourceI >= 0 ? vals[sourceI] : "—") + (eventId ? ` (ID ${eventId})` : ""),
      severity,
      message: message || "—",
      code: extractErrorCode(message),
    };
  });
}

function parseDefenderCSV(text) {
  const { headers, data } = toObjects(text, ",");
  const H = headers.map((h) => h.toLowerCase());
  const sevI = findCol(H, ["severity", "gravidade", "severidad"]);
  const timeI = findCol(H, ["timestamp", "creation time", "created time", "eventtime", "data"]);
  const devI = findCol(H, ["devicename", "device name", "dispositivo"]);
  const titleI = findCol(H, ["title", "actiontype", "category"]);

  return data.slice(0, MAX_ROWS).map((row, i) => {
    const vals = headers.map((h) => row[h]);
    const sevRaw = (sevI >= 0 ? vals[sevI] : "").toLowerCase();
    let severity = "info";
    if (sevRaw.includes("critical") || sevRaw.includes("high") || sevRaw.includes("crítico") || sevRaw.includes("alto")) severity = "error";
    else if (sevRaw.includes("medium") || sevRaw.includes("médio") || sevRaw.includes("medio")) severity = "warning";

    const message = titleI >= 0 ? vals[titleI] : headers.map((h, hi) => vals[hi]).filter(Boolean).join(" | ");
    return {
      id: i,
      time: timeI >= 0 ? vals[timeI] : "—",
      source: devI >= 0 ? vals[devI] : "Defender",
      severity,
      message: message || "—",
      code: extractErrorCode(message),
    };
  });
}

function classifyGenericLine(line) {
  if (/\b(critical|crítico|fatal)\b/i.test(line)) return "critical";
  if (/\b(error|erro|fail(ed|ure)?|falha|exception|excepción|0x[0-9a-f]{8})\b/i.test(line)) return "error";
  if (/\b(warn(ing)?|aviso|advertencia)\b/i.test(line)) return "warning";
  return "info";
}
function parseGeneric(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  return lines.slice(0, MAX_ROWS).map((line, i) => ({
    id: i,
    time: "—",
    source: "—",
    severity: classifyGenericLine(line),
    message: line.trim(),
    code: extractErrorCode(line),
  }));
}

function parseLog(text, forcedFormat) {
  if (!text || !text.trim()) return { format: null, rows: [] };
  const format = forcedFormat && forcedFormat !== "auto" ? forcedFormat : detectFormat(text);
  let rows = [];
  if (format === "cmtrace") rows = parseCMTrace(text);
  else if (format === "eventviewer") rows = parseEventViewerCSV(text);
  else if (format === "defender") rows = parseDefenderCSV(text);
  else rows = parseGeneric(text);
  if (format === "cmtrace" && rows.length === 0) rows = parseGeneric(text); // fallback se regex não casar
  return { format, rows: rows.slice(0, MAX_ROWS) };
}

/* ---------- i18n ---------- */
const L = {
  pt: {
    eyebrow: "Log Analyser", h1: "Erros e avisos, direto do seu log",
    sub: "Cole ou envie um log — CMTrace (IntuneManagementExtension.log), Windows Event Viewer, Defender/MDE ou texto genérico. Detecção automática de formato, classificação por severidade e explicação de códigos de erro conhecidos.",
    dropTitle: "Arraste o arquivo de log — ou clique para selecionar",
    dropDrag: "Solte o arquivo aqui",
    dropSub: "Aceita .log, .txt, .csv. Processamento 100% local — nenhum dado é enviado.",
    orPaste: "ou cole o conteúdo do log aqui",
    pastePlaceholder: "Cole aqui o conteúdo do log (CMTrace, Event Viewer CSV, Defender CSV ou texto puro)…",
    formatLabel: "Formato", formatAuto: "Detectar automaticamente",
    fmt: { cmtrace: "CMTrace (Intune Management Extension)", eventviewer: "Windows Event Viewer (CSV)", defender: "Defender / MDE (CSV)", generic: "Texto genérico" },
    detected: "Formato detectado",
    clear: "Limpar",
    search: "Buscar na mensagem, origem ou código…",
    all: "Todos", critical: "Crítico", error: "Erro", warning: "Aviso", info: "Info",
    colTime: "Horário", colSource: "Origem", colSev: "Severidade", colMsg: "Mensagem",
    noRows: "Nenhuma linha corresponde ao filtro atual.",
    noData: "Envie ou cole um log para começar a análise.",
    truncated: (n) => `Mostrando as primeiras ${n.toLocaleString("pt-BR")} linhas para manter a performance.`,
    exportCsv: "Exportar CSV (filtrado)",
    footer: (t, e, w, i) => `${t.toLocaleString("pt-BR")} linhas analisadas · ${e} erro${e === 1 ? "" : "s"} · ${w} aviso${w === 1 ? "" : "s"} · ${i} info. Processamento 100% local no navegador; nenhum dado sai da máquina.`,
    codeFound: "Código detectado",
    known: "Causa provável", fix: "O que verificar",
    unknownCode: (code) => `O código ${code} foi detectado mas ainda não está catalogado na base local do EndpointHub.`,
    unknownGeneric: "Este código de erro ainda não está catalogado na base local do EndpointHub. Consulte a documentação oficial abaixo.",
    searchDocs: "↗ Pesquisar no Microsoft Learn",
    noCode: "Nenhum código de erro reconhecido nesta linha.",
    rawLine: "Linha original",
    close: "Fechar",
  },
  en: {
    eyebrow: "Log Analyser", h1: "Errors and warnings, straight from your log",
    sub: "Paste or upload a log — CMTrace (IntuneManagementExtension.log), Windows Event Viewer, Defender/MDE, or plain text. Automatic format detection, severity classification, and explanations for known error codes.",
    dropTitle: "Drag the log file — or click to select",
    dropDrag: "Drop the file here",
    dropSub: "Accepts .log, .txt, .csv. 100% local processing — no data is sent.",
    orPaste: "or paste the log content here",
    pastePlaceholder: "Paste the log content here (CMTrace, Event Viewer CSV, Defender CSV, or plain text)…",
    formatLabel: "Format", formatAuto: "Auto-detect",
    fmt: { cmtrace: "CMTrace (Intune Management Extension)", eventviewer: "Windows Event Viewer (CSV)", defender: "Defender / MDE (CSV)", generic: "Plain text" },
    detected: "Detected format",
    clear: "Clear",
    search: "Search message, source, or code…",
    all: "All", critical: "Critical", error: "Error", warning: "Warning", info: "Info",
    colTime: "Time", colSource: "Source", colSev: "Severity", colMsg: "Message",
    noRows: "No line matches the current filter.",
    noData: "Upload or paste a log to start the analysis.",
    truncated: (n) => `Showing the first ${n.toLocaleString("en-US")} lines to keep performance smooth.`,
    exportCsv: "Export CSV (filtered)",
    footer: (t, e, w, i) => `${t.toLocaleString("en-US")} lines analyzed · ${e} error${e === 1 ? "" : "s"} · ${w} warning${w === 1 ? "" : "s"} · ${i} info. 100% local processing in the browser; no data leaves the machine.`,
    codeFound: "Code detected",
    known: "Likely cause", fix: "What to check",
    unknownCode: (code) => `Code ${code} was detected but isn't yet catalogued in EndpointHub's local knowledge base.`,
    unknownGeneric: "This error code isn't yet catalogued in EndpointHub's local knowledge base. Check the official docs below.",
    searchDocs: "↗ Search Microsoft Learn",
    noCode: "No recognizable error code in this line.",
    rawLine: "Raw line",
    close: "Close",
  },
  es: {
    eyebrow: "Log Analyser", h1: "Errores y avisos, directo de tu log",
    sub: "Pega o sube un log — CMTrace (IntuneManagementExtension.log), Windows Event Viewer, Defender/MDE o texto plano. Detección automática de formato, clasificación por severidad y explicación de códigos de error conocidos.",
    dropTitle: "Arrastra el archivo de log — o haz clic para seleccionar",
    dropDrag: "Suelta el archivo aquí",
    dropSub: "Acepta .log, .txt, .csv. Procesamiento 100% local — ningún dato se envía.",
    orPaste: "o pega el contenido del log aquí",
    pastePlaceholder: "Pega aquí el contenido del log (CMTrace, Event Viewer CSV, Defender CSV o texto plano)…",
    formatLabel: "Formato", formatAuto: "Detectar automáticamente",
    fmt: { cmtrace: "CMTrace (Intune Management Extension)", eventviewer: "Windows Event Viewer (CSV)", defender: "Defender / MDE (CSV)", generic: "Texto plano" },
    detected: "Formato detectado",
    clear: "Limpiar",
    search: "Buscar en mensaje, origen o código…",
    all: "Todos", critical: "Crítico", error: "Error", warning: "Aviso", info: "Info",
    colTime: "Hora", colSource: "Origen", colSev: "Severidad", colMsg: "Mensaje",
    noRows: "Ninguna línea coincide con el filtro actual.",
    noData: "Sube o pega un log para comenzar el análisis.",
    truncated: (n) => `Mostrando las primeras ${n.toLocaleString("es-ES")} líneas para mantener el rendimiento.`,
    exportCsv: "Exportar CSV (filtrado)",
    footer: (t, e, w, i) => `${t.toLocaleString("es-ES")} líneas analizadas · ${e} error${e === 1 ? "" : "es"} · ${w} aviso${w === 1 ? "" : "s"} · ${i} info. Procesamiento 100% local en el navegador; ningún dato sale de la máquina.`,
    codeFound: "Código detectado",
    known: "Causa probable", fix: "Qué verificar",
    unknownCode: (code) => `Se detectó el código ${code} pero aún no está catalogado en la base local de EndpointHub.`,
    unknownGeneric: "Este código de error aún no está catalogado en la base local de EndpointHub. Consulta la documentación oficial abajo.",
    searchDocs: "↗ Buscar en Microsoft Learn",
    noCode: "Ningún código de error reconocido en esta línea.",
    rawLine: "Línea original",
    close: "Cerrar",
  },
};

const SEV_LIST = ["critical", "error", "warning", "info"];

/* ---------- Drawer de detalhe ---------- */
function DetailDrawer({ row, t, onClose }) {
  React.useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
  if (!row) return null;
  const info = row.code ? getErrorInfo(row.code) : null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 400, display: "flex" }}>
      <div onClick={onClose} style={{ flex: 1, background: "rgba(0,0,0,0.45)", backdropFilter: "blur(2px)" }} />
      <div style={{ width: "min(600px, 92vw)", background: C.panel, borderLeft: `1px solid ${C.line}`, display: "flex", flexDirection: "column", height: "100vh", overflowY: "auto", boxShadow: "-8px 0 32px rgba(0,0,0,0.4)" }}>
        <div style={{ padding: "20px 24px 16px", borderBottom: `1px solid ${C.line}`, position: "sticky", top: 0, background: C.panel, zIndex: 1 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: "50%", background: SEV_COLOR[row.severity], display: "inline-block" }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: SEV_COLOR[row.severity], textTransform: "uppercase", letterSpacing: 1 }}>{t[row.severity]}</span>
            </div>
            <button onClick={onClose} style={{ background: "none", border: `1px solid ${C.line}`, borderRadius: 8, padding: "6px 12px", color: C.dim, fontSize: 18, cursor: "pointer", lineHeight: 1 }}>✕</button>
          </div>
          <div style={{ marginTop: 10, fontSize: 12, color: C.faint }}>{row.time} · {row.source}</div>
        </div>

        <div style={{ flex: 1, padding: "20px 24px" }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: C.dim, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>{t.rawLine}</div>
          <div style={{ background: "#0d1117", border: `1px solid ${C.line}`, borderRadius: 8, padding: "12px 14px", fontFamily: "ui-monospace, 'Cascadia Code', monospace", fontSize: 12.5, lineHeight: 1.6, color: "#e6edf3", whiteSpace: "pre-wrap", wordBreak: "break-word", marginBottom: 20 }}>
            {row.message}
          </div>

          {row.code && (
            <div style={{ marginBottom: 16 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: C.info, textTransform: "uppercase", letterSpacing: 0.5 }}>{t.codeFound}</span>
              <div style={{ fontFamily: "ui-monospace, monospace", fontSize: 15, fontWeight: 700, color: C.ink, marginTop: 4 }}>{row.code}</div>
            </div>
          )}

          {info ? (
            <>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.ink, marginBottom: 14 }}>{info.title}</div>
              <div style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: 14, marginBottom: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.warn, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>{t.known}</div>
                <div style={{ fontSize: 13.5, lineHeight: 1.6, color: C.dim }}>{info.cause}</div>
              </div>
              <div style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: C.ok, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>{t.fix}</div>
                <div style={{ fontSize: 13.5, lineHeight: 1.6, color: C.dim }}>{info.fix}</div>
              </div>
            </>
          ) : row.code ? (
            <div style={{ textAlign: "center", padding: "24px 12px", color: C.faint }}>
              <div style={{ fontSize: 13.5, lineHeight: 1.6, marginBottom: 14 }}>{t.unknownCode(row.code)}</div>
              <a href={`https://learn.microsoft.com/en-us/search/?terms=${encodeURIComponent(row.code)}`} target="_blank" rel="noopener noreferrer" style={{ color: C.info, fontSize: 13 }}>{t.searchDocs}</a>
            </div>
          ) : (row.severity === "error" || row.severity === "critical" || row.severity === "warning") ? (
            <div style={{ textAlign: "center", padding: "24px 12px", color: C.faint }}>
              <div style={{ fontSize: 13.5, lineHeight: 1.6, marginBottom: 14 }}>{t.unknownGeneric}</div>
              <a href={`https://learn.microsoft.com/en-us/search/?terms=${encodeURIComponent(row.message.slice(0, 80))}`} target="_blank" rel="noopener noreferrer" style={{ color: C.info, fontSize: 13 }}>{t.searchDocs}</a>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "24px 12px", color: C.faint, fontSize: 13 }}>{t.noCode}</div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Componente principal ---------- */
export default function LogAnalyser({ lang = "pt" }) {
  const t = L[lang] || L.pt;
  const [rawText, setRawText] = useState("");
  const [fileName, setFileName] = useState("");
  const [forcedFormat, setForcedFormat] = useState("auto");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [drag, setDrag] = useState(false);
  const [selected, setSelected] = useState(null);
  const inputRef = useRef(null);

  const ingest = useCallback((files) => {
    const file = files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => { setRawText(String(e.target.result || "")); setFileName(file.name); };
    reader.readAsText(file, "UTF-8");
  }, []);

  const onDrop = useCallback((e) => { e.preventDefault(); setDrag(false); ingest(e.dataTransfer.files); }, [ingest]);
  const onBrowse = useCallback((e) => { ingest(e.target.files); }, [ingest]);

  const parsed = useMemo(() => parseLog(rawText, forcedFormat), [rawText, forcedFormat]);

  const counts = useMemo(() => {
    const c = { critical: 0, error: 0, warning: 0, info: 0 };
    parsed.rows.forEach((r) => { c[r.severity] = (c[r.severity] || 0) + 1; });
    return c;
  }, [parsed.rows]);

  const filteredRows = useMemo(() => {
    let rows = parsed.rows;
    if (sevFilter !== "all") rows = rows.filter((r) => r.severity === sevFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      rows = rows.filter((r) => r.message.toLowerCase().includes(q) || r.source.toLowerCase().includes(q) || (r.code && r.code.toLowerCase().includes(q)));
    }
    return rows;
  }, [parsed.rows, sevFilter, search]);

  const clearAll = () => { setRawText(""); setFileName(""); setSearch(""); setSevFilter("all"); if (inputRef.current) inputRef.current.value = ""; };

  const exportCsv = () => {
    const header = ["severity", "time", "source", "code", "message"];
    const lines = [header.join(",")];
    filteredRows.forEach((r) => {
      const vals = [r.severity, r.time, r.source, r.code || "", r.message].map((v) => `"${String(v).replace(/"/g, '""')}"`);
      lines.push(vals.join(","));
    });
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "log-analyser-export.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const hasData = parsed.rows.length > 0;

  return (
    <div style={{ maxWidth: 1200, margin: "0 auto", padding: "28px 4px 60px" }}>
      <p style={{ fontSize: 12, fontWeight: 700, color: C.info, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>{t.eyebrow}</p>
      <h1 style={{ fontSize: 26, fontWeight: 800, color: C.ink, marginBottom: 8 }}>{t.h1}</h1>
      <p style={{ fontSize: 14, color: C.dim, lineHeight: 1.6, maxWidth: 780, marginBottom: 24 }}>{t.sub}</p>

      {/* Dropzone + paste */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `2px dashed ${drag ? C.info : C.line}`, borderRadius: 12, padding: "22px 20px",
          textAlign: "center", cursor: "pointer", background: drag ? "rgba(88,166,255,0.06)" : C.panel2,
          transition: "all 0.15s",
        }}
      >
        <input ref={inputRef} type="file" accept=".log,.txt,.csv" style={{ display: "none" }} onChange={onBrowse} />
        <div style={{ fontSize: 14, fontWeight: 600, color: C.ink, marginBottom: 4 }}>{drag ? t.dropDrag : t.dropTitle}</div>
        <div style={{ fontSize: 12, color: C.faint }}>{fileName ? `📄 ${fileName}` : t.dropSub}</div>
      </div>

      <div style={{ marginTop: 14 }}>
        <div style={{ fontSize: 12, color: C.faint, marginBottom: 6 }}>{t.orPaste}</div>
        <textarea
          value={rawText}
          onChange={(e) => { setRawText(e.target.value); setFileName(""); }}
          placeholder={t.pastePlaceholder}
          rows={hasData ? 3 : 8}
          style={{
            width: "100%", background: "#0d1117", border: `1px solid ${C.line}`, borderRadius: 10,
            padding: "12px 14px", color: "#e6edf3", fontFamily: "ui-monospace, 'Cascadia Code', monospace",
            fontSize: 12.5, lineHeight: 1.6, resize: "vertical", boxSizing: "border-box",
          }}
        />
      </div>

      {/* Formato + limpar */}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12, marginTop: 14 }}>
        <label style={{ fontSize: 12, color: C.dim, display: "flex", alignItems: "center", gap: 8 }}>
          {t.formatLabel}:
          <select value={forcedFormat} onChange={(e) => setForcedFormat(e.target.value)}
            style={{ background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 6, padding: "5px 8px", color: C.ink, fontSize: 12.5 }}>
            <option value="auto">{t.formatAuto}</option>
            <option value="cmtrace">{t.fmt.cmtrace}</option>
            <option value="eventviewer">{t.fmt.eventviewer}</option>
            <option value="defender">{t.fmt.defender}</option>
            <option value="generic">{t.fmt.generic}</option>
          </select>
        </label>
        {parsed.format && (
          <span style={{ fontSize: 12, color: C.faint }}>{t.detected}: <strong style={{ color: C.info }}>{t.fmt[parsed.format]}</strong></span>
        )}
        {hasData && (
          <button onClick={clearAll} style={{ marginLeft: "auto", background: "none", border: `1px solid ${C.line}`, borderRadius: 6, padding: "5px 12px", color: C.dim, fontSize: 12, cursor: "pointer" }}>{t.clear}</button>
        )}
      </div>

      {!hasData && (
        <div style={{ textAlign: "center", padding: "40px 20px", color: C.faint, fontSize: 13.5 }}>{t.noData}</div>
      )}

      {hasData && (
        <>
          {/* Summary chips */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 22, marginBottom: 16 }}>
            {["all", ...SEV_LIST].map((sev) => {
              const active = sevFilter === sev;
              const n = sev === "all" ? parsed.rows.length : counts[sev];
              const color = sev === "all" ? C.info : SEV_COLOR[sev];
              return (
                <button key={sev} onClick={() => setSevFilter(sev)}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderRadius: 10,
                    border: `1px solid ${active ? color : C.line}`, background: active ? `${color}18` : C.panel2,
                    cursor: "pointer", fontSize: 13,
                  }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
                  <span style={{ color: active ? color : C.dim, fontWeight: active ? 700 : 500 }}>{t[sev]}</span>
                  <span style={{ color: C.faint, fontWeight: 700 }}>{n.toLocaleString()}</span>
                </button>
              );
            })}
            <button onClick={exportCsv} style={{ marginLeft: "auto", background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: "8px 14px", color: C.dim, fontSize: 13, cursor: "pointer", fontWeight: 600 }}>
              ⬇ {t.exportCsv}
            </button>
          </div>

          <input
            value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t.search}
            style={{ width: "100%", boxSizing: "border-box", background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 10, padding: "10px 14px", color: C.ink, fontSize: 13.5, marginBottom: 14 }}
          />

          {parsed.rows.length >= MAX_ROWS && (
            <div style={{ fontSize: 11.5, color: C.faint, marginBottom: 10 }}>{t.truncated(MAX_ROWS)}</div>
          )}

          {/* Lista de linhas */}
          <div style={{ border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden" }}>
            {filteredRows.length === 0 ? (
              <div style={{ textAlign: "center", padding: "30px 20px", color: C.faint, fontSize: 13 }}>{t.noRows}</div>
            ) : (
              filteredRows.slice(0, 800).map((row) => (
                <div key={row.id} onClick={() => setSelected(row)}
                  style={{
                    display: "flex", alignItems: "flex-start", gap: 12, padding: "10px 14px",
                    borderLeft: `3px solid ${SEV_COLOR[row.severity]}`, borderBottom: `1px solid ${C.line}`,
                    background: C.panel, cursor: "pointer",
                  }}
                >
                  <span style={{ fontSize: 10.5, color: C.faint, fontFamily: "ui-monospace, monospace", minWidth: 130, paddingTop: 2 }}>{row.time}</span>
                  <span style={{ fontSize: 11, color: C.dim, minWidth: 110, paddingTop: 2, flexShrink: 0 }}>{row.source}</span>
                  <span style={{ fontSize: 12.5, color: C.ink, lineHeight: 1.5, flex: 1, wordBreak: "break-word", fontFamily: "ui-monospace, monospace" }}>
                    {row.message.length > 220 ? row.message.slice(0, 220) + "…" : row.message}
                  </span>
                  {row.code && (
                    <span style={{ fontSize: 10.5, fontWeight: 700, color: C.info, background: `${C.info}18`, borderRadius: 6, padding: "2px 8px", flexShrink: 0 }}>{row.code}</span>
                  )}
                </div>
              ))
            )}
          </div>

          <p style={{ fontSize: 11.5, color: C.faint, marginTop: 14, textAlign: "center" }}>
            {t.footer(parsed.rows.length, counts.error + counts.critical, counts.warning, counts.info)}
          </p>
        </>
      )}

      <DetailDrawer row={selected} t={t} onClose={() => setSelected(null)} />
    </div>
  );
}
