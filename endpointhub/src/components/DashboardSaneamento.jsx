import React, { useState, useMemo, useCallback, useRef } from "react";

/* ============================================================
   Saneamento de Endpoints — Intune × Defender × Entra
   Upload de CSVs no navegador → detecção automática de base,
   separador e encoding → cruzamento e recálculo ao vivo.
   Cruzamentos:
     • Estoque(CMDB) × Intune  → por Serial
     • Intune × Defender × Entra → por AAD Device ID (Object ID)
   ============================================================ */

const C = {
  bg: "#0d1117", panel: "#161b22", panel2: "#1c232d", line: "#2a3441",
  ink: "#e6edf3", dim: "#8b98a5", faint: "#5a6570",
  crit: "#f2545b", warn: "#e3a008", info: "#3b82f6", ok: "#2ea043",
  cyan: "#39c5cf", violet: "#a371f7",
};
const OS_COLOR = { Windows: C.info, macOS: C.dim, iOS: C.cyan, Android: C.ok, Linux: C.violet, Outro: C.faint };

/* ---------- Traduções da interface do dashboard ---------- */
const L = {
  pt: {
    eyebrow: "Saneamento de Endpoints", h1: "Equicidade entre bases",
    xref: "Estoque×Intune por Serial · Intune×Defender×Entra por AAD Object ID",
    dropTitle: "Arraste os CSVs — ou clique para selecionar",
    dropDrag: "Solte os arquivos aqui",
    dropSub: "Detecta automaticamente Intune, Defender, Entra e Estoque pelo cabeçalho. Reenviar um arquivo o substitui. Processamento 100% local — nenhum dado é enviado.",
    baseUnknown: "base não reconhecida", readFail: "leitura falhou",
    emptyLine1a: "Carregue pelo menos", emptyLine1b: "e", emptyLine1c: "para ver a equicidade.",
    emptyLine2a: "Adicione", emptyLine2b: "e", emptyLine2c: "para o cenário completo de saneamento.",
    mEquity: "Equicidade Intune↔Defender", mEquitySub: "nas duas bases",
    mStock: "Estoque a excluir", mStockSub: "também no Defender",
    mOnlyDef: "Só no Defender", mOnlyDefSub: "órfãos sem Intune",
    mOnlyInt: "Só no Intune", mOnlyIntSub: (d, m) => `${d} desktop · ${m} mobile`,
    mEntra: "Entra órfão", mEntraSub: "sem Intune e sem Defender",
    coverage: "Cobertura Intune ↔ Defender (AAD Object ID)",
    objects: "objetos", universe: "universo total",
    legBoth: "Nas duas", legOnlyInt: "Só Intune", legOnlyDef: "Só Defender", triple: "Intune∩Defender∩Entra",
    cardStockT: "Estoque ainda gerenciado", cardStockA: "Retire + Delete no Intune; onde há par, offboard MDE + limpar objeto Entra", cardStockN: (n) => `${n} exigem ação nas duas plataformas`,
    cardDefT: "Órfãos no Defender", cardDefA: "Validar stale por 'último update'; offboard MDE ou reinvestigar retire indevido", cardDefN: "Inclui nomes pessoais / não gerenciados",
    cardIntT: "Fora do Defender", cardIntA: "Focar nos desktop (Win/macOS) — checar onboarding MDE e connector", cardIntN: (m) => `${m} mobile — esperado (iOS/Android)`,
    cardEntraT: "Entra órfão", cardEntraA: "Objetos stale no diretório — avaliar disable/delete via Graph após janela de inatividade", cardEntraN: "Sem gestão Intune nem onboarding MDE",
    tabC1: "Estoque → excluir", tabC2: "Só Defender", tabC3: "Só Intune", tabC4: "Entra órfão",
    filter: "filtrar (host, serial, nome, UPN…)", platform: "Plataforma", all: "Todos",
    noRecords: "Nenhum registro", forFilter: (f) => ` para "${f}"`,
    footer: (c, i, d, e) => `Bases: ${c} CMDB · ${i} Intune · ${d} Defender · ${e} Entra. Divergências de hostname CMDB×Intune confirmam reaproveitamento de serial — cruzamento por serial prevalece. Processamento 100% local no navegador; nenhum dado sai da máquina.`,
    col: { host: "CMDB Host", serial: "Serial", status: "Status", sub: "SubStatus", iname: "Intune Name", os: "OS", indef: "Defender?", inentra: "Entra?", device: "Device", aad: "AAD ID", lastup: "Últ. update", onb: "Onboarding", health: "Saúde", lastchk: "Últ. check-in", comp: "Compliance", trust: "Trust", profile: "Profile", upn: "UPN", enabled: "Ativo", lastsign: "Últ. sign-in" },
  },
  en: {
    eyebrow: "Endpoint Reconciliation", h1: "Cross-base equity",
    xref: "Stock×Intune by Serial · Intune×Defender×Entra by AAD Object ID",
    dropTitle: "Drag the CSVs — or click to select",
    dropDrag: "Drop the files here",
    dropSub: "Auto-detects Intune, Defender, Entra and Stock by header. Re-uploading a file replaces it. 100% local processing — no data is sent.",
    baseUnknown: "unrecognized base", readFail: "read failed",
    emptyLine1a: "Load at least", emptyLine1b: "and", emptyLine1c: "to see the equity.",
    emptyLine2a: "Add", emptyLine2b: "and", emptyLine2c: "for the full reconciliation view.",
    mEquity: "Intune↔Defender equity", mEquitySub: "in both bases",
    mStock: "Stock to remove", mStockSub: "also in Defender",
    mOnlyDef: "Defender only", mOnlyDefSub: "orphans without Intune",
    mOnlyInt: "Intune only", mOnlyIntSub: (d, m) => `${d} desktop · ${m} mobile`,
    mEntra: "Entra orphan", mEntraSub: "no Intune, no Defender",
    coverage: "Intune ↔ Defender coverage (AAD Object ID)",
    objects: "objects", universe: "total universe",
    legBoth: "In both", legOnlyInt: "Intune only", legOnlyDef: "Defender only", triple: "Intune∩Defender∩Entra",
    cardStockT: "Stock still managed", cardStockA: "Retire + Delete in Intune; where paired, offboard MDE + clean Entra object", cardStockN: (n) => `${n} need action on both platforms`,
    cardDefT: "Defender orphans", cardDefA: "Validate stale by 'last update'; offboard MDE or reinvestigate wrong retire", cardDefN: "Includes personal / unmanaged names",
    cardIntT: "Outside Defender", cardIntA: "Focus on desktops (Win/macOS) — check MDE onboarding and connector", cardIntN: (m) => `${m} mobile — expected (iOS/Android)`,
    cardEntraT: "Entra orphan", cardEntraA: "Stale objects in the directory — assess disable/delete via Graph after inactivity window", cardEntraN: "No Intune management, no MDE onboarding",
    tabC1: "Stock → remove", tabC2: "Defender only", tabC3: "Intune only", tabC4: "Entra orphan",
    filter: "filter (host, serial, name, UPN…)", platform: "Platform", all: "All",
    noRecords: "No records", forFilter: (f) => ` for "${f}"`,
    footer: (c, i, d, e) => `Bases: ${c} CMDB · ${i} Intune · ${d} Defender · ${e} Entra. CMDB×Intune hostname mismatches confirm serial reuse — the serial match prevails. 100% local processing in the browser; no data leaves the machine.`,
    col: { host: "CMDB Host", serial: "Serial", status: "Status", sub: "SubStatus", iname: "Intune Name", os: "OS", indef: "Defender?", inentra: "Entra?", device: "Device", aad: "AAD ID", lastup: "Last update", onb: "Onboarding", health: "Health", lastchk: "Last check-in", comp: "Compliance", trust: "Trust", profile: "Profile", upn: "UPN", enabled: "Enabled", lastsign: "Last sign-in" },
  },
  es: {
    eyebrow: "Saneamiento de Endpoints", h1: "Equidad entre bases",
    xref: "Stock×Intune por Serial · Intune×Defender×Entra por AAD Object ID",
    dropTitle: "Arrastra los CSV — o haz clic para seleccionar",
    dropDrag: "Suelta los archivos aquí",
    dropSub: "Detecta automáticamente Intune, Defender, Entra y Stock por el encabezado. Reenviar un archivo lo reemplaza. Procesamiento 100% local — ningún dato se envía.",
    baseUnknown: "base no reconocida", readFail: "lectura fallida",
    emptyLine1a: "Carga al menos", emptyLine1b: "y", emptyLine1c: "para ver la equidad.",
    emptyLine2a: "Añade", emptyLine2b: "y", emptyLine2c: "para el escenario completo de saneamiento.",
    mEquity: "Equidad Intune↔Defender", mEquitySub: "en ambas bases",
    mStock: "Stock a excluir", mStockSub: "también en Defender",
    mOnlyDef: "Solo Defender", mOnlyDefSub: "huérfanos sin Intune",
    mOnlyInt: "Solo Intune", mOnlyIntSub: (d, m) => `${d} desktop · ${m} móvil`,
    mEntra: "Entra huérfano", mEntraSub: "sin Intune y sin Defender",
    coverage: "Cobertura Intune ↔ Defender (AAD Object ID)",
    objects: "objetos", universe: "universo total",
    legBoth: "En ambas", legOnlyInt: "Solo Intune", legOnlyDef: "Solo Defender", triple: "Intune∩Defender∩Entra",
    cardStockT: "Stock aún gestionado", cardStockA: "Retire + Delete en Intune; donde haya par, offboard MDE + limpiar objeto Entra", cardStockN: (n) => `${n} requieren acción en ambas plataformas`,
    cardDefT: "Huérfanos en Defender", cardDefA: "Validar stale por 'última actualización'; offboard MDE o reinvestigar retire indebido", cardDefN: "Incluye nombres personales / no gestionados",
    cardIntT: "Fuera de Defender", cardIntA: "Enfocar en desktops (Win/macOS) — revisar onboarding MDE y connector", cardIntN: (m) => `${m} móvil — esperado (iOS/Android)`,
    cardEntraT: "Entra huérfano", cardEntraA: "Objetos stale en el directorio — evaluar disable/delete vía Graph tras ventana de inactividad", cardEntraN: "Sin gestión Intune ni onboarding MDE",
    tabC1: "Stock → excluir", tabC2: "Solo Defender", tabC3: "Solo Intune", tabC4: "Entra huérfano",
    filter: "filtrar (host, serial, nombre, UPN…)", platform: "Plataforma", all: "Todos",
    noRecords: "Ningún registro", forFilter: (f) => ` para "${f}"`,
    footer: (c, i, d, e) => `Bases: ${c} CMDB · ${i} Intune · ${d} Defender · ${e} Entra. Divergencias de hostname CMDB×Intune confirman reutilización de serial — el cruce por serial prevalece. Procesamiento 100% local en el navegador; ningún dato sale de la máquina.`,
    col: { host: "CMDB Host", serial: "Serial", status: "Estado", sub: "SubEstado", iname: "Intune Name", os: "OS", indef: "Defender?", inentra: "Entra?", device: "Device", aad: "AAD ID", lastup: "Últ. actualización", onb: "Onboarding", health: "Salud", lastchk: "Últ. check-in", comp: "Compliance", trust: "Trust", profile: "Profile", upn: "UPN", enabled: "Activo", lastsign: "Últ. sign-in" },
  },
};

/* ---------- CSV parser (aspas, separador configurável) ---------- */
function parseCSV(text, delim) {
  const rows = [];
  let field = "", row = [], inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else {
      if (c === '"') inQ = true;
      else if (c === delim) { row.push(field); field = ""; }
      else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
      else if (c === "\r") { /* skip */ }
      else field += c;
    }
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function toObjects(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const nl = clean.indexOf("\n");
  const firstLine = nl === -1 ? clean : clean.slice(0, nl);
  const delim = (firstLine.split(";").length > firstLine.split(",").length) ? ";" : ",";
  const rows = parseCSV(clean, delim).filter((r) => r.some((c) => c.trim() !== ""));
  if (!rows.length) return { headers: [], data: [] };
  const headers = rows[0].map((h) => h.trim());
  const data = rows.slice(1).map((r) => {
    const o = {}; headers.forEach((h, i) => (o[h] = (r[i] ?? "").trim())); return o;
  });
  return { headers, data };
}

/* ---------- classificação da base pelo cabeçalho ---------- */
function classify(headers) {
  const s = new Set(headers.map((h) => h.trim()));
  const has = (...k) => k.every((x) => s.has(x));
  if (has("Serial number", "Azure AD Device ID", "Primary user UPN")) return "intune";
  if (has("AAD Device Id", "Onboarding Status", "Device ID")) return "defender";
  if (has("deviceId", "trustType", "profileType")) return "entra";
  if (has("Número de Série", "Status", "Hostname")) return "cmdb";
  return "desconhecido";
}

const n = (s) => (s || "").trim().toLowerCase();
function osIntune(o) { o = (o || "").toLowerCase(); if (o.includes("ios") || o.includes("ipad")) return "iOS"; if (o.includes("android")) return "Android"; if (o.includes("mac")) return "macOS"; if (o.includes("windows")) return "Windows"; return "Outro"; }
function osDef(o) { o = (o || "").toLowerCase(); if (o.includes("mac")) return "macOS"; if (o.includes("windows")) return "Windows"; if (o.includes("linux")) return "Linux"; return "Outro"; }
function osEntra(o) { o = (o || "").toLowerCase(); if (o.includes("ios") || o.includes("ipad")) return "iOS"; if (o.includes("android")) return "Android"; if (o.includes("mac")) return "macOS"; if (o.includes("windows")) return "Windows"; if (o.includes("linux")) return "Linux"; return "Outro"; }

/* ---------- núcleo do cruzamento ---------- */
function analyze(bases) {
  const intune = bases.intune, defender = bases.defender, entra = bases.entra, cmdb = bases.cmdb;

  const intuneBySerial = {}; intune.forEach((d) => { const k = n(d["Serial number"]); if (k) intuneBySerial[k] = d; });
  const intuneAAD = new Set(), defAAD = new Set(), entraAAD = new Set();
  const intuneAADmap = {}, defAADmap = {}, entraAADmap = {};
  intune.forEach((d) => { const k = n(d["Azure AD Device ID"]); if (k) { intuneAAD.add(k); intuneAADmap[k] = d; } });
  defender.forEach((d) => { const k = n(d["AAD Device Id"]); if (k) { defAAD.add(k); defAADmap[k] = d; } });
  entra.forEach((d) => { const k = n(d["deviceId"]); if (k) { entraAAD.add(k); entraAADmap[k] = d; } });

  const baixa = ["em estoque", "fora de uso"];
  const subBaixa = ["descartar", "furtado", "devolução pendente", "roubado"];

  // C1: estoque/baixa ainda no Intune (por serial)
  const c1 = [];
  cmdb.forEach((e) => {
    const serial = n(e["Número de Série"]); if (!serial) return;
    const st = n(e["Status"]), sub = n(e["SubStatus"]);
    if (baixa.includes(st) || subBaixa.includes(sub)) {
      const d = intuneBySerial[serial];
      if (d) {
        const aad = n(d["Azure AD Device ID"]);
        c1.push({ host: e["Hostname"], serial: e["Número de Série"], status: e["Status"], sub: e["SubStatus"],
          iname: d["Device name"], os: osIntune(d["OS"]),
          indef: defAAD.has(aad), inentra: entraAAD.has(aad), aad });
      }
    }
  });

  // C2: só Defender (sem Intune)
  const c2 = [];
  defAAD.forEach((k) => { if (!intuneAAD.has(k)) { const d = defAADmap[k];
    c2.push({ name: d["Device Name"], os: osDef(d["OS Platform"]), aad: k, defid: d["Device ID"],
      last: d["Last device update"], onb: d["Onboarding Status"], health: d["Health Status"], inentra: entraAAD.has(k) }); } });

  // C3: só Intune (sem Defender)
  const c3 = [];
  intuneAAD.forEach((k) => { if (!defAAD.has(k)) { const d = intuneAADmap[k];
    c3.push({ name: d["Device name"], os: osIntune(d["OS"]), aad: k, serial: d["Serial number"],
      last: d["Last check-in"], comp: d["Compliance"], own: d["Ownership"], inentra: entraAAD.has(k) }); } });

  // C4: Entra órfão — registrado no Entra mas ausente de Intune E Defender
  const c4 = [];
  entraAAD.forEach((k) => { if (!intuneAAD.has(k) && !defAAD.has(k)) { const d = entraAADmap[k];
    c4.push({ name: d["displayName"], os: osEntra(d["operatingSystem"]), aad: k, trust: d["trustType"],
      profile: d["profileType"], upn: d["upnName"], enabled: d["accountEnabled"],
      last: d["approximateLastSignInDateTime"], mdm: d["mdm"] }); } });

  const both = new Set([...intuneAAD].filter((k) => defAAD.has(k)));
  const triple = new Set([...both].filter((k) => entraAAD.has(k)));

  const cnt = (arr, key) => arr.reduce((m, x) => { m[x[key]] = (m[x[key]] || 0) + 1; return m; }, {});

  return {
    totals: { cmdb: cmdb.length, intune: intune.length, defender: defender.length, entra: entra.length,
      both: both.size, triple: triple.size },
    c1, c2, c3, c4,
    c1_os: cnt(c1, "os"), c2_os: cnt(c2, "os"), c3_os: cnt(c3, "os"), c4_os: cnt(c4, "os"),
    universe: new Set([...intuneAAD, ...defAAD, ...entraAAD]).size,
  };
}

/* ---------- UI ---------- */
function Metric({ label, value, sub, accent }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 10, padding: "16px 18px", flex: 1, minWidth: 150 }}>
      <div style={{ fontSize: 11, letterSpacing: 0.6, textTransform: "uppercase", color: C.dim, fontWeight: 600 }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 700, color: accent || C.ink, marginTop: 6, fontVariantNumeric: "tabular-nums", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: C.faint, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}
function OsChips({ obj }) {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
      {entries.map(([os, cnt]) => (
        <span key={os} style={{ fontSize: 11, fontWeight: 600, color: C.ink, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 20, padding: "3px 10px", display: "inline-flex", alignItems: "center", gap: 6 }}>
          <span style={{ width: 7, height: 7, borderRadius: "50%", background: OS_COLOR[os] || C.faint }} />
          {os} <span style={{ color: C.dim, fontVariantNumeric: "tabular-nums" }}>{cnt}</span>
        </span>
      ))}
    </div>
  );
}
function Legend({ c, t }) {
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><span style={{ width: 9, height: 9, borderRadius: 2, background: c }} />{t}</span>;
}
function ActionCard({ color, count, title, action, osObj, note }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderLeft: `3px solid ${color}`, borderRadius: 10, padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <span style={{ fontSize: 13.5, fontWeight: 700 }}>{title}</span>
        <span style={{ fontSize: 22, fontWeight: 700, color, fontVariantNumeric: "tabular-nums" }}>{count}</span>
      </div>
      <div style={{ fontSize: 12.5, color: C.dim, marginTop: 8, lineHeight: 1.5 }}>{action}</div>
      <OsChips obj={osObj} />
      <div style={{ fontSize: 11.5, color: C.faint, marginTop: 10, fontStyle: "italic" }}>{note}</div>
    </div>
  );
}

const TAB_DEFS = (t) => [
  { id: "c1", label: t.tabC1, color: C.crit },
  { id: "c2", label: t.tabC2, color: C.warn },
  { id: "c3", label: t.tabC3, color: C.info },
  { id: "c4", label: t.tabC4, color: C.violet },
];

function Table({ tab, rows, filter, osFilter, t }) {
  const co = t.col;
  const cols = {
    c1: [
      { k: "host", h: co.host }, { k: "serial", h: co.serial, mono: true }, { k: "status", h: co.status },
      { k: "sub", h: co.sub }, { k: "iname", h: co.iname }, { k: "os", h: co.os },
      { k: "indef", h: co.indef, r: (v) => (v ? "SIM" : "—") }, { k: "inentra", h: co.inentra, r: (v) => (v ? "SIM" : "—") },
    ],
    c2: [
      { k: "name", h: co.device }, { k: "os", h: co.os }, { k: "aad", h: co.aad, mono: true },
      { k: "last", h: co.lastup, r: (v) => (v || "").slice(0, 10) }, { k: "onb", h: co.onb },
      { k: "health", h: co.health }, { k: "inentra", h: co.inentra, r: (v) => (v ? "SIM" : "—") },
    ],
    c3: [
      { k: "name", h: co.device }, { k: "os", h: co.os }, { k: "serial", h: co.serial, mono: true },
      { k: "aad", h: co.aad, mono: true }, { k: "last", h: co.lastchk, r: (v) => (v || "").slice(0, 10) },
      { k: "comp", h: co.comp }, { k: "inentra", h: co.inentra, r: (v) => (v ? "SIM" : "—") },
    ],
    c4: [
      { k: "name", h: co.device }, { k: "os", h: co.os }, { k: "trust", h: co.trust }, { k: "profile", h: co.profile },
      { k: "upn", h: co.upn }, { k: "enabled", h: co.enabled }, { k: "last", h: co.lastsign, r: (v) => (v || "").slice(0, 10) },
    ],
  }[tab];
  const f = rows.filter((r) => {
    if (osFilter && osFilter !== "__all__" && r.os !== osFilter) return false;
    if (filter && !Object.values(r).some((v) => String(v).toLowerCase().includes(filter.toLowerCase()))) return false;
    return true;
  });
  return (
    <div style={{ overflowX: "auto", overflowY: "auto", border: `1px solid ${C.line}`, borderRadius: 10, maxHeight: "min(70vh, 720px)" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
        <thead>
          <tr>{cols.map((c) => (
            <th key={c.k} style={{ textAlign: "left", padding: "10px 12px", color: C.dim, fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.4, borderBottom: `1px solid ${C.line}`, background: C.panel2, whiteSpace: "nowrap", position: "sticky", top: 0 }}>{c.h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {f.map((r, i) => (
            <tr key={i} style={{ borderBottom: `1px solid ${C.line}` }}>
              {cols.map((c) => {
                const raw = r[c.k]; const val = c.r ? c.r(raw) : raw;
                let color = C.ink;
                if (c.k === "indef") color = raw ? C.crit : C.faint;
                if (c.k === "inentra") color = raw ? C.violet : C.faint;
                if (c.k === "os") color = OS_COLOR[raw] || C.ink;
                if (c.k === "comp") color = raw === "Compliant" ? C.ok : C.warn;
                if (c.k === "enabled") color = String(raw).toLowerCase() === "true" ? C.ok : C.faint;
                return (
                  <td key={c.k} style={{ padding: "9px 12px", color, whiteSpace: "nowrap", fontFamily: c.mono ? "ui-monospace, monospace" : "inherit", fontSize: c.mono ? 11.5 : 12.5, fontVariantNumeric: "tabular-nums" }}>{val || "—"}</td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {f.length === 0 && <div style={{ padding: 24, textAlign: "center", color: C.faint, fontSize: 13 }}>{t.noRecords}{filter ? t.forFilter(filter) : ""}.</div>}
    </div>
  );
}

const BASE_META = {
  intune: { label: "Intune", color: C.info }, defender: { label: "Defender", color: C.warn },
  entra: { label: "Entra", color: C.violet }, cmdb: { label: "Estoque (CMDB)", color: C.cyan },
};

export default function Dashboard({ lang = "pt" }) {
  const t = L[lang] || L.pt;
  const [bases, setBases] = useState({ intune: [], defender: [], entra: [], cmdb: [] });
  const [loaded, setLoaded] = useState({}); // filename -> {type, count}
  const [tab, setTab] = useState("c1");
  const [filter, setFilter] = useState("");
  const [osFilter, setOsFilter] = useState("__all__");
  const [drag, setDrag] = useState(false);
  const [errors, setErrors] = useState([]);
  const inputRef = useRef(null);

  const ingest = useCallback((fileList) => {
    const files = Array.from(fileList).filter((f) => /\.csv$/i.test(f.name));
    if (!files.length) return;
    const newErrors = [];
    Promise.all(files.map((file) => new Promise((res) => {
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const { headers, data } = toObjects(reader.result);
          res({ name: file.name, type: classify(headers), data });
        } catch (e) { res({ name: file.name, type: "erro", data: [], msg: e.message }); }
      };
      reader.onerror = () => res({ name: file.name, type: "erro", data: [], msg: t.readFail });
      reader.readAsText(file, "UTF-8");
    }))).then((results) => {
      setLoaded((prevLoaded) => {
        setBases((prev) => {
          // reconstrói cada base do zero a partir do mapa de arquivos atualizado
          const fileMap = { ...prevLoaded };
          results.forEach((r) => {
            if (r.type === "desconhecido" || r.type === "erro") {
              newErrors.push(`${r.name}: ${r.type === "erro" ? r.msg : t.baseUnknown}`);
              return;
            }
            fileMap[r.name] = { type: r.type, count: r.data.length, data: r.data };
          });
          const next = { intune: [], defender: [], entra: [], cmdb: [] };
          Object.values(fileMap).forEach((f) => { if (next[f.type]) next[f.type].push(...f.data); });
          return next;
        });
        const nl = { ...prevLoaded };
        results.forEach((r) => {
          if (r.type !== "desconhecido" && r.type !== "erro") nl[r.name] = { type: r.type, count: r.data.length, data: r.data };
        });
        return nl;
      });
      setErrors(newErrors);
    });
  }, [t]);

  const onDrop = useCallback((e) => { e.preventDefault(); setDrag(false); ingest(e.dataTransfer.files); }, [ingest]);

  const hasData = bases.intune.length || bases.defender.length || bases.entra.length || bases.cmdb.length;
  const A = useMemo(() => (hasData ? analyze(bases) : null), [bases, hasData]);
  const loadedList = Object.entries(loaded);

  return (
    <div style={{ background: C.bg, color: C.ink, minHeight: "100vh", fontFamily: "'Inter', system-ui, sans-serif", padding: "28px clamp(16px, 3vw, 40px)" }}>
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>

        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div style={{ fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: C.info, fontWeight: 700 }}>{t.eyebrow}</div>
            <h1 style={{ fontSize: 26, fontWeight: 700, margin: "4px 0 0", letterSpacing: -0.5 }}>{t.h1}</h1>
          </div>
          <div style={{ fontSize: 12, color: C.faint, textAlign: "right" }}>{t.xref}</div>
        </div>

        {/* Dropzone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          style={{ marginTop: 20, border: `1.5px dashed ${drag ? C.info : C.line}`, background: drag ? "rgba(59,130,246,0.06)" : C.panel, borderRadius: 12, padding: "22px 20px", cursor: "pointer", transition: "all .15s" }}
        >
          <input ref={inputRef} type="file" accept=".csv" multiple
            style={{ display: "none" }} onChange={(e) => ingest(e.target.files)} />
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>{drag ? t.dropDrag : t.dropTitle}</div>
              <div style={{ fontSize: 12, color: C.dim, marginTop: 4 }}>{t.dropSub}</div>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["intune", "defender", "entra", "cmdb"].map((bk) => (
                <span key={bk} style={{ fontSize: 11, fontWeight: 600, padding: "4px 10px", borderRadius: 6, border: `1px solid ${C.line}`, color: bases[bk].length ? "#0d1117" : C.dim, background: bases[bk].length ? BASE_META[bk].color : C.panel2 }}>
                  {BASE_META[bk].label} {bases[bk].length ? `· ${bases[bk].length}` : ""}
                </span>
              ))}
            </div>
          </div>
          {loadedList.length > 0 && (
            <div style={{ marginTop: 14, display: "flex", flexWrap: "wrap", gap: 6 }}>
              {loadedList.map(([name, info]) => (
                <span key={name} style={{ fontSize: 11, color: C.dim, background: C.panel2, border: `1px solid ${C.line}`, borderRadius: 6, padding: "3px 8px", display: "inline-flex", gap: 6, alignItems: "center" }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: BASE_META[info.type]?.color || C.faint }} />
                  {name} <span style={{ color: C.faint }}>{info.count}</span>
                </span>
              ))}
            </div>
          )}
          {errors.length > 0 && (
            <div style={{ marginTop: 10, fontSize: 12, color: C.crit }}>
              {errors.map((e, i) => <div key={i}>⚠ {e}</div>)}
            </div>
          )}
        </div>

        {!hasData && (
          <div style={{ marginTop: 40, textAlign: "center", color: C.faint, fontSize: 14, lineHeight: 1.7 }}>
            {t.emptyLine1a} <b style={{ color: C.dim }}>Intune</b> {t.emptyLine1b} <b style={{ color: C.dim }}>Defender</b> {t.emptyLine1c}<br />
            {t.emptyLine2a} <b style={{ color: C.dim }}>Entra</b> {t.emptyLine2b} <b style={{ color: C.dim }}>Estoque</b> {t.emptyLine2c}
          </div>
        )}

        {A && (
          <>
            {(() => {
              const denom = A.totals.both + A.c2.length + A.c3.length;
              const equity = denom ? (A.totals.both / denom) * 100 : 0;
              const c1Def = A.c1.filter((r) => r.indef).length;
              const c3Desktop = A.c3.filter((r) => r.os === "Windows" || r.os === "macOS").length;
              const c3Mobile = A.c3.length - c3Desktop;
              return (
                <>
                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap", margin: "22px 0" }}>
                    <Metric label={t.mEquity} value={`${equity.toFixed(1)}%`} sub={`${A.totals.both} ${t.mEquitySub}`} accent={equity > 90 ? C.ok : C.warn} />
                    <Metric label={t.mStock} value={A.c1.length} sub={`${c1Def} ${t.mStockSub}`} accent={C.crit} />
                    <Metric label={t.mOnlyDef} value={A.c2.length} sub={t.mOnlyDefSub} accent={C.warn} />
                    <Metric label={t.mOnlyInt} value={A.c3.length} sub={t.mOnlyIntSub(c3Desktop, c3Mobile)} accent={C.info} />
                    <Metric label={t.mEntra} value={A.c4.length} sub={t.mEntraSub} accent={C.violet} />
                  </div>

                  <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 10, padding: 18, marginBottom: 20 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>{t.coverage}</span>
                      <span style={{ fontSize: 12, color: C.dim }}>{denom} {t.objects} · {t.universe} {A.universe}</span>
                    </div>
                    <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", background: C.line }}>
                      {[{ v: A.totals.both, c: C.ok }, { v: A.c3.length, c: C.info }, { v: A.c2.length, c: C.warn }].map((s, i) => (
                        <div key={i} style={{ width: `${denom ? (s.v / denom) * 100 : 0}%`, background: s.c }} />
                      ))}
                    </div>
                    <div style={{ display: "flex", gap: 18, marginTop: 12, fontSize: 12, color: C.dim, flexWrap: "wrap" }}>
                      <Legend c={C.ok} t={`${t.legBoth} (${A.totals.both})`} />
                      <Legend c={C.info} t={`${t.legOnlyInt} (${A.c3.length})`} />
                      <Legend c={C.warn} t={`${t.legOnlyDef} (${A.c2.length})`} />
                      <span style={{ marginLeft: "auto", color: C.faint }}>{t.triple}: <b style={{ color: C.violet }}>{A.totals.triple}</b></span>
                    </div>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 12, marginBottom: 24 }}>
                    <ActionCard color={C.crit} count={A.c1.length} title={t.cardStockT}
                      action={t.cardStockA} osObj={A.c1_os}
                      note={t.cardStockN(c1Def)} />
                    <ActionCard color={C.warn} count={A.c2.length} title={t.cardDefT}
                      action={t.cardDefA} osObj={A.c2_os}
                      note={t.cardDefN} />
                    <ActionCard color={C.info} count={A.c3.length} title={t.cardIntT}
                      action={t.cardIntA} osObj={A.c3_os}
                      note={t.cardIntN(c3Mobile)} />
                    <ActionCard color={C.violet} count={A.c4.length} title={t.cardEntraT}
                      action={t.cardEntraA} osObj={A.c4_os}
                      note={t.cardEntraN} />
                  </div>
                </>
              );
            })()}

            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
              {TAB_DEFS(t).map((x) => (
                <button key={x.id} onClick={() => { setTab(x.id); setFilter(""); setOsFilter("__all__"); }}
                  style={{ background: tab === x.id ? x.color : C.panel, color: tab === x.id ? "#0d1117" : C.dim, border: `1px solid ${tab === x.id ? x.color : C.line}`, borderRadius: 8, padding: "8px 14px", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}>
                  {x.label} <span style={{ opacity: 0.75 }}>· {A[x.id].length}</span>
                </button>
              ))}
              <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t.filter}
                style={{ marginLeft: "auto", background: C.panel, border: `1px solid ${C.line}`, borderRadius: 8, padding: "8px 12px", color: C.ink, fontSize: 12.5, minWidth: 220, outline: "none" }} />
            </div>

            {/* Filtro por plataforma (OS) — derivado da aba atual */}
            {(() => {
              const counts = A[tab].reduce((m, r) => { m[r.os] = (m[r.os] || 0) + 1; return m; }, {});
              const order = ["Windows", "macOS", "iOS", "Android", "Linux", "Outro"];
              const present = order.filter((o) => counts[o]).concat(Object.keys(counts).filter((o) => !order.includes(o)));
              if (present.length <= 1) return null;
              const chips = [["__all__", A[tab].length]].concat(present.map((o) => [o, counts[o]]));
              return (
                <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: C.faint, fontWeight: 600, marginRight: 2 }}>{t.platform}</span>
                  {chips.map(([os, cnt]) => {
                    const active = osFilter === os;
                    const dot = os === "__all__" ? null : (OS_COLOR[os] || C.faint);
                    const label = os === "__all__" ? t.all : os;
                    return (
                      <button key={os} onClick={() => setOsFilter(os)}
                        style={{ display: "inline-flex", alignItems: "center", gap: 6, background: active ? C.panel2 : C.panel, color: active ? C.ink : C.dim, border: `1px solid ${active ? (dot || C.info) : C.line}`, borderRadius: 20, padding: "4px 11px", fontSize: 11.5, fontWeight: 600, cursor: "pointer" }}>
                        {dot && <span style={{ width: 7, height: 7, borderRadius: "50%", background: dot }} />}
                        {label} <span style={{ color: C.faint, fontVariantNumeric: "tabular-nums" }}>{cnt}</span>
                      </button>
                    );
                  })}
                </div>
              );
            })()}

            <Table tab={tab} rows={A[tab]} filter={filter} osFilter={osFilter} t={t} />

            <div style={{ marginTop: 20, fontSize: 11.5, color: C.faint, lineHeight: 1.6 }}>
              {t.footer(A.totals.cmdb, A.totals.intune, A.totals.defender, A.totals.entra)}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
