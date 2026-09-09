const els = {
  form: document.getElementById("inspect-form"),
  targetURL: document.getElementById("target-url"),
  useHead: document.getElementById("use-head"),
  stripKnown: document.getElementById("strip-known"),
  sampleURL: document.getElementById("sample-url"),
  clearAll: document.getElementById("clear-all"),
  summary: document.getElementById("summary"),
  chain: document.getElementById("redirect-chain"),
  rawHeaders: document.getElementById("raw-headers"),
  analyzeHeaders: document.getElementById("analyze-headers"),
  headerFindings: document.getElementById("header-findings"),
  urlParts: document.getElementById("url-parts"),
  curlCommand: document.getElementById("curl-command"),
  copyCommand: document.getElementById("copy-command"),
  copyCleanURL: document.getElementById("copy-clean-url"),
  batchInput: document.getElementById("batch-input"),
  runBatch: document.getElementById("run-batch"),
  batchResults: document.getElementById("batch-results"),
  exportJSON: document.getElementById("export-json"),
  exportCSV: document.getElementById("export-csv"),
  history: document.getElementById("history"),
  clearHistory: document.getElementById("clear-history"),
  healthLabel: document.getElementById("health-label"),
  healthScore: document.getElementById("health-score"),
  tlsFindings: document.getElementById("tls-findings"),
  tlsBadge: document.getElementById("tls-badge"),
};

const historyKey = "redirect_inspector_history_v1";
const trackingParams = new Set([
  "fbclid", "gclid", "gbraid", "wbraid", "yclid", "mc_cid", "mc_eid", "igshid", "msclkid",
  "pk_campaign", "pk_kwd", "sc_campaign", "spm", "vero_id", "oly_enc_id", "oly_anon_id"
]);
const trackingPrefixes = ["utm_", "ga_", "hsa_", "wt_", "mkt_tok"];
const securityHeaders = [
  { key: "strict-transport-security", label: "HSTS", weight: 18, hint: "Erzwingt HTTPS fuer Folgeaufrufe." },
  { key: "content-security-policy", label: "Content-Security-Policy", weight: 18, hint: "Reduziert Script- und Injection-Risiken." },
  { key: "x-frame-options", label: "X-Frame-Options", weight: 10, hint: "Schuetzt gegen Clickjacking." },
  { key: "referrer-policy", label: "Referrer-Policy", weight: 10, hint: "Begrenzt weitergegebene Herkunftsdaten." },
  { key: "permissions-policy", label: "Permissions-Policy", weight: 9, hint: "Schraenkt Browser-Funktionen ein." },
  { key: "x-content-type-options", label: "X-Content-Type-Options", weight: 7, hint: "Verhindert MIME-Sniffing." },
  { key: "cross-origin-opener-policy", label: "COOP", weight: 7, hint: "Isoliert Browsing-Kontexte." },
  { key: "cross-origin-resource-policy", label: "CORP", weight: 6, hint: "Steuert Cross-Origin-Resource-Zugriff." },
  { key: "cache-control", label: "Cache-Control", weight: 5, hint: "Zeigt Cache-Verhalten an." },
  { key: "server", label: "Server-Banner", weight: 0, hint: "Kann Stack-Details verraten." },
];

let lastResult = null;
let history = loadHistory();

init();

function init() {
  renderEmpty();
  renderHistory();
  els.form.addEventListener("submit", onInspect);
  els.sampleURL.addEventListener("click", () => {
    els.targetURL.value = "https://example.com/?utm_source=newsletter&utm_medium=email&ref=hub#section";
    inspectCurrent();
  });
  els.clearAll.addEventListener("click", clearAll);
  els.analyzeHeaders.addEventListener("click", () => renderHeaderFindings(parseRawHeaders(els.rawHeaders.value)));
  els.copyCommand.addEventListener("click", () => copyText(els.curlCommand.textContent));
  els.copyCleanURL.addEventListener("click", () => lastResult?.cleanURL && copyText(lastResult.cleanURL));
  els.runBatch.addEventListener("click", runBatch);
  els.exportJSON.addEventListener("click", () => download("redirect-inspector-history.json", JSON.stringify(history, null, 2), "application/json"));
  els.exportCSV.addEventListener("click", () => download("redirect-inspector-history.csv", toCSV(history), "text/csv"));
  els.clearHistory.addEventListener("click", () => {
    history = [];
    saveHistory();
    renderHistory();
  });
}

async function onInspect(event) {
  event.preventDefault();
  await inspectCurrent();
}

async function inspectCurrent() {
  const raw = els.targetURL.value.trim();
  const analysis = analyzeURL(raw);
  if (analysis.error) {
    renderError(analysis.error);
    return;
  }
  setHealth("Prueft", "...");
  renderURLParts(analysis);
  updateCommand(analysis.normalized);
  renderSummary(analysis, null);
  renderChain([{ url: analysis.normalized, status: "Analyse", note: "Hub-Backend prueft Redirects und Header." }]);

  const live = await inspectWithHubFallback(analysis.normalized);
  const headers = parseHeadersObject(live.headers || {});
  const score = scoreHeaders(headers, analysis.parsed.protocol === "https:");
  const tls = lastTLSInfo(live);
  lastResult = { ...analysis, live, headers, securityScore: score.score, tls };
  renderSummary(analysis, live);
  renderChain(buildChain(analysis, live));
  renderHeaderFindings(headers, score);
  renderTLSFindings(tls, analysis.protocol === "https");
  setHealth(score.label, score.score);
  els.copyCleanURL.disabled = !analysis.cleanURL;
  addHistory(lastResult);
}

function analyzeURL(raw) {
  let parsed;
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`;
    parsed = new URL(withScheme);
  } catch (_) {
    return { error: "Die URL ist nicht gueltig." };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { error: "Nur HTTP- und HTTPS-URLs koennen geprueft werden." };
  }
  const params = [...parsed.searchParams.entries()].map(([key, value]) => ({
    key,
    value,
    tracking: isTrackingParam(key),
  }));
  const clean = new URL(parsed.href);
  for (const item of params) {
    if (item.tracking && els.stripKnown.checked) clean.searchParams.delete(item.key);
  }
  const cleanURL = clean.href;
  return {
    parsed,
    normalized: parsed.href,
    cleanURL,
    host: parsed.hostname,
    protocol: parsed.protocol.replace(":", ""),
    path: parsed.pathname || "/",
    paramCount: params.length,
    trackingCount: params.filter((item) => item.tracking).length,
    params,
    hash: parsed.hash,
  };
}

function isTrackingParam(key) {
  const lower = String(key).toLowerCase();
  return trackingParams.has(lower) || trackingPrefixes.some((prefix) => lower.startsWith(prefix));
}

async function inspectWithHubFallback(url) {
  try {
    const response = await fetch("/api/http/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, method: els.useHead.checked ? "HEAD" : "GET", follow_redirects: true, max_redirects: 10, include_headers: true, include_tls: true }),
    });
    if (!response.ok) throw new Error(`Hub HTTP-Inspect ${response.status}`);
    const payload = await response.json();
    const lastHop = [...(payload.hops || [])].pop();
    return {
      ok: lastHop ? lastHop.status >= 200 && lastHop.status < 400 : false,
      method: lastHop?.method || (els.useHead.checked ? "HEAD" : "GET"),
      status: lastHop?.status || "Hub",
      statusText: lastHop?.status_text || payload.error || "",
      finalURL: payload.final_url || url,
      redirected: Boolean(payload.redirected),
      latencyMs: payload.latency_ms || 0,
      error: payload.error || "",
      headers: lastHop?.headers || {},
      hops: payload.hops || [],
      source: "hub",
    };
  } catch (error) {
    const live = await inspectLive(url);
    live.source = "browser";
    return live;
  }
}
async function inspectLive(url) {
  const started = performance.now();
  const methods = els.useHead.checked ? ["HEAD", "GET"] : ["GET"];
  for (const method of methods) {
    try {
      const response = await fetch(url, {
        method,
        redirect: "follow",
        cache: "no-store",
        mode: "cors",
      });
      const headers = {};
      response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
      return {
        ok: response.ok,
        method,
        status: response.status,
        statusText: response.statusText,
        finalURL: response.url,
        redirected: response.redirected,
        latencyMs: Math.round(performance.now() - started),
        headers,
      };
    } catch (error) {
      if (method === methods[methods.length - 1]) {
        return {
          ok: false,
          method,
          status: "CORS/Netzwerk",
          statusText: "Browser konnte die Antwort nicht auslesen",
          finalURL: url,
          redirected: false,
          latencyMs: Math.round(performance.now() - started),
          error: error.message,
          headers: {},
        };
      }
    }
  }
}

function buildChain(analysis, live) {
  const rows = [{ url: analysis.normalized, status: "Start", note: analysis.host }];
  if (Array.isArray(live.hops) && live.hops.length) {
    for (const hop of live.hops) {
      const noteParts = [];
      if (hop.location) noteParts.push(`Location: ${hop.location}`);
      if (hop.tls_expires_at) noteParts.push(`TLS bis: ${new Date(hop.tls_expires_at).toLocaleDateString("de-DE")}`);
      rows.push({ url: hop.url, status: `${hop.method || "HTTP"} ${hop.status}`, note: noteParts.join(" | ") || hop.status_text || "" });
    }
  } else if (live.finalURL && live.finalURL !== analysis.normalized) {
    rows.push({ url: live.finalURL, status: live.status, note: "Finale URL nach Browser-Follow" });
  } else {
    rows.push({ url: live.finalURL || analysis.normalized, status: live.status, note: live.redirected ? "Redirect erkannt" : "Kein sichtbarer Redirect" });
  }
  if (live.error) {
    const prefix = live.source === "browser" ? "CORS blockiert Details" : "Hinweis";
    rows.push({ url: analysis.normalized, status: "Hinweis", note: `${prefix}: ${live.error}` });
  }
  return rows;
}

function parseRawHeaders(raw) {
  const blocks = String(raw || "").split(/\r?\n\s*\r?\n/).filter(Boolean);
  const headers = {};
  const statuses = [];
  for (const block of blocks) {
    for (const line of block.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (/^HTTP\//i.test(trimmed)) {
        statuses.push(trimmed);
        continue;
      }
      const index = trimmed.indexOf(":");
      if (index < 1) continue;
      const key = trimmed.slice(0, index).trim().toLowerCase();
      const value = trimmed.slice(index + 1).trim();
      headers[key] = headers[key] ? `${headers[key]}, ${value}` : value;
    }
  }
  headers["_statuses"] = statuses.join(" | ");
  return headers;
}

function parseHeadersObject(headers) {
  return Object.fromEntries(Object.entries(headers || {}).map(([key, value]) => [key.toLowerCase(), String(value)]));
}

function lastTLSInfo(live) {
  const hops = Array.isArray(live?.hops) ? live.hops : [];
  for (let i = hops.length - 1; i >= 0; i -= 1) {
    if (hops[i]?.tls) return hops[i].tls;
  }
  return null;
}

function scoreHeaders(headers, isHTTPS) {
  let score = isHTTPS ? 10 : 0;
  for (const item of securityHeaders) {
    if (item.weight > 0 && headers[item.key]) score += item.weight;
  }
  score = Math.min(100, score);
  const label = score >= 75 ? "Gut" : score >= 45 ? "Mittel" : "Schwach";
  return { score, label };
}

function renderSummary(analysis, live) {
  const finalURL = live?.finalURL || "-";
  const changed = finalURL !== "-" && finalURL !== analysis.normalized;
  els.summary.innerHTML = [
    metric("Host", analysis.host),
    metric("Schema", analysis.protocol.toUpperCase()),
    metric("Parameter", `${analysis.paramCount} gesamt, ${analysis.trackingCount} Tracking`),
    metric("Status", live ? `${live.status} ${live.statusText || ""}` : "Noch nicht geprueft"),
    metric("Finale URL", finalURL),
    metric("Redirect", live ? (changed || live.redirected ? "Ja" : "Nein/verdeckt") : "-"),
  ].join("");
}

function renderURLParts(analysis) {
  const rows = [
    part("Origin", analysis.parsed.origin),
    part("Pfad", analysis.path),
    part("Hash", analysis.hash || "-"),
    part("Bereinigte URL", analysis.cleanURL),
  ];
  if (analysis.params.length) {
    rows.push(part("Parameter", analysis.params.map((p) => `${p.key}=${p.value}${p.tracking ? " [Tracking]" : ""}`).join("\n")));
  }
  els.urlParts.innerHTML = rows.join("");
}

function renderChain(items) {
  els.chain.innerHTML = items.map((item, index) => `<li><strong>${index + 1}. ${escapeHTML(String(item.status))}</strong><br>${escapeHTML(item.url)}<br><small>${escapeHTML(item.note || "")}</small></li>`).join("");
}

function renderHeaderFindings(headers, scored) {
  const parsed = headers || parseRawHeaders(els.rawHeaders.value);
  const score = scored || scoreHeaders(parsed, els.targetURL.value.trim().startsWith("https://"));
  const rows = [];
  if (parsed._statuses) rows.push(finding("ok", "Statuskette", parsed._statuses));
  for (const item of securityHeaders) {
    const value = parsed[item.key];
    if (value) {
      const tone = item.key === "server" ? "warn" : "ok";
      rows.push(finding(tone, item.label, value));
    } else if (item.weight > 0) {
      rows.push(finding("bad", `${item.label} fehlt`, item.hint));
    }
  }
  if (!Object.keys(parsed).filter((key) => !key.startsWith("_")).length) {
    rows.push(finding("warn", "Keine Header", "Live-Header sind wegen CORS oft nicht sichtbar. Fuege Header aus curl oder PowerShell ein."));
  }
  els.headerFindings.innerHTML = rows.join("");
  setHealth(score.label, score.score);
}

function renderTLSFindings(tls, isHTTPS) {
  if (!isHTTPS) {
    els.tlsFindings.innerHTML = "<p>Kein TLS: URL nutzt HTTP.</p>";
    els.tlsBadge.textContent = "-";
    els.tlsBadge.className = "badge";
    return;
  }
  if (!tls) {
    els.tlsFindings.innerHTML = "<p>Keine TLS-Daten. Die Hub-HTTP-Inspect-API war nicht erreichbar (Browser-CORS-Fallback liefert keine Zertifikatsdetails).</p>";
    els.tlsBadge.textContent = "?";
    els.tlsBadge.className = "badge";
    return;
  }
  const rows = [];
  const notAfter = tls.not_after ? new Date(tls.not_after) : null;
  const notBefore = tls.not_before ? new Date(tls.not_before) : null;

  if (tls.expired) {
    rows.push(finding("bad", "Zertifikat abgelaufen", notAfter ? `Ablauf: ${notAfter.toLocaleString("de-DE")}` : "Kein Ablaufdatum verfuegbar."));
  } else if (tls.expiring_soon) {
    rows.push(finding("warn", `Laeuft in ${tls.days_remaining} Tag(en) ab`, notAfter ? `Ablauf: ${notAfter.toLocaleString("de-DE")}` : ""));
  } else if (notAfter) {
    rows.push(finding("ok", `Laufzeit: ${tls.days_remaining} Tage verbleibend`, `Ablauf: ${notAfter.toLocaleString("de-DE")}`));
  }
  if (notBefore) rows.push(finding("ok", "Gueltig ab", notBefore.toLocaleString("de-DE")));
  rows.push(finding(tls.hostname_ok ? "ok" : "bad", "Hostname-Pruefung", tls.hostname_ok ? "Zertifikat passt zum Hostnamen." : "Zertifikat deckt den Hostnamen nicht ab."));
  rows.push(finding(tls.self_signed ? "warn" : "ok", "Aussteller", `${tls.issuer || "unbekannt"}${tls.self_signed ? " (selbstsigniert)" : ""}`));
  rows.push(finding("ok", "Subject", tls.subject || "-"));
  if (tls.dns_names?.length) rows.push(finding("ok", "Alternative Namen (SAN)", tls.dns_names.join(", ")));
  rows.push(finding(tls.weak_protocol ? "bad" : "ok", "Protokoll", tls.version || "unbekannt"));
  rows.push(finding("ok", "Cipher Suite", tls.cipher_suite || "unbekannt"));
  rows.push(finding("ok", "Signatur / Schluessel", `${tls.signature_algorithm || "-"} / ${tls.key_algorithm || "-"}`));
  if (tls.chain_length) rows.push(finding("ok", "Zertifikatskette", `${tls.chain_length} Zertifikat(e) vom Server gesendet.`));

  els.tlsFindings.innerHTML = rows.join("");
  const badge = tls.expired || !tls.hostname_ok || tls.weak_protocol ? "bad" : tls.expiring_soon || tls.self_signed ? "warn" : "ok";
  els.tlsBadge.textContent = tls.expired ? "Abgelaufen" : tls.expiring_soon ? "Laeuft bald ab" : !tls.hostname_ok ? "Hostname-Fehler" : tls.self_signed ? "Selbstsigniert" : "OK";
  els.tlsBadge.className = `badge ${badge}`;
}

async function runBatch() {
  const urls = els.batchInput.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const results = [];
  els.batchResults.innerHTML = "<p>Batch laeuft...</p>";
  for (const raw of urls.slice(0, 50)) {
    const analysis = analyzeURL(raw);
    if (analysis.error) {
      results.push({ raw, status: "ungueltig", finalURL: "", tracking: "", note: analysis.error });
      continue;
    }
    const live = await inspectLive(analysis.normalized);
    results.push({ raw: analysis.normalized, status: live.status, finalURL: live.finalURL || "", tracking: analysis.trackingCount, note: live.error || live.statusText || "" });
  }
  renderBatch(results);
}

function renderBatch(rows) {
  els.batchResults.innerHTML = `<table class="batch-table"><thead><tr><th>URL</th><th>Status</th><th>Finale URL</th><th>Tracking</th><th>Hinweis</th></tr></thead><tbody>${rows.map((row) => `<tr><td>${escapeHTML(row.raw)}</td><td>${escapeHTML(row.status)}</td><td>${escapeHTML(row.finalURL)}</td><td>${escapeHTML(row.tracking)}</td><td>${escapeHTML(row.note)}</td></tr>`).join("")}</tbody></table>`;
}

function addHistory(result) {
  history = [{
    at: new Date().toISOString(),
    url: result.normalized,
    cleanURL: result.cleanURL,
    finalURL: result.live.finalURL,
    status: result.live.status,
    trackingCount: result.trackingCount,
    securityScore: result.securityScore,
  }, ...history.filter((item) => item.url !== result.normalized)].slice(0, 30);
  saveHistory();
  renderHistory();
}

function renderHistory() {
  if (!history.length) {
    els.history.innerHTML = "<p>Keine Pruefungen im Verlauf.</p>";
    return;
  }
  els.history.innerHTML = history.map((item) => `<article class="history-item"><div><strong>${escapeHTML(item.url)}</strong><p class="history-meta">Status ${escapeHTML(item.status)} - Score ${escapeHTML(item.securityScore)} - Tracking ${escapeHTML(item.trackingCount)} - ${new Date(item.at).toLocaleString("de-DE")}</p></div><button class="secondary" data-url="${escapeHTML(item.url)}" type="button">Laden</button></article>`).join("");
  els.history.querySelectorAll("button[data-url]").forEach((button) => button.addEventListener("click", () => {
    els.targetURL.value = button.dataset.url;
    inspectCurrent();
  }));
}

function renderEmpty() {
  els.summary.innerHTML = [metric("Host", "-"), metric("Schema", "-"), metric("Parameter", "-")].join("");
  els.chain.innerHTML = "";
  els.headerFindings.innerHTML = "<p>Fuege Header ein oder pruefe eine URL.</p>";
  els.urlParts.innerHTML = "";
  els.tlsFindings.innerHTML = "<p>Noch keine TLS-Daten. Pruefe eine HTTPS-URL.</p>";
  els.tlsBadge.textContent = "-";
  els.tlsBadge.className = "badge";
}

function renderError(message) {
  els.summary.innerHTML = metric("Fehler", message);
  els.chain.innerHTML = "";
  setHealth("Fehler", "!");
}

function updateCommand(url) {
  const escaped = String(url || "https://example.com").replace(/"/g, "\\\"");
  els.curlCommand.textContent = `curl -I -L --max-redirs 10 "${escaped}"`;
}

function clearAll() {
  els.targetURL.value = "";
  els.rawHeaders.value = "";
  els.batchInput.value = "";
  lastResult = null;
  els.copyCleanURL.disabled = true;
  setHealth("Bereit", "-");
  renderEmpty();
  els.batchResults.innerHTML = "";
}

function setHealth(label, score) {
  els.healthLabel.textContent = label;
  els.healthScore.textContent = score;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`;
}
function part(label, value) {
  return `<div class="part"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`;
}
function finding(tone, title, body) {
  return `<div class="finding ${tone}"><strong>${escapeHTML(title)}</strong><p>${escapeHTML(body)}</p></div>`;
}
function escapeHTML(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(historyKey) || "[]"); } catch (_) { return []; }
}
function saveHistory() { localStorage.setItem(historyKey, JSON.stringify(history)); }
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}
function download(filename, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
function toCSV(rows) {
  const headers = ["at", "url", "cleanURL", "finalURL", "status", "trackingCount", "securityScore"];
  return [headers.join(","), ...rows.map((row) => headers.map((key) => csvCell(row[key])).join(","))].join("\n");
}
function csvCell(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}


