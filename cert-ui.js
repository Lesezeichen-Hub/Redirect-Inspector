(function () {
  "use strict";
  const input = document.getElementById("cert-pem");
  const files = document.getElementById("cert-file");
  const hostname = document.getElementById("cert-hostname");
  const status = document.getElementById("cert-status");
  const overview = document.getElementById("cert-overview");
  const results = document.getElementById("cert-results");
  const count = document.getElementById("cert-count");
  const escape = value => String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const row = (label, value) => `<div class="cert-field"><dt>${escape(label)}</dt><dd>${escape(value || "–")}</dd></div>`;
  const date = value => new Date(value).toLocaleString("de-DE", { dateStyle: "medium", timeStyle: "short" });
  const statusText = state => ({ valid: "Signatur gültig", invalid: "Signatur ungültig", unsupported: "Algorithmus hier nicht prüfbar", unknown: "Aussteller fehlt in der Eingabe" })[state];
  const statusTone = state => ({ valid: "ok", invalid: "bad", unsupported: "warn", unknown: "warn" })[state];

  function render(items) {
    const certs = items.filter(item => item.type === "certificate");
    const csrs = items.filter(item => item.type === "csr");
    count.textContent = `${items.length} Objekt${items.length === 1 ? "" : "e"}`;
    const now = Date.now();
    const expired = certs.filter(item => new Date(item.notAfter).getTime() < now).length;
    const upcoming = certs.filter(item => {
      const remaining = new Date(item.notAfter).getTime() - now;
      return remaining >= 0 && remaining <= 30 * 86400000;
    }).length;
    overview.innerHTML = `<div class="cert-stat-grid">${stat("Zertifikate", certs.length)}${stat("CSR", csrs.length)}${stat("Abgelaufen", expired, expired ? "bad" : "")}${stat("≤ 30 Tage", upcoming, upcoming ? "warn" : "")}</div>`;
    if (certs.length > 1) {
      const linked = certs.filter(item => item.issuerInInput && item.signatureStatus === "valid" && item.issuerIsCA && item.issuerMaySign).length;
      overview.innerHTML += `<p class="hint">Kette: ${linked} signierte Verbindung${linked === 1 ? "" : "en"} zu einem enthaltenen CA-Zertifikat. Die Prüfung bestätigt keine Vertrauensstellung durch ein Betriebssystem oder eine CA.</p>`;
    }
    results.innerHTML = items.map((item, index) => item.type === "csr" ? renderCSR(item, index) : renderCertificate(item, index, now)).join("");
  }
  function stat(label, value, tone = "") { return `<div class="cert-stat ${tone}"><strong>${value}</strong><span>${label}</span></div>`; }
  function renderCertificate(item, index, now) {
    const remaining = Math.ceil((new Date(item.notAfter).getTime() - now) / 86400000);
    const validity = now < new Date(item.notBefore).getTime() ? "Noch nicht gültig" : remaining < 0 ? "Abgelaufen" : remaining <= 30 ? `Läuft in ${remaining} Tagen ab` : `Gültig, noch ${remaining} Tage`;
    const tone = now < new Date(item.notBefore).getTime() || remaining < 0 ? "bad" : remaining <= 30 ? "warn" : "ok";
    const issuer = item.issuerInInput ? "Aussteller in der Eingabe gefunden" : item.issuerMismatch ? "Ausstellerkennung passt nicht zur Eingabe" : item.selfIssued ? "Selbst ausgestellt" : "Aussteller nicht in der Eingabe";
    const issuerWarning = item.issuerInInput && (!item.issuerIsCA || !item.issuerMaySign) ? `<span class="badge bad">Aussteller darf keine Zertifikate signieren</span>` : "";
    const host = hostname.value.trim();
    const hostMatch = host ? CertCore.matchesHostname(item.extensions.san, host) : null;
    return `<article class="cert-card"><div class="cert-card-head"><div><span class="eyebrow">X.509 · #${index + 1}</span><h3>${escape(item.subject || "Unbenanntes Zertifikat")}</h3></div><span class="badge ${tone}">${escape(validity)}</span></div>
      <div class="cert-alerts"><span class="badge ${statusTone(item.signatureStatus)}">${escape(statusText(item.signatureStatus))}</span><span class="badge">${escape(issuer)}</span>${issuerWarning}${host ? `<span class="badge ${hostMatch ? "ok" : "bad"}">${escape(host)}: ${hostMatch ? "SAN passt" : "SAN passt nicht"}</span>` : ""}</div>
      <dl class="cert-fields">${row("Aussteller", item.issuer)}${row("Gültig ab", date(item.notBefore))}${row("Gültig bis", date(item.notAfter))}${row("Seriennummer", item.serial)}${row("Version", `X.509 v${item.version}`)}${row("Signatur", item.signature.name)}${row("Öffentlicher Schlüssel", keyText(item.key))}${row("SHA-256-Fingerabdruck", item.fingerprint)}</dl>
      <details open><summary>Alternative Namen (SAN) · ${item.extensions.san.length}</summary>${list(item.extensions.san, "Keine SAN-Einträge.")}</details>
      <details><summary>Erweiterungen · ${item.extensions.all.length}</summary><dl class="cert-fields">${row("CA-Zertifikat", item.extensions.ca ? "Ja" : "Nein")}${row("Pfadlänge", item.extensions.pathLength ?? "Nicht angegeben")}${row("Key Usage", item.extensions.keyUsage.join(", "))}${row("Extended Key Usage", item.extensions.extendedKeyUsage.join(", "))}${row("Subject Key Identifier", item.extensions.ski)}${row("Authority Key Identifier", item.extensions.aki)}</dl>${list(item.extensions.all.map(ext => `${ext.name}${ext.critical ? " (kritisch)" : ""}`), "Keine Erweiterungen.")}</details></article>`;
  }
  function renderCSR(item, index) {
    return `<article class="cert-card"><div class="cert-card-head"><div><span class="eyebrow">CSR · #${index + 1}</span><h3>${escape(item.subject || "Unbenannte Anfrage")}</h3></div><span class="badge ${statusTone(item.signatureStatus)}">${escape(statusText(item.signatureStatus))}</span></div>
      <p class="hint">Eine CSR enthält noch kein Gültigkeitsdatum und ist noch kein ausgestelltes Zertifikat.</p>
      <dl class="cert-fields">${row("Antragsteller", item.subject)}${row("Öffentlicher Schlüssel", keyText(item.key))}${row("Signatur", item.signature.name)}${row("Version", item.version)}${row("SHA-256-Fingerabdruck", item.fingerprint)}</dl>
      <details open><summary>Beantragte SAN-Einträge · ${item.extensions.san.length}</summary>${list(item.extensions.san, "Keine SAN-Einträge beantragt.")}</details>
      <details><summary>Beantragte Erweiterungen · ${item.extensions.all.length}</summary>${list(item.extensions.all.map(ext => `${ext.name}${ext.critical ? " (kritisch)" : ""}`), "Keine Erweiterungen beantragt.")}</details></article>`;
  }
  function keyText(key) { return `${key.name}${key.parameter ? ` (${key.parameter})` : ""}${key.size ? ` · ${key.size} Bit` : ""}`; }
  function list(values, empty) { return values.length ? `<ul class="cert-list">${values.map(value => `<li>${escape(value)}</li>`).join("")}</ul>` : `<p class="hint">${empty}</p>`; }

  async function run() {
    results.replaceChildren(); overview.replaceChildren();
    count.textContent = "0 Objekte";
    try {
      const blocks = CertCore.fromPEM(input.value);
      const items = blocks.map(block => block.label === "CERTIFICATE" ? CertCore.parseCertificate(block.data) : CertCore.parseCSR(block.data));
      for (const file of files.files) {
        if (file.size > 5 * 1024 * 1024) throw new Error(`${file.name}: Datei ist größer als 5 MB.`);
        const data = new Uint8Array(await file.arrayBuffer());
        if (decoder.decode(data.subarray(0, 40)).includes("-----BEGIN")) {
          const fileBlocks = CertCore.fromPEM(decoder.decode(data));
          if (!fileBlocks.length) throw new Error(`${file.name}: Keine unterstützten PEM-Blöcke gefunden.`);
          items.push(...fileBlocks.map(block => block.label === "CERTIFICATE" ? CertCore.parseCertificate(block.data) : CertCore.parseCSR(block.data)));
        } else {
          try { items.push(CertCore.parseCertificate(data)); }
          catch (certError) {
            try { items.push(CertCore.parseCSR(data)); }
            catch (_) { throw new Error(`${file.name}: Kein gültiges DER-Zertifikat oder CSR (${certError.message})`); }
          }
        }
      }
      if (!items.length) throw new Error("Bitte Zertifikate oder CSR als PEM einfügen oder Dateien auswählen.");
      await CertCore.analyze(items);
      render(items);
      status.textContent = `${items.length} Objekt${items.length === 1 ? "" : "e"} lokal analysiert.`;
    } catch (error) {
      status.textContent = `Analyse fehlgeschlagen: ${error.message}`;
      overview.innerHTML = `<p class="cert-error">${escape(error.message)}</p>`;
    }
  }
  const decoder = new TextDecoder();
  document.getElementById("cert-analyze").addEventListener("click", run);
  document.getElementById("cert-clear").addEventListener("click", () => {
    input.value = ""; files.value = ""; hostname.value = ""; results.replaceChildren();
    overview.innerHTML = "<p>Zertifikate oder CSR einfügen und analysieren.</p>";
    status.textContent = "Noch kein Material analysiert."; count.textContent = "0 Objekte";
  });
})();
