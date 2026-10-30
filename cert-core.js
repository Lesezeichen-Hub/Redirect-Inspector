/* Local, dependency-free DER reader for the fields displayed by CertInspector. */
(function (root) {
  "use strict";
  const decoder = new TextDecoder();
  const names = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "Seriennummer",
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.11": "SHA-256 mit RSA",
    "1.2.840.113549.1.1.12": "SHA-384 mit RSA",
    "1.2.840.113549.1.1.13": "SHA-512 mit RSA",
    "1.2.840.10045.4.3.2": "ECDSA mit SHA-256",
    "1.2.840.10045.4.3.3": "ECDSA mit SHA-384",
    "1.2.840.10045.4.3.4": "ECDSA mit SHA-512",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521",
    "2.5.29.17": "Subject Alternative Name", "2.5.29.19": "Basic Constraints",
    "2.5.29.15": "Key Usage", "2.5.29.37": "Extended Key Usage",
    "2.5.29.14": "Subject Key Identifier", "2.5.29.35": "Authority Key Identifier",
    "1.3.6.1.5.5.7.3.1": "TLS-Server", "1.3.6.1.5.5.7.3.2": "TLS-Client",
    "1.3.6.1.5.5.7.3.3": "Code-Signierung", "1.3.6.1.5.5.7.3.4": "E-Mail-Schutz"
  };
  function fail(message) { throw new Error(message); }
  function bytes(input) { return input instanceof Uint8Array ? input : new Uint8Array(input); }
  function hex(data, separator = "") { return Array.from(data, b => b.toString(16).padStart(2, "0").toUpperCase()).join(separator); }
  function read(data, offset = 0, limit = data.length) {
    if (offset + 2 > limit) fail("Unvollständige ASN.1-Struktur.");
    const start = offset, tag = data[offset++];
    if ((tag & 31) === 31) fail("ASN.1-Tags mit langer Kennung werden nicht unterstützt.");
    let length = data[offset++];
    if (length === 128) fail("Unbestimmte ASN.1-Längen sind in DER nicht erlaubt.");
    if (length & 128) {
      const count = length & 127;
      if (count > 4 || count === 0 || offset + count > limit) fail("Ungültige ASN.1-Länge.");
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + data[offset++];
    }
    const end = offset + length;
    if (end > limit) fail("ASN.1-Länge überschreitet die Eingabe.");
    return { tag, start, value: offset, end, data };
  }
  function children(node) {
    const result = [];
    for (let at = node.value; at < node.end;) {
      const child = read(node.data, at, node.end);
      result.push(child); at = child.end;
    }
    return result;
  }
  function requireTag(node, tag, label) { if (!node || node.tag !== tag) fail(`Ungültiges ${label}.`); return node; }
  function value(node) { return node.data.subarray(node.value, node.end); }
  function raw(node) { return node.data.subarray(node.start, node.end); }
  function oid(node) {
    requireTag(node, 6, "OID");
    const b = value(node); if (!b.length) fail("Leere OID.");
    const parts = []; let n = 0, pending = false;
    for (const byte of b) {
      n = n * 128 + (byte & 127); pending = Boolean(byte & 128);
      if (!pending) {
        if (!parts.length) { parts.push(String(Math.min(2, Math.floor(n / 40)))); parts.push(String(n - Number(parts[0]) * 40)); }
        else parts.push(String(n));
        n = 0;
      }
    }
    if (pending) fail("Unvollständige OID.");
    return parts.join(".");
  }
  function integer(node) { requireTag(node, 2, "Integer"); return hex(value(node)).replace(/^00(?=[0-9A-F]{2})/, "") || "00"; }
  function intNumber(node) { const b = value(requireTag(node, 2, "Integer")); return b.reduce((n, part) => n * 256 + part, 0); }
  function text(node) {
    const b = value(node);
    if (node.tag === 30) {
      if (b.length % 2) fail("Ungültiger BMPString.");
      return Array.from({ length: b.length / 2 }, (_, i) => String.fromCharCode(b[i * 2] * 256 + b[i * 2 + 1])).join("");
    }
    return decoder.decode(b);
  }
  function time(node) {
    if (![23, 24].includes(node.tag)) fail("Ungültiges Gültigkeitsdatum.");
    const source = text(node);
    const match = node.tag === 23
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(source)
      : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(source);
    if (!match) fail("Datumsformat ohne UTC wird nicht unterstützt.");
    const year = node.tag === 23 ? (Number(match[1]) >= 50 ? 1900 : 2000) + Number(match[1]) : Number(match[1]);
    const date = new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0)));
    if (Number.isNaN(date.getTime()) || date.getUTCFullYear() !== year || date.getUTCMonth() !== Number(match[2]) - 1 || date.getUTCDate() !== Number(match[3])) fail("Ungültiges Gültigkeitsdatum.");
    return date.toISOString();
  }
  function distinguishedName(node) {
    return children(requireTag(node, 48, "Name")).flatMap(set => children(requireTag(set, 49, "RDN")).map(attribute => {
      const parts = children(requireTag(attribute, 48, "Attribut"));
      return `${names[oid(parts[0])] || oid(parts[0])}=${text(parts[1])}`;
    })).join(", ");
  }
  function algorithm(node) {
    const parts = children(requireTag(node, 48, "Algorithmus"));
    const id = oid(parts[0]);
    return { oid: id, name: names[id] || id, parameter: parts[1]?.tag === 6 ? names[oid(parts[1])] || oid(parts[1]) : "" };
  }
  function publicKey(node) {
    const parts = children(requireTag(node, 48, "öffentlicher Schlüssel"));
    const alg = algorithm(parts[0]);
    const bits = value(requireTag(parts[1], 3, "Schlüsselbits"));
    if (bits[0] !== 0) fail("Ungültige Schlüsselbits.");
    let size = null;
    if (alg.oid === "1.2.840.113549.1.1.1") {
      const rsa = children(requireTag(read(bits.subarray(1)), 48, "RSA-Schlüssel"));
      size = (value(rsa[0]).length - (value(rsa[0])[0] === 0 ? 1 : 0)) * 8;
    } else if (alg.oid === "1.2.840.10045.2.1" && alg.parameter) {
      size = ({ "P-256": 256, "P-384": 384, "P-521": 521 })[alg.parameter] || null;
    }
    return { ...alg, size, der: raw(node) };
  }
  function generalNames(node) {
    return children(requireTag(node, 48, "SAN")).map(item => {
      const b = value(item);
      if (item.tag === 130) return `DNS: ${decoder.decode(b)}`;
      if (item.tag === 129) return `E-Mail: ${decoder.decode(b)}`;
      if (item.tag === 134) return `URI: ${decoder.decode(b)}`;
      if (item.tag === 135) {
        const address = b.length === 4 ? Array.from(b).join(".") : b.length === 16 ? Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(":") : hex(b);
        return `IP: ${address}`;
      }
      return `Typ ${item.tag & 31}: ${hex(b)}`;
    });
  }
  function parseExtensions(node) {
    const result = { all: [], san: [], ca: false, pathLength: null, keyUsage: [], extendedKeyUsage: [], ski: "", aki: "" };
    for (const extension of children(requireTag(node, 48, "Erweiterungen"))) {
      const parts = children(requireTag(extension, 48, "Erweiterung"));
      const id = oid(parts[0]);
      const critical = parts[1]?.tag === 1 && value(parts[1])[0] !== 0;
      const data = value(requireTag(parts[1]?.tag === 1 ? parts[2] : parts[1], 4, "Erweiterungswert"));
      const inner = read(data);
      result.all.push({ oid: id, name: names[id] || id, critical });
      if (id === "2.5.29.17") result.san = generalNames(inner);
      if (id === "2.5.29.19") {
        const fields = children(requireTag(inner, 48, "Basic Constraints"));
        result.ca = fields.some(field => field.tag === 1 && value(field)[0] !== 0);
        const path = fields.find(field => field.tag === 2);
        if (path) result.pathLength = intNumber(path);
      }
      if (id === "2.5.29.15") {
        const bitString = value(requireTag(inner, 3, "Key Usage"));
        const labels = ["Digitale Signatur", "Nichtabstreitbarkeit", "Schlüsselverschlüsselung", "Datenverschlüsselung", "Schlüsselvereinbarung", "Zertifikate signieren", "CRLs signieren", "Nur verschlüsseln", "Nur entschlüsseln"];
        result.keyUsage = labels.filter((_, i) => bitString[1 + Math.floor(i / 8)] & (128 >> (i % 8)));
      }
      if (id === "2.5.29.37") result.extendedKeyUsage = children(requireTag(inner, 48, "Extended Key Usage")).map(item => names[oid(item)] || oid(item));
      if (id === "2.5.29.14") result.ski = hex(value(requireTag(inner, 4, "Subject Key Identifier")), ":");
      if (id === "2.5.29.35") {
        const key = children(requireTag(inner, 48, "Authority Key Identifier")).find(item => item.tag === 128);
        if (key) result.aki = hex(value(key), ":");
      }
    }
    return result;
  }
  function parseCertificate(input) {
    const data = bytes(input), outer = requireTag(read(data), 48, "Zertifikat");
    if (outer.end !== data.length) fail("Zusätzliche Daten nach dem Zertifikat.");
    const items = children(outer); if (items.length !== 3) fail("Ungültige Zertifikatsstruktur.");
    const tbs = children(requireTag(items[0], 48, "Zertifikatsdaten"));
    let i = 0, version = 1;
    if (tbs[i]?.tag === 160) version = intNumber(children(tbs[i++])[0]) + 1;
    const serial = integer(tbs[i++]); i++; // Signature algorithm inside TBS
    const issuer = distinguishedName(tbs[i++]);
    const validity = children(requireTag(tbs[i++], 48, "Gültigkeit"));
    const notBefore = time(validity[0]), notAfter = time(validity[1]);
    const subject = distinguishedName(tbs[i++]);
    const key = publicKey(tbs[i++]);
    const extNode = tbs.slice(i).find(item => item.tag === 163);
    const extensions = extNode ? parseExtensions(children(extNode)[0]) : parseExtensions({ tag: 48, value: 0, end: 0, data: new Uint8Array() });
    const signature = algorithm(items[1]);
    const sig = value(requireTag(items[2], 3, "Signatur"));
    if (sig[0] !== 0) fail("Ungültige Signaturbits.");
    return { type: "certificate", der: data, tbsDer: raw(items[0]), signatureBytes: sig.subarray(1), version, serial, issuer, subject, notBefore, notAfter, key, signature, extensions };
  }
  function parseCSR(input) {
    const data = bytes(input), outer = requireTag(read(data), 48, "CSR");
    if (outer.end !== data.length) fail("Zusätzliche Daten nach dem CSR.");
    const items = children(outer); if (items.length !== 3) fail("Ungültige CSR-Struktur.");
    const info = children(requireTag(items[0], 48, "CSR-Daten"));
    const version = intNumber(info[0]) + 1;
    const subject = distinguishedName(info[1]);
    const key = publicKey(info[2]);
    let extensions = parseExtensions({ tag: 48, value: 0, end: 0, data: new Uint8Array() });
    if (info[3]?.tag === 160) {
      for (const attribute of children(info[3])) {
        const parts = children(requireTag(attribute, 48, "CSR-Attribut"));
        if (oid(parts[0]) === "1.2.840.113549.1.9.14") {
          const ext = children(requireTag(parts[1], 49, "Erweiterungsanforderung"))[0];
          if (ext) extensions = parseExtensions(ext);
        }
      }
    }
    const signature = algorithm(items[1]);
    const sig = value(requireTag(items[2], 3, "CSR-Signatur"));
    if (sig[0] !== 0) fail("Ungültige CSR-Signaturbits.");
    return { type: "csr", der: data, tbsDer: raw(items[0]), signatureBytes: sig.subarray(1), version, subject, key, signature, extensions };
  }
  function fromPEM(source) {
    const blocks = [], pattern = /-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/g;
    for (const match of String(source).matchAll(pattern)) {
      const label = match[1];
      if (!["CERTIFICATE", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"].includes(label)) continue;
      const base64 = match[2].replace(/\s/g, "");
      if (!base64 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length % 4) fail(`Ungültiger Base64-Inhalt in ${label}.`);
      let data;
      try { data = Uint8Array.from(atob(base64), char => char.charCodeAt(0)); }
      catch (_) { fail(`Ungültiger Base64-Inhalt in ${label}.`); }
      blocks.push({ label, data });
    }
    return blocks;
  }
  async function fingerprint(data) {
    const hash = await root.crypto.subtle.digest("SHA-256", data);
    return hex(new Uint8Array(hash), ":");
  }
  async function verifySignature(subject, signerKey) {
    const algorithms = {
      "1.2.840.113549.1.1.11": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      "1.2.840.113549.1.1.12": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
      "1.2.840.113549.1.1.13": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
      "1.2.840.10045.4.3.2": { name: "ECDSA", hash: "SHA-256" },
      "1.2.840.10045.4.3.3": { name: "ECDSA", hash: "SHA-384" },
      "1.2.840.10045.4.3.4": { name: "ECDSA", hash: "SHA-512" },
      "1.3.101.112": { name: "Ed25519" }
    };
    const spec = algorithms[subject.signature.oid];
    if (!spec) return "unsupported";
    try {
      const importAlgorithm = spec.name === "ECDSA" ? { name: "ECDSA", namedCurve: signerKey.parameter } : spec.name === "Ed25519" ? { name: "Ed25519" } : spec;
      const key = await root.crypto.subtle.importKey("spki", signerKey.der, importAlgorithm, false, ["verify"]);
      const signature = spec.name === "ECDSA" ? ecdsaToRaw(subject.signatureBytes, signerKey.size) : subject.signatureBytes;
      const verifyAlgorithm = spec.name === "ECDSA" ? { name: "ECDSA", hash: spec.hash } : spec;
      return await root.crypto.subtle.verify(verifyAlgorithm, key, signature, subject.tbsDer) ? "valid" : "invalid";
    } catch (_) { return "unsupported"; }
  }
  function ecdsaToRaw(der, size) {
    if (!size) fail("Unbekannte EC-Kurve.");
    const parts = children(requireTag(read(der), 48, "ECDSA-Signatur"));
    const width = Math.ceil(size / 8), output = new Uint8Array(width * 2);
    for (let i = 0; i < 2; i++) {
      let component = value(requireTag(parts[i], 2, "ECDSA-Komponente"));
      while (component.length > width && component[0] === 0) component = component.subarray(1);
      if (component.length > width) fail("Ungültige ECDSA-Signatur.");
      output.set(component, i * width + width - component.length);
    }
    return output;
  }
  async function analyze(items) {
    for (const item of items) item.fingerprint = await fingerprint(item.der);
    const certificates = items.filter(item => item.type === "certificate");
    for (const item of items) {
      if (item.type === "csr") { item.signatureStatus = await verifySignature(item, item.key); continue; }
      const issuers = certificates.filter(candidate => candidate.subject === item.issuer && candidate !== item);
      const matching = issuers.find(candidate => !item.extensions.aki || !candidate.extensions.ski || item.extensions.aki === candidate.extensions.ski);
      item.issuerInInput = Boolean(matching);
      item.issuerMismatch = issuers.length > 0 && !matching;
      item.selfIssued = item.subject === item.issuer;
      item.signatureStatus = matching ? await verifySignature(item, matching.key) : item.selfIssued ? await verifySignature(item, item.key) : "unknown";
      item.issuerFingerprint = matching?.fingerprint || "";
      item.issuerIsCA = matching ? matching.extensions.ca : null;
      item.issuerMaySign = matching ? (!matching.extensions.keyUsage.length || matching.extensions.keyUsage.includes("Zertifikate signieren")) : null;
    }
    return items;
  }
  function matchesHostname(san, hostname) {
    let host;
    try { host = new URL(`https://${hostname.trim()}`).hostname.toLowerCase().replace(/\.$/, ""); }
    catch (_) { return false; }
    if (!host || host.includes(":")) return false;
    return san.some(entry => {
      const [kind, ...rest] = entry.split(": ");
      const name = rest.join(": ").toLowerCase().replace(/\.$/, "");
      if (kind === "IP") return host === name;
      if (kind !== "DNS") return false;
      if (name.startsWith("*.")) {
        const suffix = name.slice(2);
        return host.endsWith(`.${suffix}`) && host.split(".").length === suffix.split(".").length + 1;
      }
      return host === name;
    });
  }
  const api = { fromPEM, parseCertificate, parseCSR, analyze, matchesHostname, hex };
  root.CertCore = api;
  if (typeof module !== "undefined") module.exports = api;
})(globalThis);
