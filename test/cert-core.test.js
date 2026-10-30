const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const core = require("../cert-core.js");

const openssl = process.env.OPENSSL_BIN || (process.platform === "win32" ? "C:\\Program Files\\Git\\usr\\bin\\openssl.exe" : "openssl");
const probe = spawnSync(openssl, ["version"]);

function command(directory, ...args) {
  const result = spawnSync(openssl, args, { cwd: directory, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

test("certificate, CSR, SAN and signed chain are decoded locally", { skip: probe.error ? "OpenSSL unavailable" : false }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "cert-inspector-"));
  try {
    command(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "365", "-subj", "/CN=Test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectKeyIdentifier=hash");
    command(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=www.example.test", "-addext", "subjectAltName=DNS:www.example.test,DNS:*.example.test");
    fs.writeFileSync(path.join(directory, "ext.cnf"), "subjectAltName=DNS:www.example.test,DNS:*.example.test\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n");
    command(directory, "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.pem", "-days", "30", "-extfile", "ext.cnf");
    const pem = fs.readFileSync(path.join(directory, "leaf.pem"), "utf8") + fs.readFileSync(path.join(directory, "ca.pem"), "utf8") + fs.readFileSync(path.join(directory, "leaf.csr"), "utf8");
    const blocks = core.fromPEM(pem);
    assert.equal(blocks.length, 3);
    const items = [core.parseCertificate(blocks[0].data), core.parseCertificate(blocks[1].data), core.parseCSR(blocks[2].data)];
    await core.analyze(items);
    assert.match(items[0].subject, /CN=www\.example\.test/);
    assert.equal(items[0].issuerInInput, true);
    assert.equal(items[0].issuerIsCA, true);
    assert.equal(items[0].signatureStatus, "valid");
    assert.equal(items[1].signatureStatus, "valid");
    assert.equal(items[1].extensions.ca, true);
    assert.equal(items[2].signatureStatus, "valid");
    assert.deepEqual(items[0].extensions.san, ["DNS: www.example.test", "DNS: *.example.test"]);
    assert.deepEqual(items[2].extensions.san, items[0].extensions.san);
    assert.equal(core.matchesHostname(items[0].extensions.san, "foo.example.test"), true);
    assert.equal(core.matchesHostname(items[0].extensions.san, "a.b.example.test"), false);
    assert.equal(core.matchesHostname(items[0].extensions.san, "example.test"), false);
    assert.match(items[0].fingerprint, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    const tampered = Uint8Array.from(blocks[0].data);
    tampered[tampered.length - 1] ^= 1;
    const broken = core.parseCertificate(tampered);
    await core.analyze([broken, items[1]]);
    assert.equal(broken.signatureStatus, "invalid");
    assert.throws(() => core.parseCertificate(blocks[0].data.subarray(0, 20)), /ASN.1/);
    assert.throws(() => core.fromPEM("-----BEGIN CERTIFICATE-----\n***\n-----END CERTIFICATE-----"), /Base64/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("ECDSA and Ed25519 self-signatures are verified", { skip: probe.error ? "OpenSSL unavailable" : false }, async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "cert-inspector-algorithms-"));
  try {
    command(directory, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ec.key", "-out", "ec.pem", "-days", "30", "-subj", "/CN=EC Test");
    command(directory, "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", "ed.key", "-out", "ed.pem", "-days", "30", "-subj", "/CN=Ed Test");
    const items = ["ec.pem", "ed.pem"].map(name => core.parseCertificate(core.fromPEM(fs.readFileSync(path.join(directory, name), "utf8"))[0].data));
    await core.analyze(items);
    assert.deepEqual(items.map(item => item.signatureStatus), ["valid", "valid"]);
    assert.equal(items[0].key.parameter, "P-256");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
