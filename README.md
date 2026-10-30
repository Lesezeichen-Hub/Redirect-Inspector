# Redirect Inspector

Lokales Lesezeichen-Hub-Modul zum Pruefen von URLs, Redirects, Tracking-Parametern und HTTP-Headern.

## Funktionen

- URL normalisieren und Bestandteile sichtbar machen
- Tracking-Parameter erkennen und bereinigte URL erzeugen
- Redirect-Checks ueber die generische lokale Lesezeichen-Hub-HTTP-Inspect-API, inklusive Statuscodes und Location-Headern
- Eigenes TLS-Zertifikat-Panel: Laufzeit/Ablauf mit Warnstufen, Aussteller, Self-Signed-Erkennung, Hostname-Pruefung, SANs, Protokollversion, Cipher Suite und Zertifikatskette
- Eigener CertInspector fuer lokale Analyse von PEM- und DER-Zertifikaten sowie CSR-Dateien: Subject, Aussteller, Seriennummer, Gueltigkeit, SANs, Schluessel, Erweiterungen und SHA-256-Fingerabdruck
- Ablaufwarnung (30 Tage), optionaler Hostname-gegen-SAN-Check und Kettenzuordnung mit Signaturpruefung fuer RSA, ECDSA und Ed25519, soweit vom Browser unterstuetzt
- Header-Paste-Analyzer fuer `curl -I -L` oder PowerShell-Antworten
- Sicherheitsheader-Check fuer CSP, HSTS, X-Frame-Options, Referrer-Policy und weitere Header
- Batch-Modus fuer mehrere URLs
- Lokale Verlaufsliste mit Export als JSON oder CSV
- Kommando-Snippets fuer reproduzierbare Pruefungen ausserhalb des Browsers

## Hinweis zu CORS

Mit einer Hub-Version, die `/api/http/inspect` bereitstellt, umgeht das Modul Browser-CORS durch eine lokale serverseitige Pruefung. Wird das Modul ausserhalb des Hubs oder mit einer aelteren Hub-Version gestartet, faellt es auf Browser-Fetch zurueck und zeigt passende lokale Befehle an.

## CertInspector

PEM-Bloecke direkt einfuegen oder `.pem`, `.crt`, `.cer`, `.der` und `.csr` als Dateien auswaehlen. Mehrere Zertifikate koennen in beliebiger Reihenfolge eingegeben werden. PEM-Text und Dateien bleiben im Browser und werden weder an die Hub-API gesendet noch im Verlauf gespeichert. Der Hostname-Check verwendet SAN-Eintraege und unterstuetzt ein Wildcard-Label. Eine gueltige Signatur oder eine passende Kette bedeutet noch nicht, dass die Zertifizierungsstelle vom System als vertrauenswuerdig eingestuft wird; Sperrstatus und Certificate Transparency werden nicht geprueft.

Die Parser-Tests laufen mit `node --test test/cert-core.test.js` und benoetigen OpenSSL im Pfad oder `OPENSSL_BIN`.
