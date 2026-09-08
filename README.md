# Redirect Inspector

Lokales Lesezeichen-Hub-Modul zum Pruefen von URLs, Redirects, Tracking-Parametern und HTTP-Headern.

## Funktionen

- URL normalisieren und Bestandteile sichtbar machen
- Tracking-Parameter erkennen und bereinigte URL erzeugen
- Redirect-Checks ueber die lokale Lesezeichen-Hub-API, inklusive Statuscodes, Location-Headern und TLS-Ablaufdatum
- Header-Paste-Analyzer fuer `curl -I -L` oder PowerShell-Antworten
- Sicherheitsheader-Check fuer CSP, HSTS, X-Frame-Options, Referrer-Policy und weitere Header
- Batch-Modus fuer mehrere URLs
- Lokale Verlaufsliste mit Export als JSON oder CSV
- Kommando-Snippets fuer reproduzierbare Pruefungen ausserhalb des Browsers

## Hinweis zu CORS

Mit einer Hub-Version, die `/api/redirect-inspector` bereitstellt, umgeht das Modul Browser-CORS durch eine lokale serverseitige Pruefung. Wird das Modul ausserhalb des Hubs oder mit einer aelteren Hub-Version gestartet, faellt es auf Browser-Fetch zurueck und zeigt passende lokale Befehle an.
