# Redirect Inspector

Lokales Lesezeichen-Hub-Modul zum Pruefen von URLs, Redirects, Tracking-Parametern und HTTP-Headern.

## Funktionen

- URL normalisieren und Bestandteile sichtbar machen
- Tracking-Parameter erkennen und bereinigte URL erzeugen
- Redirect-Checks per Browser-Fetch, wenn CORS der Zielseite das erlaubt
- Header-Paste-Analyzer fuer `curl -I -L` oder PowerShell-Antworten
- Sicherheitsheader-Check fuer CSP, HSTS, X-Frame-Options, Referrer-Policy und weitere Header
- Batch-Modus fuer mehrere URLs
- Lokale Verlaufsliste mit Export als JSON oder CSV
- Kommando-Snippets fuer reproduzierbare Pruefungen ausserhalb des Browsers

## Hinweis zu CORS

Als statische Webapp kann das Modul beliebige Fremdseiten nicht immer direkt inspizieren. Wenn eine Seite CORS blockiert, zeigt das Modul passende lokale Befehle an. Die eingefuegten Header koennen danach vollstaendig analysiert werden.
