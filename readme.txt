=== Etch Security ===
Contributors: tobiashaas
Tags: security, audit-log, users, hardening, login
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Domain-Allowlist fuer neue Konten + selbst gehostetes Audit-Log (Actor/IP/Request), in einer Datei. Self-Update ueber GitHub-Releases.

== Description ==

Zwei Schutzschichten plus ein dauerhaftes Sicherheits-Log:

* **User Guard** — nur erlaubte E-Mail-Domains bekommen ein Konto; fremde werden
  sofort entschaerft (Rolle entzogen, Passwort invalidiert, Sessions beendet,
  nicht geloescht = Beweismittel). Zwei Schichten fangen auch programmatische
  Anlage (wp_insert_user) und nachtraegliche Rechte-Eskalation.
* **Audit Log** — indizierte DB-Tabelle mit Actor, Ziel, IP, User-Agent, Request
  und Kontext fuer Konten-, Auth- und Code-Ereignisse. Ansicht: Werkzeuge → Etch
  Security. CSV-Export, 180 Tage Aufbewahrung.
* **Self-Update** — haelt sich per GitHub-Releases aktuell.

Sichere Defaults: Enforcement bleibt aus, bis Domains konfiguriert sind; die
Admin-Domain ist immer erlaubt.

== Installation ==

Als mu-plugin (empfohlen): Datei nach wp-content/mu-plugins/etch-security.php
kopieren. Oder als regulaeres Plugin in wp-content/plugins/etch-security/ ablegen
und aktivieren. Danach unter Werkzeuge → Etch Security die erlaubten Domains
setzen und Enforcement einschalten.

== Changelog ==

= 1.1.0 =
* Neues Modul „Core Updates": erzwingt WordPress-Minor-/Security-Auto-Updates,
  auch wenn ein Management-Tool (z. B. Installatron) sie per Filter abschaltet.
  Nur Point-Releases derselben X.Y-Reihe, Major-Updates bleiben unberuehrt.
  Toggle unter Werkzeuge → Etch Security (Default an), Audit-Log-Eintrag bei jedem
  Core-Auto-Update.

= 1.0.0 =
* Erste Release: User Guard (Domain-Allowlist + Backstop), Audit Log (Tabelle +
  Admin-Ansicht + CSV), GitHub-Self-Updater, Einstellungsseite.
