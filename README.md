# Etch Security

Ein leichtgewichtiges WordPress-Sicherheits-Plugin in **einer Datei** — zwei
Schutzschichten plus ein selbst gehostetes Audit-Log, das ohne Premium-Abo
auskommt und sich per GitHub-Releases selbst aktuell hält.

Entstanden aus einem realen Vorfall: Auf einer gepflegten Site wurden zwei
fremde Administrator-Konten (`wpsvc_*@wordpress-svc.internal`) **programmatisch**
angelegt. Wordfence Free protokollierte das zwar, verriet aber weder Verursacher
noch Herkunft — das steckt hinter der Bezahlschranke. Etch Security schließt
genau diese Lücke.

## Was es tut

### 1. User Guard — Domain-Allowlist mit Backstop
Nur E-Mail-Adressen erlaubter Domains bekommen ein Konto. Ein fremdes Konto wird
**sofort entschärft** (Rolle entzogen, Passwort invalidiert, Sessions beendet) —
aber **nicht gelöscht**, damit es als Beweismittel erhalten bleibt.

Zwei Schichten, weil ein Angreifer selten das Registrierungsformular nutzt:
- **Schicht 1 (Prävention):** REST-API, Admin-Profil, Registrierung.
- **Schicht 2 (Backstop):** `user_register` und `set_user_role` mit maximaler
  Priorität — fängt auch `wp_insert_user()` aus Plugin-/Exploit-Code **und** die
  nachträgliche Hochstufung eines Kontos zum Administrator (Privilege
  Escalation).

### 2. Audit Log — dein eigenes Sicherheits-Log
Eine indizierte DB-Tabelle protokolliert sicherheitsrelevante Ereignisse mit
**Actor** (auslösende Identität), Ziel, IP, User-Agent, Request und Kontext
(`web` / `rest` / `cli` / `cron`):

Konten-Anlage · Rollen- und E-Mail-Änderung · Löschung · Application Passwords ·
Login (Erfolg + Fehlschlag) · Passwort-Reset · Plugin-Aktivierung/-Deaktivierung
· Theme-Wechsel.

Ansicht im Backend unter **Werkzeuge → Etch Security** (filterbar, CSV-Export).
Aufbewahrung 180 Tage, täglich per Cron gekürzt.

### 3. Core Updates — Sicherheitsupdates erzwingen
Viele Management-Tools (Installatron, MainWP, o. ä.) schalten WordPress' eigene
Core-Auto-Updates per Filter ab, weil sie die Updates selbst steuern wollen. Fällt
dieses Tool aus oder ist es zu langsam, bleibt die Site auf einer verwundbaren
Version stehen — genau das passierte hier (ein erzwungener Security-Update wurde
geblockt, die Site hing drei Tage auf einer unauth-RCE-Lücke).

Dieses Modul überstimmt solche Blocker mit höherer Filter-Priorität und lässt
**Minor-/Security-Point-Releases** (gleiche `X.Y`-Reihe, z. B. 7.0.1 → 7.0.2)
wieder automatisch durch. **Major-Versionssprünge** (7.0 → 7.1) bleiben bewusst
unberührt. Jedes Auto-Update landet im Audit-Log. Toggle unter **Werkzeuge → Etch
Security** (Standard: an).

### 4. Self-Update über GitHub
Prüft zweimal täglich `releases/latest`, vergleicht die Version und ersetzt sich
bei einer neueren Release atomar durch die Datei aus dem Tag — mit
Plausibilitätsprüfung, bevor irgendetwas geschrieben wird. Manuell auslösbar über
den Button auf der Einstellungsseite.

## Installation

**Als mu-plugin (empfohlen):** Datei nach `wp-content/mu-plugins/etch-security.php`
kopieren. mu-plugins sind automatisch aktiv und lassen sich aus dem Backend nicht
deaktivieren — ein kompromittierter Admin kann den Guard also nicht abschalten.

```bash
wp-content/mu-plugins/etch-security.php
```

**Als reguläres Plugin:** in einen Unterordner
`wp-content/plugins/etch-security/etch-security.php` legen und normal aktivieren.

## Konfiguration

Alles hat sichere Defaults. Erlaubte Domains entweder in `wp-config.php`:

```php
define('ETCH_SECURITY_ALLOWED_DOMAINS', 'meine-firma.de,partner.de');
```

… oder im Backend unter **Werkzeuge → Etch Security → Status & Einstellungen**.

Sicherheitsnetze:
- Die Domain der Site-Admin-Adresse (`admin_email`) ist **immer** erlaubt — kein
  versehentliches Selbst-Aussperren.
- **Enforcement bleibt aus, solange keine Domain gesetzt ist.** Frisch installiert
  läuft nur das Audit-Log (rein lesend, ungefährlich); der Guard greift erst,
  wenn du Domains hinterlegt und Enforcement eingeschaltet hast.

Für Reverse-Proxy/CDN-Setups liefert der Filter `etch_security_client_ip` die
echte Client-IP; die Allowlist lässt sich über `etch_security_allowed_domains`
programmatisch erweitern.

## Release-Workflow

Der Updater liest die Datei auf dem **`main`**-Branch über
`raw.githubusercontent.com` (nicht die GitHub-API — die ist pro IP auf 60
Requests/Stunde limitiert und scheitert auf Shared-Hosting mit `403`). `main`
trägt also immer die aktuellste veröffentlichte Version.

1. Version im Header **und** in `ETCH_SECURITY_VERSION` erhöhen (müssen exakt
   übereinstimmen — der Updater liest und prüft diese Zeile).
2. Nach `main` pushen. (Ein GitHub-Release + Tag `vX.Y.Z` ist optional für den
   menschlichen Changelog; der Updater braucht ihn nicht.)
3. Installierte Sites ziehen das Update beim nächsten Cron-Lauf (2×/Tag) oder per
   Button unter **Werkzeuge → Etch Security**.

> Weil `main` die Update-Quelle ist: die Version erst beim Release erhöhen, nicht
> für Zwischenstände — sonst ziehen Sites unfertigen Code.

## Lizenz

GPL-2.0-or-later. Ohne Gewähr — auf einer Staging-Umgebung testen, bevor es auf
Produktion geht.
