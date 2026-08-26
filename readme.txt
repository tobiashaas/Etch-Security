=== Etch Security ===
Contributors: tobiashaas
Tags: security, audit-log, users, hardening, login
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.1.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Domain allowlist for new accounts + self-hosted audit log (actor/IP/request), in one file. Self-update via GitHub releases.

== Description ==

Two protection layers plus a persistent security log:

* **User Guard** — only allowed email domains get an account; foreign accounts are
  immediately neutralized (role stripped, password invalidated, sessions terminated,
  not deleted = preserved as evidence). Two layers also catch programmatic account
  creation (wp_insert_user) and subsequent privilege escalation.
* **Audit Log** — indexed DB table with actor, target, IP, user agent, request and
  context for account, auth and code events. View: Tools → Etch Security.
  CSV export, 180-day retention.
* **Self-Update** — keeps itself current via GitHub releases.

Safe defaults: enforcement stays off until domains are configured; the admin domain
is always allowed.

== Installation ==

As an mu-plugin (recommended): copy the file to wp-content/mu-plugins/etch-security.php.
Or place it as a regular plugin in wp-content/plugins/etch-security/ and activate it.
Then go to Tools → Etch Security to set the allowed domains and enable enforcement.

== Changelog ==

= 1.1.1 =
* Self-updater switched from the GitHub API (60 req/h per IP -> 403 "rate limit
  exceeded" on shared hosting) to raw.githubusercontent.com (CDN, no limit).
  Source of truth = the file on main.

= 1.1.0 =
* New module "Core Updates": forces WordPress minor/security auto-updates even
  when a management tool (e.g. Installatron) disables them via filter. Only
  point releases of the same X.Y branch; major updates are left untouched.
  Toggle under Tools → Etch Security (default on), audit log entry for every
  core auto-update.

= 1.0.0 =
* Initial release: User Guard (domain allowlist + backstop), Audit Log (table +
  admin view + CSV), GitHub self-updater, settings page.
