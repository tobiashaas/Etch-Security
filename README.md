# Etch Security

A lightweight WordPress security plugin in **one file** — two protection layers
plus a self-hosted audit log that works without a premium subscription and keeps
itself up to date via GitHub releases.

Born from a real incident: two foreign administrator accounts
(`wpsvc_*@wordpress-svc.internal`) were created **programmatically** on a
well-maintained site. Wordfence Free logged it, but revealed neither the cause
nor the origin — that's behind the paywall. Etch Security closes exactly this gap.

## What it does

### 1. User Guard — Domain Allowlist with Backstop
Only email addresses from allowed domains get an account. A foreign account is
**immediately neutralized** (role stripped, password invalidated, sessions
terminated) — but **not deleted**, so it is preserved as evidence.

Two layers, because attackers rarely use the registration form:
- **Layer 1 (Prevention):** REST API, admin profile, registration.
- **Layer 2 (Backstop):** `user_register` and `set_user_role` at maximum
  priority — also catches `wp_insert_user()` from plugin/exploit code **and**
  the subsequent promotion of an account to administrator (privilege escalation).

### 2. Audit Log — your own security log
An indexed DB table records security-relevant events with **Actor** (triggering
identity), target, IP, user agent, request, and context
(`web` / `rest` / `cli` / `cron`):

Account creation · role and email changes · deletion · application passwords ·
login (success + failure) · password reset · plugin activation/deactivation ·
theme switching.

View in the backend under **Tools → Etch Security** (filterable, CSV export).
Retained for 180 days, pruned daily via cron.

### 3. Core Updates — enforce security updates
Many management tools (Installatron, MainWP, etc.) disable WordPress's own
core auto-updates via filter because they want to control updates themselves. If
that tool fails or is too slow, the site remains on a vulnerable version — that
is exactly what happened here (a forced security update was blocked and the site
was stuck on an unauthenticated RCE vulnerability for three days).

This module overrides such blockers with a higher filter priority and lets
**minor/security point releases** (same `X.Y` branch, e.g. 7.0.1 → 7.0.2) run
automatically again. **Major version jumps** (7.0 → 7.1) are deliberately left
untouched. Every auto-update is recorded in the audit log. Toggle under
**Tools → Etch Security** (default: on).

### 4. Self-Update via GitHub
Checks `releases/latest` twice daily, compares the version and atomically
replaces itself with the file from the tag when a newer release is available —
with a plausibility check before anything is written. Can be triggered manually
via the button on the settings page.

## Installation

**As an mu-plugin (recommended):** copy the file to
`wp-content/mu-plugins/etch-security.php`. mu-plugins are automatically active
and cannot be deactivated from the backend — a compromised admin cannot disable
the guard.

```bash
wp-content/mu-plugins/etch-security.php
```

**As a regular plugin:** place it in a subdirectory
`wp-content/plugins/etch-security/etch-security.php` and activate it normally.

## Configuration

Everything has safe defaults. Allowed domains can be set either in `wp-config.php`:

```php
define('ETCH_SECURITY_ALLOWED_DOMAINS', 'my-company.com,partner.com');
```

… or in the backend under **Tools → Etch Security → Status & Settings**.

Safety nets:
- The domain of the site admin address (`admin_email`) is **always** allowed —
  no accidental self-lockout.
- **Enforcement stays off as long as no domain is configured.** Freshly
  installed, only the audit log runs (read-only, harmless); the guard only
  activates once you have added domains and enabled enforcement.

For reverse proxy/CDN setups, the `etch_security_client_ip` filter provides the
real client IP; the allowlist can be extended programmatically via
`etch_security_allowed_domains`.

## Release Workflow

The updater reads the file on the **`main`** branch via `raw.githubusercontent.com`
(not the GitHub API — it is rate-limited to 60 requests/hour per IP and fails on
shared hosting with `403`). `main` therefore always carries the latest published
version.

1. Bump the version in the header **and** in `ETCH_SECURITY_VERSION` (they must
   match exactly — the updater reads and validates this line).
2. Push to `main`. (A GitHub release + tag `vX.Y.Z` is optional for the human
   changelog; the updater does not need it.)
3. Installed sites pull the update on the next cron run (2×/day) or via the
   button under **Tools → Etch Security**.

> Because `main` is the update source: only bump the version at release time, not
> for intermediate states — otherwise sites will pull unfinished code.

## License

GPL-2.0-or-later. No warranty — test on a staging environment before deploying
to production.
