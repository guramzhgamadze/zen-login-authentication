# Zen Login & Authentication

**Secure, accessible frontend login, registration, and password recovery for WordPress — with two-factor authentication, passkeys, rate limiting, honeypot protection, and native Elementor widgets.**

Zen Login & Authentication replaces the default `wp-login.php` experience with clean,
theme-integrated forms that live on your actual site. It works out of the box on any WordPress
theme and ships with first-class Elementor support — five drag-and-drop widgets that fit into any
page-builder layout, with full Theme Builder compatibility.

- **Website:** https://guramzhgamadze.github.io/zen-login-authentication/
- **WordPress.org:** https://wordpress.org/plugins/zen-login-authentication/
- **Requires:** WordPress 6.5+ · PHP 8.0+ · Elementor optional
- **Licence:** GPL-2.0-or-later
- **Current version:** 2.2.3

The plugin works with no configuration and adds no tracking or phone-home behaviour. Every feature
that contacts an external service is opt-in, so out of the box it makes no external calls at all.

---

## What it does

- **Login** with username, email, or either — configurable.
- **Registration** with optional user-chosen passwords and auto-login.
- **Lost Password / Reset Password** with the full WordPress email flow.
- **Account page** — logged-in users edit their first/last name, public display name (a live
  "Display name publicly as" dropdown, like the core profile screen), email and password entirely
  on the frontend, without ever seeing wp-admin. Guests are sent to the login form and returned
  after signing in.
- **Two-factor authentication** (optional, opt-in per user) — app-based TOTP set up from the
  Account page, with a locally rendered QR code and one-time recovery codes. Enforced across the
  plugin's forms, AJAX submissions and `wp-login.php`.
- **Passkeys (WebAuthn)** (optional, opt-in per user) — passwordless sign-in with Face ID, a
  fingerprint, Windows Hello, or a security key. Phishing-resistant and inherently multi-factor,
  so a passkey login skips both the password and any two-factor step. Verified locally; requires
  HTTPS.
- **Sign in with Google** (optional) — a server-side OpenID Connect flow with no Google JavaScript
  on your pages. New accounts can be auto-created; existing accounts are linked by verified email.
- **New-device login alerts** — emails the account owner the first time their account is signed in
  from an unrecognised device or browser, using your site's normal email. On by default.
- **Sign out of other devices** — one click on the Account page ends every other active session;
  the current device stays signed in.
- **Login activity dashboard** — a widget summarising successful logins, failed attempts and
  rate-limit lockouts over the past week, with the top failed usernames, most-blocked IPs, and a
  recent-events feed. IP addresses are stored anonymised, history auto-prunes, and the data is
  removed on uninstall.
- **URL rewriting** so every site-wide `wp-login.php` link is transparently redirected to your
  frontend pages.
- **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
- **Smart redirects** — `?redirect_to=` is honoured everywhere. Subscribers are kept out of
  wp-admin and sent to a destination you set; privileged users always land where they intended.
- **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page
  Cache, WP Rocket, W3 Total Cache and WP Super Cache.

---

## Security

- **Nonce verification** on every form submission.
- **Rate limiting** — configurable max attempts per IP with a lockout window, per form (login,
  register, lost-password, reset-password), with optional per-form thresholds.
- **Per-account login throttle** — alongside the per-IP limiter, repeated failed logins for one
  username add a short, progressively longer delay. It is a *delay, not a lockout*, so it cannot be
  weaponised to lock a real user out, and it blunts credential-stuffing that rotates IP addresses.
- **Honeypot spam protection** — a rotating hidden field (hourly HMAC key rotation) catches bots;
  trapped submissions get a fake success response, so bots never learn they failed.
- **Spoof-resistant IP detection** — rate-limit keys use the real socket address (`REMOTE_ADDR`) by
  default, and IPs are stored anonymised (IPv4 last octet zeroed, IPv6 to /48). Forwarded headers
  are opt-in via a filter, for sites genuinely behind Cloudflare with the origin firewall locked to
  Cloudflare's ranges.
- **No password pre-population**, bcrypt-compatible (`wp_set_password()` / `wp_signon()`), and an
  8-character minimum on new passwords.
- **Username-enumeration hardening** (on by default) — blocks `?author=N` author scans and the REST
  `/wp/v2/users` listing for logged-out visitors, and collapses login errors to one neutral message
  so a valid username is never confirmed. Author archives at `/author/name/` and logged-in editors
  are unaffected.
- **Breached-password blocking** (optional) — reject passwords found in the Have I Been Pwned
  corpus at registration, reset and account update, using k-anonymity: only the first 5 characters
  of the password's SHA-1 hash are sent, never the password. Fails open if the service is
  unreachable.
- **Cloudflare Turnstile** (optional) — a privacy-friendly bot challenge on the login, registration
  and lost-password forms, on the plugin's forms and `wp-login.php` alike.
- **XML-RPC lockdown** (optional) — closes the `system.multicall` brute-force amplifier and
  pingback abuse.
- **Encrypted secrets at rest** — the Google client secret and Turnstile secret key are stored with
  AES-256-GCM keyed from your `wp-config.php` salts, never re-displayed in admin HTML, and survive
  a salt rotation via a fallback-material filter.
- **GDPR** — personal-data export and erasure covering devices, passkeys, two-factor and Google
  links.

### External services

The plugin contacts an external service **only** when you enable one of the optional features
below. Out of the box it makes no external calls.

| Service | When | What is sent |
|---|---|---|
| **Google OAuth / OpenID Connect** | "Sign in with Google" is enabled and a user clicks it | Your configured OAuth client credentials and the single-use authorization code. Google returns the user's verified email, name and account ID, used solely to log them in or create their account. [Terms](https://policies.google.com/terms) · [Privacy](https://policies.google.com/privacy) |
| **Have I Been Pwned (Pwned Passwords)** | "Block breached passwords" is enabled and a password is set or changed | The **first 5 characters** of the password's SHA-1 hash only. The password, the full hash, and any user identity are never transmitted; the request is cached. [Terms](https://haveibeenpwned.com/API/v3#License) · [Privacy](https://haveibeenpwned.com/Privacy) |
| **Cloudflare Turnstile** | Turnstile is configured | The challenge script loads on the protected forms; on submission the challenge token and the visitor's IP are sent to Cloudflare's siteverify endpoint. [Terms](https://www.cloudflare.com/website-terms/) · [Privacy](https://www.cloudflare.com/privacypolicy/) |

Two-factor QR codes and passkey verification are handled entirely locally — neither makes any
external request.

---

## Elementor integration

Five native widgets registered under a "Zen Login & Authentication" category. Each can be toggled
off under **Settings → Widgets**.

| Widget | Description |
|---|---|
| **Login Form** | Custom labels, placeholders, toggle text and link overrides. Hidden when logged in (unless `reauth=1`). Picks up `?redirect_to=` from the URL, taking priority over the editor-configured default. Optional passkey and "Continue with Google" buttons. |
| **Registration Form** | Password + confirm fields when user-chosen passwords are enabled, with a live strength meter. Editor placeholder when registration is disabled. |
| **Lost Password Form** | Password-recovery request form. |
| **Reset Password Form** | Reads `?key=&login=` from the URL and shows a friendly message when the link is missing or expired. |
| **Account Form** | Frontend profile editing — read-only username, first/last name, a live "Display name publicly as" dropdown, email, an optional password change, plus the Passkeys, Two-Factor and Session Management cards. Renders nothing for guests. |

All widgets share a comprehensive style panel: form container (width, max-width, alignment,
background, border, radius, shadow, padding), title typography, label styling, input fields
(text/placeholder colour, background, border, focus state with glow), buttons (normal + hover tabs
with typography, padding, radius, shadow, transition), action links, messages and errors, the
password toggle, and checkbox styling.

Every auth widget declares `is_dynamic_content(): true`, so Elementor's element cache can never
freeze a per-request nonce or `?redirect_to=` value, and `has_widget_inner_wrapper(): false` for
V4 Atomic Widgets compatibility.

### Pages

On activation the plugin sets up a real WordPress page for each auth action so Elementor Theme
Builder conditions (Singular → Page, targeted by ID) work correctly. For each default slug it
**reuses** an existing page if one is there — never modifying or deleting it — otherwise it
**creates** one. The process is idempotent, so activate/deactivate cycles never duplicate pages,
and the plugin also works with no real pages at all via its virtual URL-rewrite fallback.

### Classic widgets

Five `WP_Widget` subclasses are also registered for classic and block-based widget areas: Login,
Register, Lost Password, Reset Password and Account. All expose `show_instance_in_rest` for the
block-based Widgets screen and respect their per-widget enable toggle.

---

## Installation

1. Install through **Plugins → Add New** (search for "Zen Login & Authentication"), or from
   [WordPress.org](https://wordpress.org/plugins/zen-login-authentication/).
2. Activate it through **Plugins → Installed Plugins**.
3. Go to **Zen Login & Authentication** in the admin sidebar to configure options.
4. Auth pages are created automatically on activation. If you delete some and want them back, use
   **Create Missing Pages** in the Page Management section.
5. Rewrite rules flush automatically on the first page load after activation. If a frontend URL
   404s, visit **Settings → Permalinks** and click **Save Changes**.
6. *(Elementor users)* Open a page in the Elementor editor and search the widget panel under the
   **Zen Login & Authentication** category.

---

## Settings

### General

| Setting | Default | Description |
|---|---|---|
| Login with | Username or Email | Restrict to username-only or email-only |
| Pretty URLs | On | Uses `/login/` instead of `?action=login` |
| AJAX forms | Off | Submit forms without a page reload |
| User-chosen passwords | Off | Shows password fields on the registration form |
| Auto-login | Off | Logs users in immediately after registering |
| Honeypot protection | On | Hidden field to catch bots |
| Subscriber redirect | *(empty)* | Where subscribers land after login — a page slug or full URL; empty = site home. Admins and editors keep their normal redirect. |

### Rate limiting

| Setting | Default | Description |
|---|---|---|
| Max attempts | 10 | Failed attempts before lockout (0 = disabled) |
| Lockout window | 15 min | Duration of the lockout once max attempts is reached |

Each form (Login, Registration, Lost Password, Reset Password) additionally has its own enable
toggle and an optional **Max attempts override**. The override defaults to `0`, meaning "use the
global value"; any positive integer takes precedence for that form only.

**Count successful lost-password requests** (default off) closes an email-spam loophole: core's
`retrieve_password()` returns `true` even for unknown addresses (anti-enumeration), so without this
the limiter would never engage on a stream of reset requests to a known-valid address.

### Page slugs

Each action URL slug is customisable: `login`, `logout`, `register`, `lostpassword` (default
`lost-password`), `resetpass` (default `reset-password`), and `account`.

### Page management

| Button | Description |
|---|---|
| Create Missing Pages | Creates real WordPress pages for any auth action that doesn't already have one. Existing pages with matching slugs are adopted, not duplicated. |
| Delete Auto-Created Pages | Removes only pages the plugin created. Pages you created manually and the plugin adopted are left intact. |

---

## Hooks & filters

### Actions

| Hook | Parameters | Description |
|---|---|---|
| `zenlogau_init` | `ZENLOGAU $instance` | Fires when the core class initialises |
| `zenlogau_registered_action` | `string $name, array $args` | After an action is registered |
| `zenlogau_registered_form` | `string $name, ZENLOGAU_Form $form` | After a form is registered |
| `zenlogau_before_form_{name}` | `ZENLOGAU_Form $form` | Before form HTML renders |
| `zenlogau_after_form_{name}` | `ZENLOGAU_Form $form` | After form HTML renders |
| `zenlogau_{name}_form` | — | Inside the form, for adding custom fields |
| `zenlogau_action_{action}` | — | When a POST action is dispatched |
| `zenlogau_login_failed` | `string $username` | After a failed login attempt |
| `zenlogau_login_success` | `WP_User $user` | After a successful login |
| `zenlogau_logout_success` | — | After a successful logout |
| `zenlogau_registration_success` | `int $user_id` | After a successful registration |
| `zenlogau_password_reset` | `WP_User $user` | After a successful password reset |
| `zenlogau_account_updated` | `int $user_id, bool $password_changed` | After a profile update via the Account form |
| `zenlogau_rate_limit_recorded` | `string $action, int $attempts` | After a rate-limit bump |
| `zenlogau_rate_limit_locked` | `string $action, string $ip, int $attempts` | Fires once, the moment an IP crosses the threshold |
| `zenlogau_exclude_from_cache` | — | On every auth page request — hook here for custom cache exclusion |

### Filters

| Filter | Default | Description |
|---|---|---|
| `zenlogau_use_permalinks` | `true` | Toggle pretty URLs |
| `zenlogau_use_ajax` | `false` | Toggle AJAX form submission |
| `zenlogau_allow_user_passwords` | `false` | Toggle user-chosen passwords |
| `zenlogau_allow_auto_login` | `false` | Toggle auto-login after registration |
| `zenlogau_use_honeypot` | `true` | Toggle honeypot protection |
| `zenlogau_rate_limit` | `10` | Max failed attempts (global default) |
| `zenlogau_rate_limit_window` | `15` | Lockout window in minutes |
| `zenlogau_rate_limit_ip_headers` | `['REMOTE_ADDR']` | `$_SERVER` keys checked for the client IP. Prepend `HTTP_CF_CONNECTING_IP` **only if** the origin is locked to Cloudflare's ranges |
| `zenlogau_rate_limit_enabled_{action}` | `true` | Per-form rate-limit toggle (`login`, `register`, `lostpassword`, `resetpass`) |
| `zenlogau_rate_limit_{action}` | global default | Per-form threshold override |
| `zenlogau_account_throttle_*` | — | Tune the per-account login delay |
| `zenlogau_2fa_trust_days` | `30` | How long a trusted two-factor device stays trusted |
| `zenlogau_2fa_trusted_devices_enabled` | option | Turn "trust this device" off entirely |
| `zenlogau_passkey_require_user_verification` | `true` | Require a PIN/biometric on passkey sign-in. Set `false` only to support presence-only keys, accepting the weaker guarantee |
| `zenlogau_frame_options` | `SAMEORIGIN` | The `X-Frame-Options` value sent on auth pages |
| `zenlogau_crypto_fallback_materials` | — | Previous salt material, so secrets survive a `wp-config.php` salt rotation |
| `zenlogau_action_url` | — | Filter any action URL |
| `zenlogau_action_slug_{action}` | — | Filter a specific action's slug |
| `zenlogau_username_label` | — | Filter the username field label |
| `zenlogau_subscriber_redirect` | resolved from the setting | Destination for subscribers after login, or when they try to reach wp-admin |
| `zenlogau_subscriber_login_redirect_to` | resolved destination | Final say over where a restricted subscriber lands |
| `zenlogau_widget_enabled` | per-widget option | Whether a given form widget is registered |
| `zenlogau_account_update_errors` | `WP_Error $errors, WP_User $user` | Add custom validation to an Account-form submission |
| `zenlogau_account_display_name_options` | `array $options, WP_User $user` | Filter the "Display name publicly as" choices |
| `zenlogau_activity_log_enabled` | option (`true`) | Whether login-activity logging is active |
| `zenlogau_activity_retention_days` | option (`30`) | Days of history to keep (0 = forever) |
| `zenlogau_logged_in_redirect` | role-based | Redirect for already-logged-in users visiting login/register |
| `zenlogau_logout_redirect` | `home_url()` | Redirect after logout |
| `zenlogau_login_url_exempt` | `false` | Return `true` to bypass login-URL rewriting (for OAuth/REST flows) |
| `zenlogau_script_data` | — | Filter the JS config object |
| `zenlogau_form_links_{name}` | — | Filter the action links below a form |
| `zenlogau_form_attributes_{name}` | — | Add custom HTML attributes to a form |
| `zenlogau_widget_form_output` | — | Filter rendered form HTML |
| `zenlogau_new_user_notification` | `'both'` | Control new-user email recipients |
| `zenlogau_page_actions` | — | Filter which actions get real WP pages |
| `zenlogau_ajax_success_data` / `zenlogau_ajax_error_data` | — | Filter AJAX response data |

### Redirect priority order

Every front-end login runs WordPress's standard `login_redirect` filter (exactly as `wp-login.php`
does), so membership and LMS plugins always get their say. After that filter:

1. `?redirect_to=` in the URL is the pre-filter default for the user's intended destination; the
   Elementor widget's configured Redirect URL is used when no URL parameter is present.
2. **Other plugins** can override the destination via `login_redirect` — a non-admin destination
   they choose is respected.
3. Role-based guardrails: **restricted subscribers** are never landed in wp-admin (an empty or
   `/wp-admin/` target falls back to the Subscriber redirect setting), while **administrators,
   editors and other roles** are unaffected — including the "clicked Edit → bounced to login → back
   to Edit" round-trip.

---

## Third-party compatibility

The plugin fires the standard WordPress form hooks (`login_form`, `register_form`,
`lostpassword_form`, `resetpass_form`) inside its forms, so plugins that add fields to WordPress's
native login — 2FA plugins, CAPTCHA plugins, social login plugins — render their fields inside
these forms automatically.

An OAuth/REST exemption is built in: when another plugin calls `wp_login_url()` or
`site_url('wp-login.php')` with a REST API redirect target, the plugin stands aside and returns the
native `/wp-login.php` URL so the handshake completes. The `zenlogau_login_url_exempt` filter is
available for an explicit opt-out.

### Cache plugins

Auth pages are automatically excluded from caching, and stale entries are purged on version change.

| Plugin | Method |
|---|---|
| LiteSpeed Cache | `X-LiteSpeed-Cache-Control: no-cache` header + `litespeed_control_set_nocache` + per-URL purge |
| Super Page Cache | `DONOTCACHEPAGE` |
| WP Rocket | `DONOTROCKETOPTIMIZE` |
| W3 Total Cache | `DONOTCACHEOBJECT` + `DONOTMINIFY` |
| WP Super Cache | `DONOTCACHEPAGE` |
| Any plugin | `Cache-Control: no-store` + `Pragma: no-cache`. Hook `zenlogau_exclude_from_cache` for custom logic. |

---

## Changelog

### 2.2.3
The rate limiter's companion "lockout start" transient is now built as a fully prefixed literal
(`zenlogau_rl_ts_…`) by a dedicated key builder, instead of appending a suffix to the counter key —
so it passes strict transient-naming checks. Added a direct-access (`ABSPATH`) guard to the 13
bundled WebAuthn library files that lacked one. No behaviour, settings or data changes.

### 2.2.1
**Passkey user verification is now required by default.** A passkey sign-in bypasses both the
password and any two-factor step, so it must itself be multi-factor; previously a presence-only
authenticator could complete a login, undermining that invariant. Also: the plugin's auth pages now
send `X-Frame-Options` and `X-Content-Type-Options`, matching `wp-login.php`.

### 2.2.0
**Trust this device** for two-factor logins — a trusted browser skips the code prompt on later
logins, but the password is always still required. **Per-account login throttle** — a short,
progressively longer delay (never a lockout) on repeated failures for one username, blunting
credential-stuffing that rotates IPs. Google-created accounts are no longer asked for a "current
password" they never set. Encrypted secrets survive a `wp-config.php` salt rotation. Faster
Google-account lookups on large sites. The bundled WebAuthn library's origin check now requires an
exact domain or true subdomain, and an unused routine that wrote files to an arbitrary folder was
removed.

### 2.1.4 – 2.1.6
The Account page was reorganised into clear cards — Profile Information, Change Password, Passkeys,
Two-Factor Authentication and Session Management — with two-column profile fields and separate
"Save Profile" / "Update Password" actions. Card headings gained their own Elementor style controls
instead of inheriting the theme colour, the Session Management card lists the devices currently
signed in, and an **Action Links** style section makes every text link styleable from the toolbar.

### 2.1.3
Security hardening from a full audit: turning off two-factor now requires a current authenticator
or recovery code; TOTP codes can no longer be replayed within their validity window; passkey
sign-in is rate-limited and validates the authenticator signature counter (clone detection);
changing your email or password on the Account page requires your current password; and GDPR
personal-data export and erasure were added. Administrators can reset a locked-out user's
two-factor and passkeys from the user-edit screen.

### 2.1.2
All Elementor editor-preview templates now escape interpolated field values. The previews
previously used raw Backbone interpolation, which could render unescaped HTML inside the builder —
an editor-context XSS vector. No functional changes.

### 2.1.1
Redesigned login, registration and account forms: a polished default card surface, a refined
"security blue" palette, full-width primary buttons and an outline secondary style — all still
controllable from the Elementor toolbar. The passkey button gained an icon and its own
normal/hover controls. The new-device alert email became a styled, mobile-friendly HTML message.

### 2.1.0
**Passkeys (WebAuthn).** Users add passkeys from the Account page and sign in with no password
using Face ID, a fingerprint, Windows Hello or a security key. Credentials are verified locally —
no external request. Requires HTTPS.
**New-device login alerts.** Emails the account owner the first time their account is signed in
from an unrecognised device, using your site's normal email. On by default.

### 2.0.0
**Two-factor authentication (TOTP).** Opt-in per user and managed entirely from the Account page:
scan a QR code (rendered locally) or enter the setup key in any authenticator app, confirm a code
to turn it on, and save one-time recovery codes. Enforced across the plugin's forms, AJAX
submissions and `wp-login.php`. The shared secret is stored encrypted; recovery codes are hashed
and single-use; the login challenge sets no auth cookie until the second factor verifies.
Also: **sign out of other devices** from the Account page.

### 1.9.0
**Security Hardening panel.** Username-enumeration protection (on by default) blocks `?author=N`
scans and the guest REST user listing, and collapses login errors to one neutral message. Optional
XML-RPC lockdown. **Breached-password blocking** via the Have I Been Pwned k-anonymity range API.
**Cloudflare Turnstile** bot protection on the login, registration and lost-password forms.

### 1.8.0 – 1.8.1
Internal prefix changed to `zenlogau` across functions, classes, constants, options, transients,
meta and the activity table, with a one-time automatic migration. 1.8.1 removed the migration
routine once it had served its purpose.

### 1.7.0 – 1.7.2
**Login activity dashboard widget** — successful logins, failed attempts and lockouts for the past
week, the top failed usernames, the most-blocked IPs, and a recent-events feed. Captured across
every login path; IPs stored anonymised; retention configurable and auto-pruned; table dropped on
uninstall. 1.7.1 renamed the plugin to **Zen Login & Authentication** and moved all admin CSS to
enqueued stylesheets.

### 1.6.x
**Account page and widget** — frontend profile editing for logged-in users, with a live "Display
name publicly as" dropdown mirroring the wp-admin profile screen. **Per-widget on/off toggles.**
Post-login redirects now run WordPress's standard `login_redirect` filter, so membership and LMS
plugins are respected, while restricted subscribers are still never landed in wp-admin.

### 1.5.0
**Sign in with Google** — a server-side OpenID Connect authorization-code flow with no Google
JavaScript on any page. CSRF-protected by a single-use state token bound to the browser; only
verified Google emails are accepted. The client secret is encrypted at rest with AES-256-GCM keyed
from the `wp-config.php` salts, and never re-displayed in admin. Credentials can alternatively be
defined as constants to keep them out of the database entirely.

### 1.4.x
Real WordPress pages for auth actions (Elementor Theme Builder compatibility) with idempotent
adopt-or-create; the full Elementor style panel; per-form rate limiting; the lost-password email
spam loophole closed; automatic cache exclusion and stale-404 purging; rate-limit IP detection
hardened against header spoofing; uninstall no longer deletes edited or adopted pages; and a
configurable subscriber redirect.

### 1.2.0
Initial public release.

---

## About this repository

This repository hosts the **documentation and project page** for Zen Login & Authentication. The
plugin source is developed privately; the released, installable plugin is distributed through the
[WordPress plugin directory](https://wordpress.org/plugins/zen-login-authentication/) under the
GPL-2.0-or-later licence, which includes its complete source.

Other plugins in the Zen family:

- [Zen Site Security](https://github.com/guramzhgamadze/zen-site-security) — HTTPS, headers and hardening
- [Zen MCP Bridge](https://github.com/guramzhgamadze/zen-mcp-bridge) — read-only MCP server for WordPress
- [Zen GEO](https://github.com/guramzhgamadze/zen-geo) — generative engine optimization
- [Zen Blogger](https://github.com/guramzhgamadze/zen-blogger) — accessible Elementor blog widgets

---

Built by [Guram Zhgamadze](https://github.com/guramzhgamadze).
