# Zen Login & Authentication

Secure, accessible frontend login, registration, and password recovery forms for WordPress — with rate limiting, honeypot protection, AJAX support, native Elementor widgets, and full cache-plugin compatibility.

## Description

Zen Login & Authentication replaces the default `wp-login.php` experience with clean, theme-integrated forms that live on your actual site. It works out of the box on any WordPress theme and ships with first-class Elementor support — five drag-and-drop widgets that fit into any page builder layout with full Theme Builder compatibility.

### What It Does

- **Login form** with username, email, or either — configurable from Settings.
- **Registration form** with optional user-chosen passwords and auto-login.
- **Lost Password / Reset Password** forms with full email flow integration.
- **Account page** — logged-in users edit their first/last name, public display name (live "Display name publicly as" dropdown, like the core profile screen), email, and password entirely on the frontend. Guests visiting the account page are sent to login and returned after signing in.
- **Two-factor authentication** (optional, opt-in per user) — app-based TOTP set up from the Account page, with a locally rendered QR (no external calls) and one-time recovery codes. Enforced across the plugin's forms, AJAX, and `wp-login.php`.
- **Passkeys (WebAuthn)** (optional) — passwordless sign-in with Face ID, a fingerprint, Windows Hello, or a security key, registered from the Account page. Phishing-resistant and inherently multi-factor, so it skips both the password and any 2FA step. Verified locally by the bundled lbuchs/WebAuthn library — no external request. Requires HTTPS.
- **New-device login alerts** — emails the account owner the first time their account is signed in from an unrecognised device, using your site's normal email (no external service). On by default; supports a custom HTML body.
- **Sign out of other devices** — a one-click action on the Account page that ends every other active session for the account, keeping the current one.
- **Login activity dashboard** — a "Login Activity" widget on the WordPress dashboard summarising successful logins, failed attempts, and rate-limit lockouts over the past week, with the top failed usernames, most-blocked IPs, and a recent-events feed. IPs are stored anonymised, history auto-prunes, and the data is removed on uninstall.
- **Per-widget toggles** — enable or disable each form widget (login, register, lost password, reset password, account) for both the Elementor panel and classic widget areas, under **Settings → Zen Login & Authentication → Widgets**.
- **Sign in with Google** (optional) — a server-side OpenID Connect flow with no Google JavaScript on your pages and no third-party libraries. New accounts can be auto-created (toggleable); existing accounts are linked by verified email. Configured under **Settings → Zen Login & Authentication → Sign in with Google**.
- **URL rewriting** — all `wp-login.php` links site-wide are transparently redirected to your frontend pages.
- **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
- **Smart redirects** — every front-end login runs WordPress's standard `login_redirect` filter, so membership/LMS and other plugins are respected. Restricted subscribers are kept out of wp-admin and sent to a configurable destination — set a page slug or URL under **Settings → Zen Login & Authentication → Subscriber redirect** (default: the site home page; also filterable via `zenlogau_subscriber_redirect`). Administrators and editors keep their normal flow, including the "clicked Edit → login → back to Edit" round-trip. `?redirect_to=` is fully honoured on both virtual and Elementor pages.
- **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache. Stale 404 cache entries are purged automatically on plugin update.

### Security

- **Nonce verification** on every form submission.
- **Rate limiting** — configurable max attempts per IP with lockout window (uses transients). Applied to all four handlers: login, register, lost-password, and reset-password.
- **Honeypot spam protection** — rotating hidden field (hourly key rotation via HMAC) catches bots. Trapped submissions get a fake success response — bots never know they failed.
- **IP anonymisation** — rate-limit keys hash truncated IPs (last octet zeroed for IPv4, /48 for IPv6). The client IP is read from `REMOTE_ADDR` only by default, because forwarded headers like `HTTP_CF_CONNECTING_IP` / `X-Forwarded-For` are spoofable on any server not actually behind that proxy (an attacker could rotate the header to land in a fresh bucket and dodge the throttle). Sites genuinely behind Cloudflare — with the origin firewall locked to Cloudflare's IP ranges — can opt the real-client header back in: `add_filter('zenlogau_rate_limit_ip_headers', fn() => ['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR']);`
- **No password pre-population** — password fields are never re-filled from POST data.
- **bcrypt-compatible** — uses `wp_set_password()` / `wp_signon()` which support WP 6.8+ bcrypt hashing.
- **Password minimum length** — reset and registration passwords require at least 8 characters.
- **Breached-password blocking** (optional) — reject passwords found in the Have I Been Pwned corpus via k-anonymity; only a 5-character SHA-1 prefix ever leaves the site, never the password, and it fails open if the service is unreachable.
- **Username-enumeration & XML-RPC hardening** — blocks `?author=N` author scans and the guest REST user listing, collapses login errors to one neutral message so a valid username is never confirmed, and offers an optional XML-RPC lockdown. On by default where it's safe.
- **Cloudflare Turnstile** (optional) — privacy-first bot challenge on login, registration, and lost-password (and `wp-login.php`), with server-side token verification and the secret stored encrypted at rest.

### Elementor Integration

Five native `Widget_Base` widgets registered via `elementor/widgets/register` (each can be toggled off under **Settings → Zen Login & Authentication → Widgets**):

| Widget | Class | Description |
|--------|-------|-------------|
| Login Form | `ZENLOGAU_Elementor_Login_Widget` | Login form with custom labels, placeholders, toggle text, and link overrides. Hidden when logged in (unless `reauth=1`). Automatically picks up `?redirect_to=` from the URL, taking priority over the editor-configured default. Optional "Sign in with Google" button. |
| Registration Form | `ZENLOGAU_Elementor_Register_Widget` | Registration form with password + confirm fields when user-chosen passwords are enabled. Editor placeholder when registration is disabled. Optional "Sign in with Google" button. |
| Lost Password Form | `ZENLOGAU_Elementor_Lost_Password_Widget` | Password recovery request form. |
| Reset Password Form | `ZENLOGAU_Elementor_Reset_Password_Widget` | Password reset form — reads `?key=&login=` from the URL. Shows invalid-link message when parameters are missing, with an editor preview of the form fields. |
| Account Form | `ZENLOGAU_Elementor_Account_Widget` | Frontend profile editing for the logged-in user — read-only username, first/last name, a live "Display name publicly as" dropdown, email, and an optional password change. Renders nothing for guests. |

All widgets share a comprehensive Elementor style panel: form container (width, max-width, alignment, background, border, radius, shadow, padding), title typography, label styling, input fields (text colour, placeholder colour, background, border, focus state with glow), button (normal + hover tabs with typography, padding, radius, shadow, transition), action links, messages/errors, password toggle (normal + hover tabs), and checkbox styling.

The Reset Password and Account widgets (and all auth widgets, in fact) declare `is_dynamic_content(): true` so Elementor element caching never freezes a per-request nonce or redirect.

#### Page Management

On activation the plugin sets up a real WordPress page for each auth action so Elementor Theme Builder conditions work correctly (Singular > Page targeting by ID). For each action it checks the default slug: if a page already exists there it is **reused** as-is (never modified, and never deleted on uninstall); otherwise a new page is **created**. The process is idempotent, so activate/deactivate cycles never duplicate pages. The **Page Management** panel in the settings screen lets you re-create any missing pages or remove the auto-created ones manually. The plugin also works without real pages via its virtual URL rewrite system.

### Classic Widgets

Five `WP_Widget` subclasses are also registered for classic sidebar/widget-area use:

- `ZENLOGAU_Login_Widget`
- `ZENLOGAU_Register_Widget`
- `ZENLOGAU_Lost_Password_Widget`
- `ZENLOGAU_Reset_Password_Widget`
- `ZENLOGAU_Account_Widget`

All expose `show_instance_in_rest` for the WP 5.8+ block-based Widgets screen, and each respects its per-widget enable toggle.

## Requirements

| Dependency | Minimum |
|-----------|---------|
| WordPress | 6.5+ |
| PHP | 8.0+ |
| Elementor | Optional — plugin works without it |

## Installation

1. Upload the `zen-login-authentication` folder to `/wp-content/plugins/`.
2. Activate the plugin through **Plugins → Installed Plugins**.
3. Go to **Zen Login & Authentication** in the admin sidebar to configure options.
4. *(Optional)* The auth pages are created automatically on activation. If you later delete some and want them back, click **Create Missing Pages** in the Page Management section.
5. Rewrite rules are flushed automatically on the first page load after activation (v1.4.16+). If needed, go to **Settings → Permalinks** and click **Save Changes**, or run `wp rewrite flush`.
6. *(Elementor users)* Open any page in the Elementor editor and search for "Login Form", "Registration Form", etc. in the widget panel under the **Zen Login & Authentication** category.

## Settings

All settings are under the **Zen Login & Authentication** admin menu:

### General

| Setting | Default | Description |
|---------|---------|-------------|
| Login with | Username or Email | Restrict to username-only or email-only |
| Pretty URLs | On | Uses `/login/` instead of `?action=login` |
| AJAX forms | Off | Submit forms without page reload |
| User-chosen passwords | Off | Shows password fields on registration form |
| Auto-login | Off | Logs users in immediately after registering |
| Honeypot protection | On | Hidden field to catch bots |
| Subscriber redirect | *(empty)* | Where subscribers land after login. A page slug (e.g. `dashboard`) or full URL; empty = site home page. Admins/editors keep their normal redirect. |

### Rate Limiting

| Setting | Default | Description |
|---------|---------|-------------|
| Max attempts | 10 | Failed attempts before lockout (0 = disabled) |
| Lockout window | 15 min | Duration of lockout after max attempts reached |

### Per-Form Rate Limiting (v1.4.18+)

Each form has its own enable toggle and an optional threshold override. The override defaults to `0` which means "use the global Max attempts value above"; any positive integer takes precedence for that form only.

| Setting | Default | Description |
|---------|---------|-------------|
| Login — enabled | On | Toggle rate limiting on the login form |
| Login — Max attempts override | 0 (use global) | Per-form threshold; e.g. set to `5` for stricter login lockout |
| Registration — enabled | On | Toggle rate limiting on the registration form |
| Registration — Max attempts override | 0 (use global) | Per-form threshold |
| Lost Password — enabled | On | Toggle rate limiting on the lost-password form |
| Lost Password — Max attempts override | 0 (use global) | Per-form threshold |
| Reset Password — enabled | On | Toggle rate limiting on the reset-password form |
| Reset Password — Max attempts override | 0 (use global) | Per-form threshold |
| Count successful lost-password requests | Off | When enabled, every lost-password submission bumps the counter (not just failures). Closes the email-spam loophole where attackers spam reset emails to a known-valid address — `retrieve_password()` returns `true` on success (anti-enumeration), so the rate limiter would otherwise never engage. |

### Page Slugs

Each action URL slug is customisable: `login`, `logout`, `register`, `lostpassword` (default: `lost-password`), `resetpass` (default: `reset-password`).

### Page Management

| Button | Description |
|--------|-------------|
| Create Missing Pages | Creates real WordPress pages for any auth action that doesn't already have one. Existing pages with matching slugs are adopted, not duplicated. |
| Delete Auto-Created Pages | Removes only pages the plugin created. Pages you created manually and the plugin adopted are left intact. |

## Hooks & Filters

### Actions

| Hook | Parameters | Description |
|------|-----------|-------------|
| `zenlogau_init` | `ZENLOGAU $instance` | Fires when the core class initialises |
| `zenlogau_registered_action` | `string $name, array $args` | After an action is registered |
| `zenlogau_registered_form` | `string $name, ZENLOGAU_Form $form` | After a form is registered |
| `zenlogau_before_form_{name}` | `ZENLOGAU_Form $form` | Before form HTML renders |
| `zenlogau_after_form_{name}` | `ZENLOGAU_Form $form` | After form HTML renders |
| `zenlogau_{name}_form` | — | Inside form, for adding custom fields |
| `zenlogau_action_{action}` | — | Fires when a POST action is dispatched |
| `zenlogau_login_failed` | `string $username` | After a failed login attempt |
| `zenlogau_login_success` | `WP_User $user` | After successful login |
| `zenlogau_logout_success` | — | After successful logout |
| `zenlogau_registration_success` | `int $user_id` | After successful registration |
| `zenlogau_password_reset` | `WP_User $user` | After successful password reset |
| `zenlogau_account_updated` | `int $user_id, bool $password_changed` | After a user updates their profile via the Account form |
| `zenlogau_rate_limit_recorded` | `string $action, int $attempts` | After a rate-limit bump |
| `zenlogau_rate_limit_locked` | `string $action, string $ip, int $attempts` | Fires once, the moment an IP crosses the rate-limit threshold for an action (drives the activity-log "lockout" event) |
| `zenlogau_exclude_from_cache` | — | Fires on every auth page request — hook here to add custom cache exclusion logic |

### Filters

| Filter | Default | Description |
|--------|---------|-------------|
| `zenlogau_use_permalinks` | `true` | Toggle pretty URLs |
| `zenlogau_use_ajax` | `false` | Toggle AJAX form submission |
| `zenlogau_allow_user_passwords` | `false` | Toggle user-chosen passwords |
| `zenlogau_allow_auto_login` | `false` | Toggle auto-login after registration |
| `zenlogau_use_honeypot` | `true` | Toggle honeypot protection |
| `zenlogau_rate_limit` | `10` | Max failed attempts (global default) |
| `zenlogau_rate_limit_window` | `15` | Lockout window in minutes |
| `zenlogau_rate_limit_ip_headers` | `['REMOTE_ADDR']` | `$_SERVER` keys checked for client IP. Default is `REMOTE_ADDR` only (unforgeable); Cloudflare sites can prepend `HTTP_CF_CONNECTING_IP` *only if* the origin is locked to Cloudflare's IP ranges |
| `zenlogau_rate_limit_enabled_{action}` | `true` | Per-form rate-limit toggle. `{action}` = `login` \| `register` \| `lostpassword` \| `resetpass`. Return `false` to disable rate limiting on a specific form. |
| `zenlogau_rate_limit_{action}` | global default | Per-form threshold override. Only fires when a positive integer override is set in the admin panel. |
| `zenlogau_action_url` | — | Filter any action URL |
| `zenlogau_action_slug_{action}` | — | Filter a specific action's slug |
| `zenlogau_username_label` | — | Filter the username field label |
| `zenlogau_subscriber_redirect` | resolved from the **Subscriber redirect** setting (empty = `home_url()`) | Destination URL for subscribers after login, or when they attempt to reach wp-admin. Override to send subscribers anywhere. |
| `zenlogau_subscriber_login_redirect_to` | the resolved subscriber destination | Final say over where a restricted subscriber lands after login (params: `$redirect_to, $requested_redirect_to, $user`). |
| `zenlogau_widget_enabled` | per-widget option (default `true`) | Whether a given form widget is registered. Params: `$enabled, $widget` (`login`\|`register`\|`lostpassword`\|`resetpass`\|`account`). |
| `zenlogau_account_update_errors` | `WP_Error $errors, WP_User $user` | Add custom validation errors to an Account-form submission. |
| `zenlogau_account_display_name_options` | `array $options, WP_User $user` | Filter the choices in the Account form's "Display name publicly as" dropdown. |
| `zenlogau_activity_log_enabled` | option (default `true`) | Whether login-activity logging is active. |
| `zenlogau_activity_retention_days` | option (default `30`) | Days of activity history to keep before auto-pruning (0 = forever). |
| `zenlogau_logged_in_redirect` | Role-based (see below) | Final redirect URL for already-logged-in users visiting the login/register page |
| `zenlogau_logout_redirect` | `home_url()` | Redirect URL after logout |
| `zenlogau_login_url_exempt` | `false` | Return `true` to bypass ZENLOGAU's login URL rewriting (for OAuth/MCP flows) |
| `zenlogau_script_data` | — | Filter the JS config object |
| `zenlogau_form_links_{name}` | — | Filter action links below a form |
| `zenlogau_form_attributes_{name}` | — | Add custom HTML attributes to a form |
| `zenlogau_widget_form_output` | — | Filter rendered form HTML |
| `zenlogau_new_user_notification` | `'both'` | Control new-user email recipients |
| `zenlogau_page_actions` | — | Filter which actions get real WP pages |
| `zenlogau_ajax_success_data` | — | Filter AJAX success response data |
| `zenlogau_ajax_error_data` | — | Filter AJAX error response data |

#### Redirect priority order

Every front-end login runs WordPress's standard `login_redirect` filter (exactly as wp-login.php does), so membership/LMS and other plugins always get their say. After that filter:

1. `?redirect_to=` in the URL is the pre-filter default for the user's intended destination (e.g. bounced from a protected page); the Elementor widget's configured Redirect URL is used when no URL parameter is present.
2. **Other plugins** can override the destination via `login_redirect` — a non-admin destination they choose is respected.
3. Role-based guardrails:
   - **Restricted subscribers** are never landed in wp-admin: a non-admin destination is kept, but an empty or `/wp-admin/` target falls back to the **Subscriber redirect** setting (overridable via `zenlogau_subscriber_login_redirect_to`).
   - **Administrators, editors, and other roles** are unaffected — their normal flow works, including the "clicked Edit → bounced to login → back to Edit" round-trip.

## 3rd-Party Plugin Compatibility

Zen Login & Authentication fires the standard WordPress form hooks (`login_form`, `register_form`, `lostpassword_form`, `resetpass_form`) inside its forms. This means plugins that add fields to WordPress's native login — including 2FA plugins, CAPTCHA plugins, and social login plugins — will render their fields inside ZENLOGAU forms automatically.

An OAuth/REST exemption system is built in. When another plugin (e.g. WordPress MCP Bridge) calls `wp_login_url()` or `site_url('wp-login.php')` with a REST API redirect target, ZENLOGAU automatically stands aside and returns the native `/wp-login.php` URL so the OAuth handshake completes correctly. Plugins can also use the `zenlogau_login_url_exempt` filter for an explicit opt-out.

### Cache Plugin Compatibility (v1.4.16+)

Auth pages are automatically excluded from caching and stale entries are purged on version change:

| Plugin | Method |
|--------|--------|
| LiteSpeed Cache | `X-LiteSpeed-Cache-Control: no-cache` header + `litespeed_control_set_nocache` action + per-URL purge via `litespeed_purge_url` |
| Super Page Cache | `DONOTCACHEPAGE` constant |
| WP Rocket | `DONOTROCKETOPTIMIZE` constant |
| W3 Total Cache | `DONOTCACHEOBJECT` + `DONOTMINIFY` constants |
| WP Super Cache | `DONOTCACHEPAGE` constant |
| Any plugin | `Cache-Control: no-store` + `Pragma: no-cache` HTTP headers. Hook `zenlogau_exclude_from_cache` for custom logic. |

## File Structure

```
zen-login-authentication/
├── zen-login-authentication.php   Main plugin file (activation, deactivation, Elementor loader)
├── uninstall.php                 Cleanup on deletion (respects user-created pages)
├── README.md                     This file
├── index.html                    GitHub Pages landing page
├── admin/
│   ├── settings.php              Settings page with card-based UI
│   ├── hooks.php                 Admin hooks, slug sync, page management handlers
│   └── dashboard.php             "Login Activity" dashboard widget + clear-log handler
├── assets/
│   ├── scripts/
│   │   ├── frontend-auth.js   Frontend JS (AJAX, password toggle, strength meter)
│   │   └── frontend-auth.min.js
│   └── styles/
│       ├── frontend-auth.css       Frontend CSS (CSS custom properties, V4 compatible)
│       ├── frontend-auth.min.css
│       ├── frontend-auth-editor.css  Elementor editor-only styles
│       └── frontend-auth-admin.css   Settings page + dashboard widget styles (enqueued)
├── includes/
│   ├── class-fauth.php            Core singleton (actions & forms registry)
│   ├── class-fauth-form.php       Form class (fields, rendering, errors)
│   ├── options.php               Option accessors, page management, slug helpers
│   ├── helpers.php               Request helpers, URL helpers, honeypot, Elementor detection
│   ├── handlers.php              Form POST handlers (login, register, lostpassword, resetpass)
│   ├── hooks.php                 Frontend hooks, rewrites, URL filters, virtual pages, cache exclusion
│   ├── forms.php                 Form definitions (field registration, link filters)
│   ├── widgets.php               Classic WP_Widget classes (4 widgets)
│   ├── rate-limit.php            Rate limiting via transients
│   ├── activity-log.php          Login-activity table, logging, queries (dashboard widget data)
│   ├── crypto.php                AES-256-GCM at-rest encryption for the Google client secret
│   ├── google-login.php          Sign in with Google (server-side OpenID Connect)
│   ├── ms-hooks.php              Multisite-specific hooks
│   └── elementor/
│       └── class-fauth-elementor-widgets.php   Elementor Widget_Base classes (4 widgets)
└── languages/
    └── zen-login-authentication.pot
```

## Changelog

### 2.1.3

**Security hardening (post-audit)**

- Turning off two-factor authentication now requires a current authenticator or recovery code; TOTP codes can no longer be replayed within their validity window.
- Auto-login after registration now fires the standard `wp_login` hook, so new-device alerts and the activity log capture it.
- Passkey sign-in is rate-limited and validates the authenticator signature counter (clone detection for hardware keys).
- Changing the email address or password on the Account page now requires the current password (filterable for Google/passkey-only sites).
- Added GDPR personal-data export and erasure (devices, passkeys, two-factor, Google link).
- Bundled WebAuthn library hardened (direct-access guard + WordPress HTTP/filesystem/URL helpers); uninstall now clears plugin transients.

### 2.1.2

**Security & Review Hardening**

- All Elementor editor-preview templates now escape interpolated field values (titles, labels, button/link/toggle text, passkey and Google button text). The previews previously used raw Backbone interpolation that could render unescaped HTML inside the builder — an editor-context XSS vector.
- The Google sign-in button preview is built entirely from escaped, literal markup (removing a misleading "escaped during construction" suppression flagged in review).
- Added late output escaping / input unslashing throughout per the WordPress Plugin Directory review (Cloudflare request-method check, new-device cookie). No functional changes — forms, passkeys, two-factor, and new-device alerts behave exactly as in 2.1.1.

### 2.1.1

**Design & Polish**

- Redesigned login, registration, and account forms: polished default card surface, refined "security blue" palette, full-width primary buttons, and an outline secondary style — all still controllable from the Elementor style panel.
- The "Sign in with a passkey" button now has an icon and its own Normal/Hover style controls, and sits below the "or" divider alongside other sign-in options.
- Cleaner input focus (solid border + soft ring, no floating outline) and no stray hover border on buttons.
- The new-device alert email is now a styled, mobile-friendly HTML message with an optional admin-supplied custom body.
- Added missing password placeholder controls on the Account widget; the Elementor editor now previews the passkey, Google, two-factor, and passkeys/sessions sections.

### 2.1.0

**New: Passkeys (WebAuthn)**

- Users can add passkeys from the Account page and sign in with no password using Face ID, a fingerprint, Windows Hello, or a security key. Passwordless sign-ins are phishing-resistant and inherently multi-factor, skipping both the password and any two-factor step. Credentials are verified locally by the bundled lbuchs/WebAuthn library (MIT) using "none" attestation — no external request. Requires HTTPS.

**New: New-device login alerts**

- Emails the account owner the first time their account is signed in from an unrecognised device or browser, similar to the "new sign-in" alerts from Google or GitHub. Recognises devices with a long-lived cookie; uses your site's normal email (no external service). On by default; supports a custom HTML body.

### 2.0.0

**New: Two-factor authentication (TOTP)**

- Opt-in per user, managed entirely from the Account page: scan a QR code (or enter the setup key) in any authenticator app, confirm a code to enable it, and save one-time recovery codes. After the password, a second-factor step is required — enforced across the plugin's forms, AJAX submissions, and `wp-login.php`. REST/XML-RPC application passwords and Google sign-in are unaffected.
- The shared secret is stored encrypted at rest; recovery codes are stored hashed and single-use. The login challenge sets no auth cookie until the second factor verifies.
- The enrollment QR is rendered locally by the bundled qrcode-generator library (Kazuhiko Arase, MIT) — no external request.

**New: Sign out of other devices**

- From the Account page, a logged-in user can end every other active session for their account in one click; the current device stays signed in.

**Security**

- The subscriber-redirect setting now uses `esc_url_raw()` instead of `sanitize_text_field()` to keep full URLs intact.

### 1.9.0

**New: Security Hardening panel**

- **Username-enumeration protection** (on by default) — blocks `?author=N` author scans and the REST `/wp/v2/users` listing for logged-out visitors, and collapses login errors to one neutral message so a valid username is never confirmed. Applies to `wp-login.php` and the plugin's own forms.
- **XML-RPC lockdown** (optional) — disables `xmlrpc.php` to close the `system.multicall` brute-force amplifier and pingback abuse.

**New: Breached-password blocking (optional)**

- Rejects passwords found in the Have I Been Pwned corpus at registration, password reset, and account update. Uses the k-anonymity range API — only the first 5 characters of the password's SHA-1 hash leave the site, never the password — and fails open if the service is unreachable.

**New: Cloudflare Turnstile bot protection (optional)**

- Privacy-friendly bot challenge on the login, registration, and lost-password forms — both the plugin's forms and `wp-login.php`. Server-side token verification; the secret key is stored encrypted at rest.

### 1.8.1

- Removed the one-time pre-release prefix-migration routine (it had served its purpose; all known installs are already on the current `zenlogau` prefix). No change to normal installs or updates.

### 1.8.0

- Internal: the plugin's PHP/option prefix is now `zenlogau` (functions, classes, constants, options, transients, user/post meta, and the activity table). A one-time migration moves existing data automatically on update, so settings, Google credentials, pages, and the activity log carry over.

### 1.7.2

- Removed a read of WP Super Cache's `$file_prefix` global during the version-change cache purge. Auth pages already set `DONOTCACHEPAGE` (which WP Super Cache honours), so they are never cached and need no explicit purge.

### 1.7.1

- **Renamed** the plugin to **Zen Login & Authentication** (slug `zen-login-authentication`) for a distinctive WordPress.org directory name.
- All admin CSS is now **enqueued** via a registered stylesheet instead of inline `<style>` blocks (settings page + dashboard widget).
- Asset handles use a distinct prefix instead of the generic `frontend-auth`.
- The Google client secret is encrypted from its **raw** value — no lossy `sanitize_text_field()` pass that could alter secret characters.

### 1.7.0

**New: Login activity dashboard**

- A **"Zen Login & Authentication — Login Activity"** widget on the WordPress dashboard summarises, for the past 7 days, the number of successful logins, failed attempts, and rate-limit lockouts, plus the **top failed usernames**, the **most-blocked IPs**, and a colour-coded **recent-events** feed.
- Successful and failed logins are captured via core's `wp_login` / `wp_login_failed`, so the dashboard reflects every login path — the plugin's forms, `wp-login.php`, and programmatic `wp_signon()`. Lockouts come from the rate limiter via the new `zenlogau_rate_limit_locked` action.
- Events are stored in a dedicated `{prefix}_zenlogau_activity` table (created on activation/update, dropped on uninstall). **IPs are stored anonymised** — the same value the rate limiter buckets on (IPv4 last octet zeroed, IPv6 to /48).
- **Settings → Zen Login & Authentication → Login Activity**: toggle logging, set a retention window (default 30 days; old rows auto-prune), and a separate **Clear Activity Log** button. Cached in a 5-minute transient so the dashboard never hammers the table.

### 1.6.2

- **New:** per-widget on/off toggles under **Settings → Zen Login & Authentication → Widgets** for each form widget (Login, Registration, Lost Password, Reset Password, Account) — applies to both the Elementor panel and classic widget areas (filter: `zenlogau_widget_enabled`).
- The settings screen now uses the full admin content width instead of a fixed narrow column.

### 1.6.3

- **Improved:** post-login redirects run WordPress's standard `login_redirect` filter on every front-end login, so membership/LMS and other plugins are respected.
- **Improved:** restricted subscribers are never landed in wp-admin — a non-admin destination chosen by another plugin is kept; only an empty or `/wp-admin/` target falls back to the Subscriber redirect. Administrators/editors are unaffected, including the "clicked Edit → login → back to Edit" round-trip.

### 1.6.0 – 1.6.1

**New: Frontend account management**

- A new **Account page and widget** let logged-in users edit their **first name**, **last name**, a **"Display name publicly as"** dropdown (rebuilt live as you type, mirroring wp-admin's profile screen), **email**, and an optional **password change** — entirely on the frontend. Available as an Elementor widget, a classic widget, and an auto-created `/account/` page with the usual virtual-URL fallback.
- The username is shown read-only (like wp-admin). Email changes are validated for format and uniqueness; password changes follow the reset rules (match + 8-character minimum), keep the current session logged in, and sign out all other sessions.
- Guests visiting the account page are redirected to login and returned afterwards. The page is excluded from page caches like every other auth page.
- `ZENLOGAU_Form` gained a `select` field type; new filters `zenlogau_account_update_errors` and `zenlogau_account_display_name_options`; new action `zenlogau_account_updated`.
- **Fixed:** `<select>` fields no longer clip on themes (e.g. Astra) that force a fixed height on selects.

### 1.5.0

**Fixed**

- Required-field asterisks were invisible: the honeypot's catch-all CSS rule (`.fauth [aria-hidden="true"] { display:none }`) also hid the decorative asterisk spans (and would have hidden any inline SVG icon). The honeypot now has its own `fauth-hp` class and the rule is scoped to it.

**New: Sign in with Google (optional)**

- Server-side OpenID Connect authorization-code flow — no Google JavaScript on any page, no third-party PHP libraries. The button is a plain link; the CSRF `state` token is generated at click time on an `admin-post.php` endpoint, so cached pages can never serve a stale sign-in link, and nothing depends on rewrite rules.
- Settings: enable toggle, Client ID/Secret, "Allow new accounts" toggle, and the exact Authorized redirect URI to copy into Google Cloud Console.
- User provisioning: matched by stored Google account ID first, then by **verified** email (links the existing account); otherwise a new account is created with the site's default role (toggleable). New Google users get the same hidden-toolbar default as form registrations; the admin is notified (filterable via `zenlogau_google_new_user_notification`).
- Google logins run through `login_redirect`, so the Subscriber redirect, wp-admin blocking, and rate limiting all apply exactly like password logins.
- Security: single-use `state` stored server-side **and** bound to the browser via a `SameSite=Lax` cookie (blocks OAuth login-CSRF); `iss`/`aud`/`exp` claim validation; `email_verified` required; ID token received directly from Google's token endpoint over TLS (OIDC Core §3.1.3.7).
- Credential storage: the Client Secret is **encrypted at rest** with AES-256-GCM (`includes/crypto.php`), keyed from the `wp-config.php` salts — ciphertext in `wp_options` is useless without the config file. The settings field never re-displays the saved secret (blank = keep current). A plaintext value saved before this hardening is auto-migrated on first read. Power users can define `ZENLOGAU_GOOGLE_CLIENT_ID` / `ZENLOGAU_GOOGLE_CLIENT_SECRET` in `wp-config.php` instead, keeping credentials out of the database entirely. Caveat: rotating the WordPress salts invalidates the ciphertext — re-enter the secret afterwards.
- Elementor: Login and Register widgets get a "Show Google button" toggle, button-text override, an editor preview, and a Google Button style section (typography, padding, radius, normal/hover colors, divider color). New filters: `zenlogau_show_google_button`, `zenlogau_google_button_text`, `zenlogau_google_redirect_to`, `zenlogau_google_remember`, `zenlogau_google_allow_registration`, `zenlogau_google_enabled`.

### 1.4.23

- **Fixed:** the Elementor editor preview now shows the in-field password toggle layout, matching the front end — the preview templates were missing the `fauth-field-wrap--password` modifier class that the overlay CSS keys off.

### 1.4.22

**Design**

- Refreshed the **default form styling** for a modern, polished out-of-the-box look — softer rounded inputs/buttons (`10px`), refined focus rings (accent border + soft glow), fully-rounded tinted status notices, an updated password strength meter, a brand-tinted "Remember Me" checkbox (`accent-color`), and a cleaner password field (label above, with the Show/Hide toggle **inside** the field's right edge so the input stays full-width like the others).
- Everything remains overridable via the `--fauth-*` CSS custom properties and the Elementor style controls. Applies to all four forms and every widget type (Elementor, classic sidebar, and virtual pages), since they share one stylesheet.
- **Fixed (Elementor):** the Form Container styling (background, border, padding, radius, shadow) now wraps the **form title** too — it previously rendered outside the styled container because those controls targeted `.fauth-form` instead of the outer `.fauth-form-wrap`.

### 1.4.20

**Subscriber handling**

- **New:** subscribers who register through the plugin have the front-end admin toolbar ("Show Toolbar when viewing site") hidden by default. It's a default preference (stored as `show_admin_bar_front` user meta) they can re-enable from their profile; filterable via `zenlogau_hide_admin_bar_on_register`.
- **New:** subscribers are blocked from `wp-admin` and redirected to the Subscriber redirect destination (site home by default). `admin-ajax.php` is exempt so front-end AJAX keeps working.
- **Fixed:** the Subscriber redirect now applies to **every** login path — the front-end form, `wp-login.php`, and third-party login flows — via a priority-100 `login_redirect` filter. Previously the destination was only enforced inside the plugin's own login handler, so another plugin (security/membership) or a non-plugin login could silently override it.
- The "restricted subscriber" definition is centralized in `zenlogau_user_is_restricted_subscriber()` and filterable via `zenlogau_is_restricted_subscriber`.

**Other**

- **Fixed:** the "Settings" action link on the Plugins page now resolves the plugin basename dynamically (`plugin_basename()`), so it works regardless of the installed folder name.
- Tested up to WordPress 7.0.

### 1.4.19

**Security & Bug Fixes**

- **Medium (regression fix):** Reverted the default rate-limit IP source back to `REMOTE_ADDR` only. 1.4.18 changed the default to try `HTTP_CF_CONNECTING_IP` first, which is spoofable on any site not actually behind Cloudflare — an attacker could send a different forged header on each request to land in a fresh rate-limit bucket and bypass throttling entirely. This restores the 1.4.11 behaviour. Cloudflare sites can opt back in with `add_filter('zenlogau_rate_limit_ip_headers', fn() => ['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR'])`, and should only do so with the origin firewall restricted to Cloudflare's IP ranges.
- **Medium (data loss):** Hardened uninstall page cleanup. Older versions force-deleted *every* stored auth page when the plugin was deleted (e.g. during a deactivate → delete → reinstall "replace"), including pages built in Elementor. Uninstall now deletes a page only when the plugin created it (`_zenlogau_auto_created`), it was never edited in Elementor, and it has no content — adopted pages and any page you've touched are always kept. Stored page-ID references are removed either way.

**Changes**

- **Auto page setup on activation (adopt-or-create).** On install the plugin again creates a real page for each auth action — but now checks each default slug first: if a page already exists there it is reused as-is; otherwise a new page is created. Reused pages are never flagged for deletion, and the routine is idempotent, so activate/deactivate cycles can't duplicate pages (the duplication that caused auto-creation to be disabled in 1.4.16 cannot recur). The **Create Missing Pages** / **Delete Auto-Created Pages** buttons remain for manual control.
- **Configurable subscriber redirect.** Replaced the hardcoded `/instructor_dashboard/` default with a **Subscriber redirect** field under **Settings → Zen Login & Authentication → General**. Enter a page slug or full URL, or leave it empty to send subscribers to the site home page. The `zenlogau_subscriber_redirect` filter still works.
- **Housekeeping:** removed an unreachable duplicate guard in `zenlogau_filter_site_url()`, removed an empty admin-enqueue no-op, switched a `DOING_AJAX` constant check to `wp_doing_ajax()`, and corrected `current_time('mysql', 1)` to `current_time('mysql', true)`. No behaviour change.

### 1.4.18

**Security & Bug Fixes**

- **Medium:** Closed the lost-password email-spam loophole. WordPress core's `retrieve_password()` returns `true` on success — including for unknown email addresses (anti-enumeration behaviour since WP 5.5). This meant a determined attacker spamming reset emails to a single known-valid address bypassed the rate limiter entirely: every call returned `true`, the counter was cleared on success, and emails went out unchecked. The new "Count successful lost-password requests" toggle (default off for backward compatibility) bumps the counter on every submission and skips the success-clear path, so attempt #11 from the same IP gets blocked regardless of whether the email is valid.
- **Medium:** Updated default IP-detection header order for Cloudflare deployments. `zenlogau_rate_limit_get_ip()` now tries `HTTP_CF_CONNECTING_IP` first, then `REMOTE_ADDR`. On Cloudflare-fronted sites this means rate-limit transient keys are derived from the real visitor IP instead of pooling all attempts behind a handful of Cloudflare edge-node IPs (which would have caused legitimate users to be blocked by attackers sharing the same edge node). On non-Cloudflare servers, override via `add_filter('zenlogau_rate_limit_ip_headers', fn() => ['REMOTE_ADDR'])` to prevent header spoofing.
- **Low:** Fixed admin panel checkboxes silently failing to save when unchecked. WordPress's options.php only updates options that are present in `$_POST`; an unchecked HTML checkbox doesn't submit any value, so unchecking a toggle wouldn't persist as `0`. Added paired hidden `value="0"` inputs before each new checkbox so unchecking actually saves.

**New Features**

- **Per-Form Rate Limiting panel** in **Zen Login & Authentication → Settings**. Each of the four forms (Login, Registration, Lost Password, Reset Password) gets:
  - An **enable/disable toggle** — turn rate limiting off for an individual form without affecting the others
  - A **Max attempts override** — leave at `0` to inherit the global default, or set a specific number (e.g. login=5, register=10, lostpassword=3) for per-form strictness
- **Two new filters**: `zenlogau_rate_limit_enabled_{action}` (override the per-form toggle in code) and `zenlogau_rate_limit_{action}` (override the per-form threshold in code).
- **Two new functions**: `zenlogau_rate_limit_action_enabled($action)` and `zenlogau_get_rate_limit_for($action)` — public helpers for themes/plugins that need to inspect the resolved per-action state.

### 1.4.17

**Maintenance**

- One-time database cleanup on upgrade from any earlier version. Runs once via `zenlogau_upgrade_cleanup_1_4_17()` — version-gated, idempotent, and skipped on fresh installs:
  - **Orphaned `zenlogau_slug_*` options**: scans every option matching `zenlogau_slug_*` and deletes any whose action name isn't in the known list (`login`, `logout`, `register`, `lostpassword`, `resetpass`). Catches debris from earlier configuration experiments such as `zenlogau_slug_dashboard`.
  - **Auth page revision pruning**: for each of the four real auth pages (login, register, lostpassword, resetpass), keeps the 5 newest revisions and deletes the rest via `wp_delete_post_revision()`. On Yogahub this reclaimed ~1.5 MB of `wp_postmeta` (Elementor stores a full copy of `_elementor_data` per revision).
- Hardened `uninstall.php` with a wildcard sweep that catches any remaining `zenlogau_slug_*` options not in the explicit list, so reinstall→uninstall cycles can't leave debris behind.

### 1.4.16

**Bug Fixes**

- **Critical:** Fixed blank login page on Elementor sites. `zenlogau_maybe_inject_form()` checked `trim($content) !== ''` to decide whether to inject the form. Elementor outputs empty wrapper divs (`<div class="elementor elementor-123">…</div>`) even on pages with no widgets, so this check always passed and the form was never injected. Fixed by changing the check to `trim(wp_strip_all_tags($content)) !== ''` — Elementor's structural markup no longer blocks injection.
- **Critical:** Fixed `?redirect_to=` being silently dropped after login. The login URL could carry `?redirect_to=/some-page/` but the form rendered with no hidden `redirect_to` field, so POST submissions had nothing to read — the handler fell through to `home_url()`. Fixed in two places: `zenlogau_maybe_inject_form()` now passes the URL parameter into `zenlogau_render_form()`, and `build_render_args()` in the Elementor widget now reads `$_GET['redirect_to']` first, taking priority over the editor-configured default redirect URL.
- **High:** Fixed stale page ID causing hard 404s. `zenlogau_get_page_id()` returned the stored integer even when the page had been deleted or trashed. Both `zenlogau_add_rewrite_rules()` and `zenlogau_the_posts()` trust this value and skip their fallback logic when it is non-zero — leaving `/login/` as a 404 with no rewrite rule and no virtual post. Fixed by validating the stored ID against a live, published `WP_Post`. Stale options are cleared automatically so the rewrite/virtual-page fallback takes over immediately.
- **High:** Fixed caching plugins serving stale 404s for auth pages. LiteSpeed Cache and Super Page Cache were caching 404 responses for auth URLs before rewrite rules were in place. After rules were flushed, WordPress served the page correctly but the cache kept returning the old 404. Fixed by: (1) emitting `Cache-Control: no-store` and `X-LiteSpeed-Cache-Control: no-cache` headers on every auth page request; (2) defining `DONOTCACHEPAGE`, `DONOTROCKETOPTIMIZE`, `DONOTCACHEOBJECT`, and `DONOTMINIFY`; (3) calling `litespeed_control_set_nocache` and `LiteSpeed_Cache_API::no_cache()`; (4) purging all auth page URLs from LiteSpeed Cache, WP Rocket, WP Super Cache, and W3 Total Cache on every plugin version change.
- **Medium:** Fixed rewrite rules flush happening too late after plugin update. The upgrade routine scheduled `flush_rewrite_rules()` on the `shutdown` hook, meaning rules were only written to the database at the end of the first page load — `/login/` would still 404 on that first request. Flush is now hooked at `init` priority 99, which runs after `zenlogau_add_rewrite_rules()` (priority 10) but still within the same init cycle, so rules are in the database before any template is rendered.
- **Medium:** Fixed `zenlogau_filter_site_url()` missing the MCP/OAuth REST exemption that `zenlogau_filter_login_url()` already had. The MCP Bridge plugin calls `site_url('wp-login.php')` directly — not `wp_login_url()` — so the exemption in the login URL filter never fired. ZENLOGAU rewrote the URL to the frontend `/log-in/` page, breaking the OAuth handshake. Fixed by applying `zenlogau_is_login_url_exempt()` inside `zenlogau_filter_site_url()` and extending the exemption to cover all non-Elementor `REST_REQUEST` contexts.

**New Features**

- **Subscriber redirect destination is now filterable** via `zenlogau_subscriber_redirect`. Subscribers are blocked from wp-admin and sent to this URL instead (default: `home_url('/instructor_dashboard/')`). Override from your theme or a snippet: `add_filter('zenlogau_subscriber_redirect', fn() => home_url('/dashboard/'));`
- **`zenlogau_exclude_from_cache` action** — fires on every auth page request. Hook here to add exclusion logic for custom or unlisted caching plugins.

### 1.4.15

**Bug Fixes**

- **Critical:** Added `the_content` filter (`zenlogau_maybe_inject_form`) that auto-renders the appropriate auth form on virtual pages and empty real ZENLOGAU pages. Previously, the virtual page system injected a `WP_Post` with empty `post_content`, so the theme rendered a blank page — the user never saw a login form unless they placed an Elementor widget or classic widget manually. The filter runs at priority 20 (after Elementor's priority 9 and WordPress core's priority 10–11), so Elementor pages with widgets are never affected. Handles edge cases: hides login form for logged-in users (unless `reauth=1`), shows "registration disabled" message, and shows "invalid reset link" error when key/login params are absent.
- **Medium:** Fixed `Undefined array key "key"` and `Undefined array key "login"` PHP warnings in both the Elementor Reset Password widget and the classic `ZENLOGAU_Reset_Password_Widget`. The previous `is_string()` guard used `$_GET['key'] ?? ''` for the null-coalesce check but then re-accessed `$_GET['key']` directly in the ternary true-branch — triggering the warning when the parameter was absent. Fixed by extracting to local variables first.

### 1.4.14

**Bug Fixes**

- **High (Security):** Fixed PHP 8.0+ fatal `TypeError` crash via array-valued HTTP parameters. An attacker could send `log[]=foo`, `key[]=bar`, or any other array-formatted parameter to crash form handlers — `sanitize_user()`, `sanitize_text_field()`, `sanitize_key()`, and `wp_sanitize_redirect()` all expect strings and throw a fatal `TypeError` when given arrays on PHP 8.0+. This was a denial-of-service vector that bypassed nonce verification (the crash occurred after the nonce check passed). Fixed across 7 files by adding `is_string()` guards to all direct `$_GET`/`$_POST`/`$_REQUEST` access points, and by changing the core `zenlogau_get_request_value()` helper to return an empty string for non-string input instead of passing raw arrays through.
- **Medium (Security):** Added missing honeypot check to the lost-password handler. The honeypot hidden field was rendered in the form HTML but `zenlogau_honeypot_is_spam()` was never called in `zenlogau_handle_lostpassword()`. This allowed bots to automate the lost-password form and trigger mass password-reset emails to arbitrary users. The handler now checks the honeypot before calling `retrieve_password()` and returns a fake success response to fool the bot — identical to the existing pattern in the registration handler.
- **Low:** Replaced deprecated `wp.passwordStrength.userInputBlacklist()` with `wp.passwordStrength.userInputDisallowedList()` in the password strength meter JavaScript. The old API was deprecated in WordPress 5.5.0 (Trac #50413) and logged a console warning on every keystroke. Since the plugin requires WP 6.5+, the replacement API is guaranteed available. Fixed in both the source and minified JS files.
- **Low:** Fixed `zenlogau_rate_limit_clear()` not deleting the companion `_ts` timestamp transient alongside the counter. After a successful login, the orphaned `_ts` transient caused `zenlogau_rate_limit_remaining_seconds()` to return a stale non-zero lockout duration even though the user was no longer locked out — misleading any theme or plugin using the public API to display retry timers.

### 1.4.13

**Bug Fixes**

- **High:** Fixed login redirect sending all roles (including admins, editors, authors, contributors) to `home_url()` or ignoring the `redirect_to` parameter. Previously, `zenlogau_maybe_redirect_logged_in_user()` blindly redirected every logged-in user visiting the login/register page to `admin_url()`, ignoring the `redirect_to` query parameter entirely. Now, the `redirect_to` parameter is honoured for privileged roles, and only subscribers are redirected away from `wp-admin`.
- **High:** Fixed login handler (`zenlogau_handle_login`) also using `admin_url()` as the default redirect for non-subscribers. Privileged users with no `redirect_to` now go to `home_url()`. If a privileged user was bounced from wp-admin (WordPress adds `?redirect_to=wp-admin/...`), that redirect is honoured exactly.

**Documentation Fixes**

- Fixed incorrect inline comment claiming `wp_send_new_user_notification_to_admin` was introduced in WP 4.6 — the correct version is WP 6.1.0.
- Fixed misleading comment in main plugin file referencing `load_plugin_textdomain()` as "soft-deprecated in WP 6.7" — it was not deprecated but made redundant by the deferred translation loading system.
- Fixed WP version guard comment inconsistency (referenced "6.2+ minimum" when the actual requirement is 6.5+).
- Updated `zenlogau_logged_in_redirect` filter documentation to reflect the role-based redirect logic.

### 1.4.12

**Bug Fixes**

- **Critical:** Removed automatic page creation on plugin activation/reactivation. Previously, deactivating and reactivating the plugin created duplicate Login, Register, Lost Password, and Reset Password pages every cycle. Pages are now managed manually via a new **Page Management** panel in the settings screen with "Create Missing Pages" and "Delete Auto-Created Pages" buttons.
- **Critical:** Fixed `render_form_title()` in Elementor widgets — `add_render_attribute()` was called with the return value of `get_render_attribute_string()` as the attribute name, producing malformed HTML on every widget with a form title.
- **High:** Fixed password toggle click listeners stacking on Elementor pages. `document.addEventListener('click', ...)` was inside `bindPasswordToggle()` which runs on every Elementor `element_ready` re-render. After N renders, N+1 identical listeners caused rapid toggle flicker. Moved to a single document-level delegate registered once at boot.
- **High:** Fixed Elementor `element_ready` hooks never registering. Used native `addEventListener` for `elementor/frontend/init` but Elementor fires this via jQuery's event system. Changed to `jQuery(window).on(...)`.
- **Medium:** Fixed `uninstall.php` deleting user-created pages. Now tracks auto-created pages via `_zenlogau_auto_created` post meta and only deletes those.
- **Low:** Corrected `Group_Control_Box_Shadow` comments incorrectly stating it is "Pro-only" — it is available in free Elementor.

### 1.4.11

- Fixed double admin notification email on registration when user-chosen passwords are enabled.
- Fixed hardcoded `post_author => 1` in auto-created pages.
- Fixed IP address spoofing in rate limiter — defaults to `REMOTE_ADDR` only.
- Added rate limiting to the reset-password handler.
- Added `reauth=1` support for re-authentication without redirect loops.
- Fixed OAuth/REST exemption for login URL rewriting (MCP Bridge compatibility).

### 1.4.8

- Fixed triple-brace in placeholder HTML attributes in Elementor content templates.
- Wired `bindPasswordToggle()` and `bindPasswordStrength()` to Elementor `element_ready` lifecycle.
- Replaced `outline:none` with `:focus/:focus-visible` pair (WCAG 2.2).
- Added `Group_Control_Typography` for error/success messages, Remember Me, and strength meter.
- Added text-decoration control for action links.
- Renamed heading control IDs to `zenlogau_h_*` to avoid cross-widget collision.

### 1.4.3

- Fixed `const fauthConfig` declared twice causing SyntaxError on Elementor pages.
- Fixed Elementor editor filter leak — closures inside `render()` now cleaned up immediately.

### 1.4.0

- Real WordPress pages for auth actions (Elementor Theme Builder compatibility).
- Full Elementor style panel with 15+ control sections.
- Custom label, placeholder, button text, and link URL overrides per widget instance.
- Password toggle with per-field Show/Hide text via data attributes.
- Form self-posting for reliable AJAX on Elementor pages.
- Elementor V4 Atomic Widgets compatibility (`has_widget_inner_wrapper(): false`).

### 1.2.0

- Initial public release.

## License

GPL-2.0-or-later — https://www.gnu.org/licenses/gpl-2.0.html
