# WP Frontend Auth

Secure, accessible frontend login, registration, and password recovery forms for WordPress — with rate limiting, honeypot protection, AJAX support, native Elementor widgets, and full cache-plugin compatibility.

## Description

WP Frontend Auth replaces the default `wp-login.php` experience with clean, theme-integrated forms that live on your actual site. It works out of the box on any WordPress theme and ships with first-class Elementor support — four drag-and-drop widgets that fit into any page builder layout with full Theme Builder compatibility.

### What It Does

- **Login form** with username, email, or either — configurable from Settings.
- **Registration form** with optional user-chosen passwords and auto-login.
- **Lost Password / Reset Password** forms with full email flow integration.
- **URL rewriting** — all `wp-login.php` links site-wide are transparently redirected to your frontend pages.
- **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
- **Smart redirects** — `?redirect_to=` is fully honoured on both virtual and Elementor pages. Subscribers are blocked from wp-admin and sent to a configurable destination — set a page slug or URL under **Settings → Frontend Auth → Subscriber redirect** (default: the site home page; also filterable via `wpfa_subscriber_redirect`). Privileged users always land where they intended.
- **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache. Stale 404 cache entries are purged automatically on plugin update.

### Security

- **Nonce verification** on every form submission.
- **Rate limiting** — configurable max attempts per IP with lockout window (uses transients). Applied to all four handlers: login, register, lost-password, and reset-password.
- **Honeypot spam protection** — rotating hidden field (hourly key rotation via HMAC) catches bots. Trapped submissions get a fake success response — bots never know they failed.
- **IP anonymisation** — rate-limit keys hash truncated IPs (last octet zeroed for IPv4, /48 for IPv6). The client IP is read from `REMOTE_ADDR` only by default, because forwarded headers like `HTTP_CF_CONNECTING_IP` / `X-Forwarded-For` are spoofable on any server not actually behind that proxy (an attacker could rotate the header to land in a fresh bucket and dodge the throttle). Sites genuinely behind Cloudflare — with the origin firewall locked to Cloudflare's IP ranges — can opt the real-client header back in: `add_filter('wpfa_rate_limit_ip_headers', fn() => ['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR']);`
- **No password pre-population** — password fields are never re-filled from POST data.
- **bcrypt-compatible** — uses `wp_set_password()` / `wp_signon()` which support WP 6.8+ bcrypt hashing.
- **Password minimum length** — reset and registration passwords require at least 8 characters.

### Elementor Integration

Four native `Widget_Base` widgets registered via `elementor/widgets/register`:

| Widget | Class | Description |
|--------|-------|-------------|
| Login Form | `WPFA_Elementor_Login_Widget` | Login form with custom labels, placeholders, toggle text, and link overrides. Hidden when logged in (unless `reauth=1`). Automatically picks up `?redirect_to=` from the URL, taking priority over the editor-configured default. |
| Registration Form | `WPFA_Elementor_Register_Widget` | Registration form with password + confirm fields when user-chosen passwords are enabled. Editor placeholder when registration is disabled. |
| Lost Password Form | `WPFA_Elementor_Lost_Password_Widget` | Password recovery request form. |
| Reset Password Form | `WPFA_Elementor_Reset_Password_Widget` | Password reset form — reads `?key=&login=` from the URL. Shows invalid-link message when parameters are missing, with an editor preview of the form fields. |

All widgets share a comprehensive Elementor style panel: form container (width, max-width, alignment, background, border, radius, shadow, padding), title typography, label styling, input fields (text colour, placeholder colour, background, border, focus state with glow), button (normal + hover tabs with typography, padding, radius, shadow, transition), action links, messages/errors, password toggle (normal + hover tabs), and checkbox styling.

Only the Reset Password widget declares `is_dynamic_content(): true` (it reads `$_GET` parameters). The other three return `false` for optimal Elementor caching.

#### Page Management

On activation the plugin sets up a real WordPress page for each auth action so Elementor Theme Builder conditions work correctly (Singular > Page targeting by ID). For each action it checks the default slug: if a page already exists there it is **reused** as-is (never modified, and never deleted on uninstall); otherwise a new page is **created**. The process is idempotent, so activate/deactivate cycles never duplicate pages. The **Page Management** panel in the settings screen lets you re-create any missing pages or remove the auto-created ones manually. The plugin also works without real pages via its virtual URL rewrite system.

### Classic Widgets

Four `WP_Widget` subclasses are also registered for classic sidebar/widget-area use:

- `WPFA_Login_Widget`
- `WPFA_Register_Widget`
- `WPFA_Lost_Password_Widget`
- `WPFA_Reset_Password_Widget`

All expose `show_instance_in_rest` for the WP 5.8+ block-based Widgets screen.

## Requirements

| Dependency | Minimum |
|-----------|---------|
| WordPress | 6.5+ |
| PHP | 8.0+ |
| Elementor | Optional — plugin works without it |

## Installation

1. Upload the `wp-frontend-auth` folder to `/wp-content/plugins/`.
2. Activate the plugin through **Plugins → Installed Plugins**.
3. Go to **Frontend Auth** in the admin sidebar to configure options.
4. *(Optional)* The auth pages are created automatically on activation. If you later delete some and want them back, click **Create Missing Pages** in the Page Management section.
5. Rewrite rules are flushed automatically on the first page load after activation (v1.4.16+). If needed, go to **Settings → Permalinks** and click **Save Changes**, or run `wp rewrite flush`.
6. *(Elementor users)* Open any page in the Elementor editor and search for "Login Form", "Registration Form", etc. in the widget panel under the **Frontend Auth** category.

## Settings

All settings are under the **Frontend Auth** admin menu:

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
| `wpfa_init` | `WPFA $instance` | Fires when the core class initialises |
| `wpfa_registered_action` | `string $name, array $args` | After an action is registered |
| `wpfa_registered_form` | `string $name, WPFA_Form $form` | After a form is registered |
| `wpfa_before_form_{name}` | `WPFA_Form $form` | Before form HTML renders |
| `wpfa_after_form_{name}` | `WPFA_Form $form` | After form HTML renders |
| `wpfa_{name}_form` | — | Inside form, for adding custom fields |
| `wpfa_action_{action}` | — | Fires when a POST action is dispatched |
| `wpfa_login_failed` | `string $username` | After a failed login attempt |
| `wpfa_login_success` | `WP_User $user` | After successful login |
| `wpfa_logout_success` | — | After successful logout |
| `wpfa_registration_success` | `int $user_id` | After successful registration |
| `wpfa_password_reset` | `WP_User $user` | After successful password reset |
| `wpfa_rate_limit_recorded` | `string $action, int $attempts` | After a rate-limit bump |
| `wpfa_exclude_from_cache` | — | Fires on every auth page request — hook here to add custom cache exclusion logic |

### Filters

| Filter | Default | Description |
|--------|---------|-------------|
| `wpfa_use_permalinks` | `true` | Toggle pretty URLs |
| `wpfa_use_ajax` | `false` | Toggle AJAX form submission |
| `wpfa_allow_user_passwords` | `false` | Toggle user-chosen passwords |
| `wpfa_allow_auto_login` | `false` | Toggle auto-login after registration |
| `wpfa_use_honeypot` | `true` | Toggle honeypot protection |
| `wpfa_rate_limit` | `10` | Max failed attempts (global default) |
| `wpfa_rate_limit_window` | `15` | Lockout window in minutes |
| `wpfa_rate_limit_ip_headers` | `['REMOTE_ADDR']` | `$_SERVER` keys checked for client IP. Default is `REMOTE_ADDR` only (unforgeable); Cloudflare sites can prepend `HTTP_CF_CONNECTING_IP` *only if* the origin is locked to Cloudflare's IP ranges |
| `wpfa_rate_limit_enabled_{action}` | `true` | Per-form rate-limit toggle. `{action}` = `login` \| `register` \| `lostpassword` \| `resetpass`. Return `false` to disable rate limiting on a specific form. |
| `wpfa_rate_limit_{action}` | global default | Per-form threshold override. Only fires when a positive integer override is set in the admin panel. |
| `wpfa_action_url` | — | Filter any action URL |
| `wpfa_action_slug_{action}` | — | Filter a specific action's slug |
| `wpfa_username_label` | — | Filter the username field label |
| `wpfa_subscriber_redirect` | resolved from the **Subscriber redirect** setting (empty = `home_url()`) | Destination URL for subscribers after login, or when they attempt to reach wp-admin. Override to send subscribers anywhere. |
| `wpfa_logged_in_redirect` | Role-based (see below) | Final redirect URL for already-logged-in users visiting the login/register page |
| `wpfa_logout_redirect` | `home_url()` | Redirect URL after logout |
| `wpfa_login_url_exempt` | `false` | Return `true` to bypass WPFA's login URL rewriting (for OAuth/MCP flows) |
| `wpfa_script_data` | — | Filter the JS config object |
| `wpfa_form_links_{name}` | — | Filter action links below a form |
| `wpfa_form_attributes_{name}` | — | Add custom HTML attributes to a form |
| `wpfa_widget_form_output` | — | Filter rendered form HTML |
| `wpfa_new_user_notification` | `'both'` | Control new-user email recipients |
| `wpfa_page_actions` | — | Filter which actions get real WP pages |
| `wpfa_ajax_success_data` | — | Filter AJAX success response data |
| `wpfa_ajax_error_data` | — | Filter AJAX error response data |

#### Redirect priority order

After a successful login, the destination is resolved in this order:

1. `?redirect_to=` in the URL — always wins (user's actual intended destination, e.g. bounced from a protected page).
2. Redirect URL configured in the Elementor widget editor panel — used when no URL parameter is present.
3. Role-based fallback:
   - **Subscriber** → the **Subscriber redirect** setting (a slug or URL; empty = `home_url()`), overridable via the `wpfa_subscriber_redirect` filter. Subscribers can never reach wp-admin regardless of `redirect_to`.
   - **All other roles** → `home_url()` when no redirect is specified. If WordPress bounced them from wp-admin (adding `?redirect_to=wp-admin/...` to the login URL), that redirect is honoured exactly.

## 3rd-Party Plugin Compatibility

WP Frontend Auth fires the standard WordPress form hooks (`login_form`, `register_form`, `lostpassword_form`, `resetpass_form`) inside its forms. This means plugins that add fields to WordPress's native login — including 2FA plugins, CAPTCHA plugins, and social login plugins — will render their fields inside WPFA forms automatically.

An OAuth/REST exemption system is built in. When another plugin (e.g. WordPress MCP Bridge) calls `wp_login_url()` or `site_url('wp-login.php')` with a REST API redirect target, WPFA automatically stands aside and returns the native `/wp-login.php` URL so the OAuth handshake completes correctly. Plugins can also use the `wpfa_login_url_exempt` filter for an explicit opt-out.

### Cache Plugin Compatibility (v1.4.16+)

Auth pages are automatically excluded from caching and stale entries are purged on version change:

| Plugin | Method |
|--------|--------|
| LiteSpeed Cache | `X-LiteSpeed-Cache-Control: no-cache` header + `litespeed_control_set_nocache` action + per-URL purge via `litespeed_purge_url` |
| Super Page Cache | `DONOTCACHEPAGE` constant |
| WP Rocket | `DONOTROCKETOPTIMIZE` constant |
| W3 Total Cache | `DONOTCACHEOBJECT` + `DONOTMINIFY` constants |
| WP Super Cache | `DONOTCACHEPAGE` constant |
| Any plugin | `Cache-Control: no-store` + `Pragma: no-cache` HTTP headers. Hook `wpfa_exclude_from_cache` for custom logic. |

## File Structure

```
wp-frontend-auth/
├── wp-frontend-auth.php          Main plugin file (activation, deactivation, Elementor loader)
├── uninstall.php                 Cleanup on deletion (respects user-created pages)
├── README.md                     This file
├── index.html                    GitHub Pages landing page
├── admin/
│   ├── settings.php              Settings page with card-based UI
│   └── hooks.php                 Admin hooks, slug sync, page management handlers
├── assets/
│   ├── scripts/
│   │   ├── wp-frontend-auth.js   Frontend JS (AJAX, password toggle, strength meter)
│   │   └── wp-frontend-auth.min.js
│   └── styles/
│       ├── wp-frontend-auth.css       Frontend CSS (CSS custom properties, V4 compatible)
│       ├── wp-frontend-auth.min.css
│       └── wp-frontend-auth-editor.css  Elementor editor-only styles
├── includes/
│   ├── class-wpfa.php            Core singleton (actions & forms registry)
│   ├── class-wpfa-form.php       Form class (fields, rendering, errors)
│   ├── options.php               Option accessors, page management, slug helpers
│   ├── helpers.php               Request helpers, URL helpers, honeypot, Elementor detection
│   ├── handlers.php              Form POST handlers (login, register, lostpassword, resetpass)
│   ├── hooks.php                 Frontend hooks, rewrites, URL filters, virtual pages, cache exclusion
│   ├── forms.php                 Form definitions (field registration, link filters)
│   ├── widgets.php               Classic WP_Widget classes (4 widgets)
│   ├── rate-limit.php            Rate limiting via transients
│   ├── ms-hooks.php              Multisite-specific hooks
│   └── elementor/
│       └── class-wpfa-elementor-widgets.php   Elementor Widget_Base classes (4 widgets)
└── languages/
    └── .gitkeep
```

## Changelog

### 1.4.19

**Security & Bug Fixes**

- **Medium (regression fix):** Reverted the default rate-limit IP source back to `REMOTE_ADDR` only. 1.4.18 changed the default to try `HTTP_CF_CONNECTING_IP` first, which is spoofable on any site not actually behind Cloudflare — an attacker could send a different forged header on each request to land in a fresh rate-limit bucket and bypass throttling entirely. This restores the 1.4.11 behaviour. Cloudflare sites can opt back in with `add_filter('wpfa_rate_limit_ip_headers', fn() => ['HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR'])`, and should only do so with the origin firewall restricted to Cloudflare's IP ranges.
- **Medium (data loss):** Hardened uninstall page cleanup. Older versions force-deleted *every* stored auth page when the plugin was deleted (e.g. during a deactivate → delete → reinstall "replace"), including pages built in Elementor. Uninstall now deletes a page only when the plugin created it (`_wpfa_auto_created`), it was never edited in Elementor, and it has no content — adopted pages and any page you've touched are always kept. Stored page-ID references are removed either way.

**Changes**

- **Auto page setup on activation (adopt-or-create).** On install the plugin again creates a real page for each auth action — but now checks each default slug first: if a page already exists there it is reused as-is; otherwise a new page is created. Reused pages are never flagged for deletion, and the routine is idempotent, so activate/deactivate cycles can't duplicate pages (the duplication that caused auto-creation to be disabled in 1.4.16 cannot recur). The **Create Missing Pages** / **Delete Auto-Created Pages** buttons remain for manual control.
- **Configurable subscriber redirect.** Replaced the hardcoded `/instructor_dashboard/` default with a **Subscriber redirect** field under **Settings → Frontend Auth → General**. Enter a page slug or full URL, or leave it empty to send subscribers to the site home page. The `wpfa_subscriber_redirect` filter still works.
- **Housekeeping:** removed an unreachable duplicate guard in `wpfa_filter_site_url()`, removed an empty admin-enqueue no-op, switched a `DOING_AJAX` constant check to `wp_doing_ajax()`, and corrected `current_time('mysql', 1)` to `current_time('mysql', true)`. No behaviour change.

### 1.4.18

**Security & Bug Fixes**

- **Medium:** Closed the lost-password email-spam loophole. WordPress core's `retrieve_password()` returns `true` on success — including for unknown email addresses (anti-enumeration behaviour since WP 5.5). This meant a determined attacker spamming reset emails to a single known-valid address bypassed the rate limiter entirely: every call returned `true`, the counter was cleared on success, and emails went out unchecked. The new "Count successful lost-password requests" toggle (default off for backward compatibility) bumps the counter on every submission and skips the success-clear path, so attempt #11 from the same IP gets blocked regardless of whether the email is valid.
- **Medium:** Updated default IP-detection header order for Cloudflare deployments. `wpfa_rate_limit_get_ip()` now tries `HTTP_CF_CONNECTING_IP` first, then `REMOTE_ADDR`. On Cloudflare-fronted sites this means rate-limit transient keys are derived from the real visitor IP instead of pooling all attempts behind a handful of Cloudflare edge-node IPs (which would have caused legitimate users to be blocked by attackers sharing the same edge node). On non-Cloudflare servers, override via `add_filter('wpfa_rate_limit_ip_headers', fn() => ['REMOTE_ADDR'])` to prevent header spoofing.
- **Low:** Fixed admin panel checkboxes silently failing to save when unchecked. WordPress's options.php only updates options that are present in `$_POST`; an unchecked HTML checkbox doesn't submit any value, so unchecking a toggle wouldn't persist as `0`. Added paired hidden `value="0"` inputs before each new checkbox so unchecking actually saves.

**New Features**

- **Per-Form Rate Limiting panel** in **Frontend Auth → Settings**. Each of the four forms (Login, Registration, Lost Password, Reset Password) gets:
  - An **enable/disable toggle** — turn rate limiting off for an individual form without affecting the others
  - A **Max attempts override** — leave at `0` to inherit the global default, or set a specific number (e.g. login=5, register=10, lostpassword=3) for per-form strictness
- **Two new filters**: `wpfa_rate_limit_enabled_{action}` (override the per-form toggle in code) and `wpfa_rate_limit_{action}` (override the per-form threshold in code).
- **Two new functions**: `wpfa_rate_limit_action_enabled($action)` and `wpfa_get_rate_limit_for($action)` — public helpers for themes/plugins that need to inspect the resolved per-action state.

### 1.4.17

**Maintenance**

- One-time database cleanup on upgrade from any earlier version. Runs once via `wpfa_upgrade_cleanup_1_4_17()` — version-gated, idempotent, and skipped on fresh installs:
  - **Orphaned `wpfa_slug_*` options**: scans every option matching `wpfa_slug_*` and deletes any whose action name isn't in the known list (`login`, `logout`, `register`, `lostpassword`, `resetpass`). Catches debris from earlier configuration experiments such as `wpfa_slug_dashboard`.
  - **Auth page revision pruning**: for each of the four real auth pages (login, register, lostpassword, resetpass), keeps the 5 newest revisions and deletes the rest via `wp_delete_post_revision()`. On Yogahub this reclaimed ~1.5 MB of `wp_postmeta` (Elementor stores a full copy of `_elementor_data` per revision).
- Hardened `uninstall.php` with a wildcard sweep that catches any remaining `wpfa_slug_*` options not in the explicit list, so reinstall→uninstall cycles can't leave debris behind.

### 1.4.16

**Bug Fixes**

- **Critical:** Fixed blank login page on Elementor sites. `wpfa_maybe_inject_form()` checked `trim($content) !== ''` to decide whether to inject the form. Elementor outputs empty wrapper divs (`<div class="elementor elementor-123">…</div>`) even on pages with no widgets, so this check always passed and the form was never injected. Fixed by changing the check to `trim(wp_strip_all_tags($content)) !== ''` — Elementor's structural markup no longer blocks injection.
- **Critical:** Fixed `?redirect_to=` being silently dropped after login. The login URL could carry `?redirect_to=/some-page/` but the form rendered with no hidden `redirect_to` field, so POST submissions had nothing to read — the handler fell through to `home_url()`. Fixed in two places: `wpfa_maybe_inject_form()` now passes the URL parameter into `wpfa_render_form()`, and `build_render_args()` in the Elementor widget now reads `$_GET['redirect_to']` first, taking priority over the editor-configured default redirect URL.
- **High:** Fixed stale page ID causing hard 404s. `wpfa_get_page_id()` returned the stored integer even when the page had been deleted or trashed. Both `wpfa_add_rewrite_rules()` and `wpfa_the_posts()` trust this value and skip their fallback logic when it is non-zero — leaving `/login/` as a 404 with no rewrite rule and no virtual post. Fixed by validating the stored ID against a live, published `WP_Post`. Stale options are cleared automatically so the rewrite/virtual-page fallback takes over immediately.
- **High:** Fixed caching plugins serving stale 404s for auth pages. LiteSpeed Cache and Super Page Cache were caching 404 responses for auth URLs before rewrite rules were in place. After rules were flushed, WordPress served the page correctly but the cache kept returning the old 404. Fixed by: (1) emitting `Cache-Control: no-store` and `X-LiteSpeed-Cache-Control: no-cache` headers on every auth page request; (2) defining `DONOTCACHEPAGE`, `DONOTROCKETOPTIMIZE`, `DONOTCACHEOBJECT`, and `DONOTMINIFY`; (3) calling `litespeed_control_set_nocache` and `LiteSpeed_Cache_API::no_cache()`; (4) purging all auth page URLs from LiteSpeed Cache, WP Rocket, WP Super Cache, and W3 Total Cache on every plugin version change.
- **Medium:** Fixed rewrite rules flush happening too late after plugin update. The upgrade routine scheduled `flush_rewrite_rules()` on the `shutdown` hook, meaning rules were only written to the database at the end of the first page load — `/login/` would still 404 on that first request. Flush is now hooked at `init` priority 99, which runs after `wpfa_add_rewrite_rules()` (priority 10) but still within the same init cycle, so rules are in the database before any template is rendered.
- **Medium:** Fixed `wpfa_filter_site_url()` missing the MCP/OAuth REST exemption that `wpfa_filter_login_url()` already had. The MCP Bridge plugin calls `site_url('wp-login.php')` directly — not `wp_login_url()` — so the exemption in the login URL filter never fired. WPFA rewrote the URL to the frontend `/log-in/` page, breaking the OAuth handshake. Fixed by applying `wpfa_is_login_url_exempt()` inside `wpfa_filter_site_url()` and extending the exemption to cover all non-Elementor `REST_REQUEST` contexts.

**New Features**

- **Subscriber redirect destination is now filterable** via `wpfa_subscriber_redirect`. Subscribers are blocked from wp-admin and sent to this URL instead (default: `home_url('/instructor_dashboard/')`). Override from your theme or a snippet: `add_filter('wpfa_subscriber_redirect', fn() => home_url('/dashboard/'));`
- **`wpfa_exclude_from_cache` action** — fires on every auth page request. Hook here to add exclusion logic for custom or unlisted caching plugins.

### 1.4.15

**Bug Fixes**

- **Critical:** Added `the_content` filter (`wpfa_maybe_inject_form`) that auto-renders the appropriate auth form on virtual pages and empty real WPFA pages. Previously, the virtual page system injected a `WP_Post` with empty `post_content`, so the theme rendered a blank page — the user never saw a login form unless they placed an Elementor widget or classic widget manually. The filter runs at priority 20 (after Elementor's priority 9 and WordPress core's priority 10–11), so Elementor pages with widgets are never affected. Handles edge cases: hides login form for logged-in users (unless `reauth=1`), shows "registration disabled" message, and shows "invalid reset link" error when key/login params are absent.
- **Medium:** Fixed `Undefined array key "key"` and `Undefined array key "login"` PHP warnings in both the Elementor Reset Password widget and the classic `WPFA_Reset_Password_Widget`. The previous `is_string()` guard used `$_GET['key'] ?? ''` for the null-coalesce check but then re-accessed `$_GET['key']` directly in the ternary true-branch — triggering the warning when the parameter was absent. Fixed by extracting to local variables first.

### 1.4.14

**Bug Fixes**

- **High (Security):** Fixed PHP 8.0+ fatal `TypeError` crash via array-valued HTTP parameters. An attacker could send `log[]=foo`, `key[]=bar`, or any other array-formatted parameter to crash form handlers — `sanitize_user()`, `sanitize_text_field()`, `sanitize_key()`, and `wp_sanitize_redirect()` all expect strings and throw a fatal `TypeError` when given arrays on PHP 8.0+. This was a denial-of-service vector that bypassed nonce verification (the crash occurred after the nonce check passed). Fixed across 7 files by adding `is_string()` guards to all direct `$_GET`/`$_POST`/`$_REQUEST` access points, and by changing the core `wpfa_get_request_value()` helper to return an empty string for non-string input instead of passing raw arrays through.
- **Medium (Security):** Added missing honeypot check to the lost-password handler. The honeypot hidden field was rendered in the form HTML but `wpfa_honeypot_is_spam()` was never called in `wpfa_handle_lostpassword()`. This allowed bots to automate the lost-password form and trigger mass password-reset emails to arbitrary users. The handler now checks the honeypot before calling `retrieve_password()` and returns a fake success response to fool the bot — identical to the existing pattern in the registration handler.
- **Low:** Replaced deprecated `wp.passwordStrength.userInputBlacklist()` with `wp.passwordStrength.userInputDisallowedList()` in the password strength meter JavaScript. The old API was deprecated in WordPress 5.5.0 (Trac #50413) and logged a console warning on every keystroke. Since the plugin requires WP 6.5+, the replacement API is guaranteed available. Fixed in both the source and minified JS files.
- **Low:** Fixed `wpfa_rate_limit_clear()` not deleting the companion `_ts` timestamp transient alongside the counter. After a successful login, the orphaned `_ts` transient caused `wpfa_rate_limit_remaining_seconds()` to return a stale non-zero lockout duration even though the user was no longer locked out — misleading any theme or plugin using the public API to display retry timers.

### 1.4.13

**Bug Fixes**

- **High:** Fixed login redirect sending all roles (including admins, editors, authors, contributors) to `home_url()` or ignoring the `redirect_to` parameter. Previously, `wpfa_maybe_redirect_logged_in_user()` blindly redirected every logged-in user visiting the login/register page to `admin_url()`, ignoring the `redirect_to` query parameter entirely. Now, the `redirect_to` parameter is honoured for privileged roles, and only subscribers are redirected away from `wp-admin`.
- **High:** Fixed login handler (`wpfa_handle_login`) also using `admin_url()` as the default redirect for non-subscribers. Privileged users with no `redirect_to` now go to `home_url()`. If a privileged user was bounced from wp-admin (WordPress adds `?redirect_to=wp-admin/...`), that redirect is honoured exactly.

**Documentation Fixes**

- Fixed incorrect inline comment claiming `wp_send_new_user_notification_to_admin` was introduced in WP 4.6 — the correct version is WP 6.1.0.
- Fixed misleading comment in main plugin file referencing `load_plugin_textdomain()` as "soft-deprecated in WP 6.7" — it was not deprecated but made redundant by the deferred translation loading system.
- Fixed WP version guard comment inconsistency (referenced "6.2+ minimum" when the actual requirement is 6.5+).
- Updated `wpfa_logged_in_redirect` filter documentation to reflect the role-based redirect logic.

### 1.4.12

**Bug Fixes**

- **Critical:** Removed automatic page creation on plugin activation/reactivation. Previously, deactivating and reactivating the plugin created duplicate Login, Register, Lost Password, and Reset Password pages every cycle. Pages are now managed manually via a new **Page Management** panel in the settings screen with "Create Missing Pages" and "Delete Auto-Created Pages" buttons.
- **Critical:** Fixed `render_form_title()` in Elementor widgets — `add_render_attribute()` was called with the return value of `get_render_attribute_string()` as the attribute name, producing malformed HTML on every widget with a form title.
- **High:** Fixed password toggle click listeners stacking on Elementor pages. `document.addEventListener('click', ...)` was inside `bindPasswordToggle()` which runs on every Elementor `element_ready` re-render. After N renders, N+1 identical listeners caused rapid toggle flicker. Moved to a single document-level delegate registered once at boot.
- **High:** Fixed Elementor `element_ready` hooks never registering. Used native `addEventListener` for `elementor/frontend/init` but Elementor fires this via jQuery's event system. Changed to `jQuery(window).on(...)`.
- **Medium:** Fixed `uninstall.php` deleting user-created pages. Now tracks auto-created pages via `_wpfa_auto_created` post meta and only deletes those.
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
- Renamed heading control IDs to `wpfa_h_*` to avoid cross-widget collision.

### 1.4.3

- Fixed `const wpFrontendAuth` declared twice causing SyntaxError on Elementor pages.
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
