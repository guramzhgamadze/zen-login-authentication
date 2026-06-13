=== Frontend Auth ===
Contributors: guramzhgamadze
Tags: login, registration, authentication, elementor, frontend
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Frontend login, registration, and password recovery for WordPress and Elementor, with rate limiting, honeypot, and AJAX forms.

== Description ==

Frontend Auth replaces the default `wp-login.php` experience with clean, accessible, theme-integrated forms that live on your actual site. It works out of the box on any WordPress theme and ships with first-class Elementor support: five drag-and-drop widgets that fit any page-builder layout, with full Theme Builder compatibility.

The plugin works with no configuration and adds no tracking or "phone home" behaviour. The only external service it ever contacts is Google — and only during a sign-in, when the optional "Sign in with Google" feature is enabled.

= What it does =

* **Login** with username, email, or either (configurable).
* **Registration** with optional user-chosen passwords and auto-login.
* **Lost Password / Reset Password** with the full WordPress email flow.
* **Account page** — logged-in users edit their first/last name, public display name, email, and password from the frontend, without ever seeing wp-admin. Guests visiting the account page are sent to the login form and return after signing in.
* **Sign in with Google** (optional) — a server-side OpenID Connect flow with no Google JavaScript on your pages. New accounts can be auto-created (toggleable) and existing accounts are linked by verified email.
* **URL rewriting** so every site-wide `wp-login.php` link is transparently redirected to your frontend pages.
* **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
* **Smart redirects** — `?redirect_to=` is honoured everywhere. Subscribers are kept out of wp-admin and sent to a destination you set in **Settings &rarr; Frontend Auth &rarr; Subscriber redirect** (a page slug or URL; empty = site home). Privileged users always land where they intended.
* **Login activity dashboard** — a "Login Activity" widget on your WordPress dashboard summarising successful logins, failed attempts, and rate-limit lockouts over the past week, with the top failed usernames, the most-blocked IPs, and a recent-events feed. IP addresses are stored anonymised, history is auto-pruned, and the data is removed on uninstall.
* **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache.

= Security =

* **Nonce verification** on every form submission.
* **Rate limiting** — configurable max attempts per IP with a lockout window, per form (login, register, lost-password, reset-password), with optional per-form thresholds.
* **Honeypot spam protection** — rotating hidden field (hourly key rotation via HMAC) catches bots; trapped submissions get a fake success response.
* **Spoof-resistant IP detection** — rate-limit keys use the real socket address (`REMOTE_ADDR`) by default; forwarded headers are opt-in via a filter for sites genuinely behind Cloudflare.
* **No password pre-population**, bcrypt-compatible (`wp_set_password()` / `wp_signon()`), and an 8-character minimum on new passwords.

= External services =

This plugin contacts an external service **only** when the optional "Sign in with Google" feature is enabled, and only during a Google sign-in:

* **Google OAuth / OpenID Connect** (accounts.google.com and oauth2.googleapis.com). When a user clicks "Continue with Google", they are redirected to Google's consent screen, and the plugin's server then exchanges the one-time authorization code for an ID token. The data involved: the OAuth client credentials you configured, the single-use authorization code, and — returned by Google — the user's verified email address, name, and Google account ID, which are used solely to log the user in or create their account on your site. No other data is sent to Google, and nothing is sent at any other time. This service is provided by Google LLC: [Terms of Service](https://policies.google.com/terms), [Privacy Policy](https://policies.google.com/privacy).

If the feature is disabled (the default), the plugin makes no external calls whatsoever.

= Elementor integration =

Five native widgets registered under a "Frontend Auth" category:

* **Login Form** — custom labels, placeholders, toggle text, and link overrides; hidden when logged in (unless `reauth=1`); picks up `?redirect_to=` from the URL.
* **Registration Form** — password + confirm fields when user-chosen passwords are enabled, with a live strength meter.
* **Lost Password Form** — password-recovery request form.
* **Reset Password Form** — reads `?key=&login=` from the URL and shows a friendly message when the link is missing or expired.
* **Account Form** — frontend profile editing (first/last name, public display name, email, optional password change) for the logged-in user, with the same label/placeholder/style controls as the other widgets.

Every widget has a full style panel (container, title, labels, fields with focus glow, button normal/hover, links, messages, password toggle, strength meter).

= Classic widgets =

Five `WP_Widget` subclasses are also registered for classic / block-based widget areas: Login, Register, Lost Password, Reset Password, and Account.

= Pages =

On activation the plugin sets up a real WordPress page for each auth action so Elementor Theme Builder targeting works. For each default slug it **reuses** an existing page if one is there (never modifying or deleting it), otherwise **creates** one. The process is idempotent, so activate/deactivate cycles never duplicate pages, and the plugin also works with no real pages via its virtual URL-rewrite fallback.

== Installation ==

1. Upload the `frontend-auth` folder to `/wp-content/plugins/`, or install it from **Plugins &rarr; Add New**.
2. Activate the plugin through **Plugins &rarr; Installed Plugins**.
3. Go to **Frontend Auth** in the admin sidebar to configure options.
4. Auth pages are created automatically on activation. If you delete some and want them back, use **Create Missing Pages** in the Page Management section.
5. Rewrite rules flush automatically on the first page load after activation. If a frontend URL 404s, visit **Settings &rarr; Permalinks** and click **Save Changes**.
6. *(Elementor users)* Open a page in the Elementor editor and search the widget panel under the **Frontend Auth** category.

== Frequently Asked Questions ==

= Does it require Elementor? =

No. The plugin works on any theme via its built-in forms and URL rewrites. Elementor only adds the optional drag-and-drop widgets.

= Does it disable wp-login.php? =

No. It rewrites the links across your site to your frontend pages, but `wp-login.php` remains available for administrators and recovery flows.

= How do I let users choose their own password when registering? =

Enable **User-chosen passwords** under **Settings &rarr; Frontend Auth &rarr; General**. You can also enable **Auto-login** to log users in immediately after they register.

= Where do users go after logging in? =

`?redirect_to=` is always honoured. Subscribers (who can't reach wp-admin) go to the **Subscriber redirect** you configure — a page slug or full URL, or the site home page if left empty.

= I'm behind Cloudflare. How do I get the real visitor IP for rate limiting? =

By default the plugin uses `REMOTE_ADDR` only, because forwarded headers are spoofable. If your origin firewall is locked to Cloudflare's IP ranges, opt the header back in:
`add_filter( 'fauth_rate_limit_ip_headers', fn() => [ 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR' ] );`

= How do I set up Sign in with Google? =

1. In Google Cloud Console, create an OAuth client: APIs & Services → Credentials → Create credentials → OAuth client ID → Web application.
2. Copy the **Authorized redirect URI** shown under Settings → Frontend Auth → Sign in with Google, and add it to the OAuth client.
3. Paste the Client ID and Client Secret into the same settings panel and switch the feature on.

A "Continue with Google" button then appears on the login and registration forms (each Elementor widget has a toggle and style controls for it). The flow is entirely server-side — no Google JavaScript is loaded on your pages.

= Can users edit their profile without going to wp-admin? =

Yes. The **Account** page (created on activation, default slug `/account/`) lets a logged-in user change their display name, email address, and password from the frontend. Changing the password keeps the user's current session logged in and signs out every other session, exactly like the wp-admin profile screen. Leave both password fields blank to keep the current password. Guests who open the page are redirected to the login form and brought back after signing in.

= Is it multisite compatible? =

Yes. It is network-activatable, with per-site settings and signup/activation handling.

= What happens to my pages when I uninstall? =

Only pages the plugin created that you never edited (no content, no Elementor data) are removed. Pages you edited, or pre-existing pages the plugin merely reused, are always kept.

== Screenshots ==

1. The frontend Login form with the optional "Continue with Google" button, rendered on a live theme.
2. The frontend Registration form (username, email, and user-chosen passwords).
3. The frontend Lost Password (password recovery) form.
4. The frontend Reset Password form with the in-field show/hide toggle.
5. Settings &mdash; General: login identifier, pretty URLs, AJAX submission, user-chosen passwords, honeypot, and the subscriber redirect.
6. Settings &mdash; Rate limiting, with optional per-form thresholds.
7. Settings &mdash; Page slugs and page management (adopt-or-create auth pages).
8. The Sign in with Google settings panel &mdash; enable the feature, add your Client ID and Secret (stored encrypted), and choose whether new accounts are created automatically.

== Changelog ==

= 1.7.0 =
* New: **Login activity dashboard widget.** A "Login Activity" panel on the WordPress dashboard shows, for the past week, the number of successful logins, failed attempts, and lockouts, plus the top failed usernames, the most-blocked IPs, and a recent-events feed. Successful and failed logins are captured for every login path (the plugin's forms, wp-login.php, and programmatic logins); lockouts come from the plugin's rate limiter. IP addresses are stored anonymised (the same value the rate limiter buckets on). Settings → Frontend Auth → Login Activity lets you turn logging off, set a retention window (default 30 days; old entries auto-prune), and clear the log. The activity table is removed on uninstall.

= 1.6.3 =
* Improved: post-login redirects now run WordPress's standard `login_redirect` filter on every front-end login, so membership/LMS and other plugins are respected — wherever they send a user is honoured.
* Improved: restricted subscribers are never landed in wp-admin. A non-admin destination chosen by another plugin (a member area, a course page, an explicit redirect) is kept; only an empty or wp-admin target falls back to the Subscriber redirect. Administrators and editors are unaffected — their normal dashboard flow, including the "clicked Edit → login → back to Edit" round-trip, still works.

= 1.6.2 =
* New: **per-widget switches** under Settings → Frontend Auth → Widgets — turn each form widget (Login, Registration, Lost Password, Reset Password, Account) on or off for both the Elementor panel and classic widget areas.
* Improved: the settings screen now uses 80% of the admin content area instead of a fixed narrow column.

= 1.6.1 =
* New: **Account page & widget** — frontend profile editing for logged-in users (read-only username, first and last name, a "Display name publicly as" dropdown that rebuilds live as you type — just like the wp-admin profile screen — plus email and an optional password change), available as an Elementor widget, a classic widget, and an auto-created `/account/` page with the usual virtual-URL fallback. Email changes are validated (format + uniqueness); password changes follow the same rules as the reset form (match + 8-character minimum), keep the current session logged in, and sign out all other sessions. Guests visiting the account page are redirected to the login form and return after signing in. The page is excluded from page caches like every other auth page.
* Fixed: `<select>` fields no longer clip their text on themes that set a fixed height on selects (e.g. Astra); the dropdown now uses the plugin's own styling with a consistent chevron.

= 1.5.0 =
* Security: the Google Client Secret is **encrypted at rest** (AES-256-GCM, keyed from your wp-config.php salts — a database dump alone cannot leak it) and is never re-displayed in the admin once saved. Both credentials can alternatively be defined as `FAUTH_GOOGLE_CLIENT_ID` / `FAUTH_GOOGLE_CLIENT_SECRET` constants in wp-config.php to keep them out of the database entirely. If you rotate your WordPress salts, re-enter the secret.
* Fixed: required-field asterisks were invisible — the honeypot's catch-all CSS rule (`.fauth [aria-hidden="true"]`) also hid the decorative asterisk spans. The rule is now scoped to the honeypot element only.
* New: **Sign in with Google** (optional). A server-side OpenID Connect flow — no Google JavaScript on your pages and no third-party libraries. Configure a Client ID/Secret under Settings → Frontend Auth → Sign in with Google; a "Continue with Google" button then appears on the login and registration forms (toggleable per Elementor widget, with its own style section). First-time Google users can be auto-created (toggleable); existing accounts are linked by verified email. Google logins respect the Subscriber redirect, wp-admin blocking, rate limiting, and the hidden-toolbar default for new sign-ups. CSRF protection via a single-use state token bound to the browser; only verified Google emails are accepted.

= 1.4.23 =
* Fixed: the Elementor editor preview now shows the in-field password toggle layout, matching the front end (the preview templates were missing the password-field modifier class).

= 1.4.22 =
* Design: refreshed the default form styling for a modern, polished look out of the box — softer rounded inputs and buttons, refined focus rings, fully-rounded status notices, an updated password strength meter, a brand-tinted "Remember Me" checkbox, and a cleaner password field (label above, with the Show/Hide toggle inside the field's right edge so the input stays full-width like the other fields). Every value stays overridable via the `--fauth-*` CSS custom properties and the Elementor style controls. Applies to all four forms and every widget type (Elementor, classic, and virtual pages).
* Fixed (Elementor): the Form Container background, border, padding, radius, and shadow now wrap the form title too — previously the title rendered outside the styled container.

= 1.4.20 =
* New: subscribers who register through the plugin have the front-end admin toolbar ("Show Toolbar when viewing site") hidden by default — a preference they can re-enable from their profile.
* New: subscribers are kept out of wp-admin and redirected to the Subscriber redirect destination (site home page by default). admin-ajax.php is exempt so front-end AJAX keeps working.
* Fixed: the Subscriber redirect now applies to every login path — the front-end form, wp-login.php, and third-party login flows — via a high-priority `login_redirect` filter. Previously it was only enforced inside the plugin's own login form, so a security/membership plugin or a wp-login.php login could bypass it.
* Fixed: the "Settings" link on the Plugins screen now works regardless of the plugin's folder name.
* Tested up to WordPress 7.0.

= 1.4.19 =
* Security: rate-limit IP detection now uses `REMOTE_ADDR` by default, closing a header-spoofing bypass. Cloudflare sites can opt the real-client header back in via the `fauth_rate_limit_ip_headers` filter.
* Fixed data loss on uninstall: only empty, unedited, plugin-created pages are removed; adopted and edited pages are always kept.
* Activation now adopts an existing page at each slug or creates one (idempotent, no duplicate pages).
* New: configurable **Subscriber redirect** setting (page slug or URL; empty = site home), replacing a hardcoded path.
* Housekeeping: dead-code removal and minor cleanups. No behaviour change.

= 1.4.18 =
* New: per-form rate limiting (enable/disable and threshold override per form) and a "count successful lost-password requests" option that closes the reset-email spam loophole.
* Admin checkboxes now save correctly when unchecked.

= 1.4.17 =
* One-time database cleanup: removes orphaned options and prunes excess revisions on auth pages.

= 1.4.16 =
* Automatic cache exclusion and stale-404 purging for LiteSpeed, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache.
* Rewrite rules now flush automatically on the first load after an update.
* OAuth / REST (e.g. MCP) login flows are exempted from URL rewriting.

Older versions: see the project's CHANGELOG / README on the plugin homepage.

== Upgrade Notice ==

= 1.7.0 =
Adds a "Login Activity" dashboard widget showing successful logins, failed attempts, and lockouts. A small activity table is created on update and removed on uninstall.

= 1.6.3 =
Post-login redirects now respect other plugins (membership/LMS) while keeping subscribers out of wp-admin. Administrators are unaffected.

= 1.6.1 =
Adds a frontend Account page and widget — users can now edit their name, public display name, email, and password without wp-admin. The /account/ page is created automatically on upgrade.

= 1.5.0 =
Adds optional Sign in with Google — a secure server-side flow with no Google JavaScript on your pages. Configure it under Settings → Frontend Auth.

= 1.4.20 =
Subscribers are now reliably sent to your configured destination on every login path and kept out of wp-admin. New subscriber registrations get the front-end toolbar hidden by default.

= 1.4.19 =
Security fix: rate-limit IP detection hardened against header spoofing. Uninstall no longer deletes edited or adopted pages. Adds a configurable subscriber redirect. Recommended update.
