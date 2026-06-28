=== Zen Login & Authentication ===
Contributors: guramzhgamadze
Tags: login, registration, authentication, elementor, frontend
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 2.1.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Frontend login, registration, and password recovery for WordPress and Elementor, with rate limiting, honeypot, and AJAX forms.

== Description ==

Zen Login & Authentication replaces the default `wp-login.php` experience with clean, accessible, theme-integrated forms that live on your actual site. It works out of the box on any WordPress theme and ships with first-class Elementor support: five drag-and-drop widgets that fit any page-builder layout, with full Theme Builder compatibility.

The plugin works with no configuration and adds no tracking or "phone home" behaviour. Every feature that contacts an external service is opt-in — Google sign-in, breached-password checking (Have I Been Pwned), and Cloudflare Turnstile — so out of the box the plugin makes no external calls at all. See **External services** below.

= What it does =

* **Login** with username, email, or either (configurable).
* **Registration** with optional user-chosen passwords and auto-login.
* **Lost Password / Reset Password** with the full WordPress email flow.
* **Account page** — logged-in users edit their first/last name, public display name, email, and password from the frontend, without ever seeing wp-admin. Guests visiting the account page are sent to the login form and return after signing in.
* **Sign in with Google** (optional) — a server-side OpenID Connect flow with no Google JavaScript on your pages. New accounts can be auto-created (toggleable) and existing accounts are linked by verified email.
* **Two-factor authentication** (optional, opt-in per user) — app-based TOTP with local QR enrollment and one-time recovery codes, managed from the Account page. Once a user turns it on, a second-factor step is required at login.
* **Sign out of other devices** — from the Account page, a logged-in user can end every other active session for their account in one click; the current device stays signed in.
* **Passkeys (WebAuthn)** (optional, opt-in per user) — users add passkeys from the Account page and sign in with no password using Face ID, a fingerprint, Windows Hello, or a security key. Passwordless sign-ins are phishing-resistant and count as multi-factor, so they skip both the password and any two-factor step. Verified locally; requires HTTPS.
* **New-device login alerts** — emails the account owner the first time their account is signed in from an unrecognised device or browser, using your site's normal email. On by default.
* **URL rewriting** so every site-wide `wp-login.php` link is transparently redirected to your frontend pages.
* **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
* **Smart redirects** — `?redirect_to=` is honoured everywhere. Subscribers are kept out of wp-admin and sent to a destination you set in **Settings &rarr; Zen Login & Authentication &rarr; Subscriber redirect** (a page slug or URL; empty = site home). Privileged users always land where they intended.
* **Login activity dashboard** — a "Login Activity" widget on your WordPress dashboard summarising successful logins, failed attempts, and rate-limit lockouts over the past week, with the top failed usernames, the most-blocked IPs, and a recent-events feed. IP addresses are stored anonymised, history is auto-pruned, and the data is removed on uninstall.
* **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache.

= Security =

* **Nonce verification** on every form submission.
* **Rate limiting** — configurable max attempts per IP with a lockout window, per form (login, register, lost-password, reset-password), with optional per-form thresholds.
* **Honeypot spam protection** — rotating hidden field (hourly key rotation via HMAC) catches bots; trapped submissions get a fake success response.
* **Spoof-resistant IP detection** — rate-limit keys use the real socket address (`REMOTE_ADDR`) by default; forwarded headers are opt-in via a filter for sites genuinely behind Cloudflare.
* **No password pre-population**, bcrypt-compatible (`wp_set_password()` / `wp_signon()`), and an 8-character minimum on new passwords.
* **Username-enumeration hardening** (on by default) — blocks `?author=N` author scans and the REST `/wp/v2/users` listing for logged-out visitors, and collapses login errors to one neutral message so a valid username is never confirmed. Author archives at `/author/name/` and logged-in editors are unaffected.
* **Breached-password blocking** (optional) — reject passwords found in the Have I Been Pwned corpus at registration, reset, and account update, using k-anonymity: only the first 5 characters of the password's SHA-1 hash are sent, never the password. Fails open if the service is unreachable.
* **Cloudflare Turnstile** (optional) — a privacy-friendly bot challenge on the login, registration, and lost-password forms, on the plugin's forms and wp-login.php alike.
* **XML-RPC lockdown** (optional) — disable XML-RPC to close the `system.multicall` brute-force amplifier and pingback abuse.
* **Two-factor authentication (TOTP)** — opt-in per user; the shared secret is stored encrypted, recovery codes are hashed and single-use, and the login challenge sets no auth cookie until the second factor verifies.

= External services =

This plugin contacts an external service **only** when you enable one of the optional features below. Out of the box it makes no external calls.

* **Google OAuth / OpenID Connect** (accounts.google.com and oauth2.googleapis.com). When a user clicks "Continue with Google", they are redirected to Google's consent screen, and the plugin's server then exchanges the one-time authorization code for an ID token. The data involved: the OAuth client credentials you configured, the single-use authorization code, and — returned by Google — the user's verified email address, name, and Google account ID, which are used solely to log the user in or create their account on your site. This service is provided by Google LLC: [Terms of Service](https://policies.google.com/terms), [Privacy Policy](https://policies.google.com/privacy).
* **Have I Been Pwned — Pwned Passwords** (api.pwnedpasswords.com). Enabled only when "Block breached passwords" is turned on. When a user sets or changes a password (registration, password reset, or account update), the plugin sends the **first 5 characters of the password's SHA-1 hash** to the range API and checks the returned list locally. The password itself, the full hash, and any user identity are never transmitted (k-anonymity model), and the request is cached. This service is provided by Have I Been Pwned: [Terms of Use](https://haveibeenpwned.com/API/v3#License), [Privacy Policy](https://haveibeenpwned.com/Privacy), [Pwned Passwords](https://haveibeenpwned.com/Passwords).
* **Cloudflare Turnstile** (challenges.cloudflare.com). Enabled only when Turnstile is configured. The challenge script is loaded on the protected forms, and on submission the resulting challenge token and the visitor's IP address are sent to Cloudflare's siteverify endpoint to confirm the visitor is not a bot. This service is provided by Cloudflare, Inc.: [Terms of Service](https://www.cloudflare.com/website-terms/), [Privacy Policy](https://www.cloudflare.com/privacypolicy/).

If none of these features are enabled (the default), the plugin makes no external calls whatsoever.

= Elementor integration =

Five native widgets registered under a "Zen Login & Authentication" category:

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

1. Upload the `zen-login-authentication` folder to `/wp-content/plugins/`, or install it from **Plugins &rarr; Add New**.
2. Activate the plugin through **Plugins &rarr; Installed Plugins**.
3. Go to **Zen Login & Authentication** in the admin sidebar to configure options.
4. Auth pages are created automatically on activation. If you delete some and want them back, use **Create Missing Pages** in the Page Management section.
5. Rewrite rules flush automatically on the first page load after activation. If a frontend URL 404s, visit **Settings &rarr; Permalinks** and click **Save Changes**.
6. *(Elementor users)* Open a page in the Elementor editor and search the widget panel under the **Zen Login & Authentication** category.

== Frequently Asked Questions ==

= Does it require Elementor? =

No. The plugin works on any theme via its built-in forms and URL rewrites. Elementor only adds the optional drag-and-drop widgets.

= Does it disable wp-login.php? =

No. It rewrites the links across your site to your frontend pages, but `wp-login.php` remains available for administrators and recovery flows.

= How do I let users choose their own password when registering? =

Enable **User-chosen passwords** under **Settings &rarr; Zen Login & Authentication &rarr; General**. You can also enable **Auto-login** to log users in immediately after they register.

= Where do users go after logging in? =

`?redirect_to=` is always honoured. Subscribers (who can't reach wp-admin) go to the **Subscriber redirect** you configure — a page slug or full URL, or the site home page if left empty.

= I'm behind Cloudflare. How do I get the real visitor IP for rate limiting? =

By default the plugin uses `REMOTE_ADDR` only, because forwarded headers are spoofable. If your origin firewall is locked to Cloudflare's IP ranges, opt the header back in:
`add_filter( 'zenlogau_rate_limit_ip_headers', fn() => [ 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR' ] );`

= How do I set up Sign in with Google? =

1. In Google Cloud Console, create an OAuth client: APIs & Services → Credentials → Create credentials → OAuth client ID → Web application.
2. Copy the **Authorized redirect URI** shown under Settings → Zen Login & Authentication → Sign in with Google, and add it to the OAuth client.
3. Paste the Client ID and Client Secret into the same settings panel and switch the feature on.

A "Continue with Google" button then appears on the login and registration forms (each Elementor widget has a toggle and style controls for it). The flow is entirely server-side — no Google JavaScript is loaded on your pages.

= Can users edit their profile without going to wp-admin? =

Yes. The **Account** page (created on activation, default slug `/account/`) lets a logged-in user change their display name, email address, and password from the frontend. Changing the password keeps the user's current session logged in and signs out every other session, exactly like the wp-admin profile screen. Leave both password fields blank to keep the current password. Guests who open the page are redirected to the login form and brought back after signing in.

= Is it multisite compatible? =

Yes. It is network-activatable, with per-site settings and signup/activation handling.

= What happens to my pages when I uninstall? =

Only pages the plugin created that you never edited (no content, no Elementor data) are removed. Pages you edited, or pre-existing pages the plugin merely reused, are always kept.

== Screenshots ==

1. Settings &mdash; General: login identifier, pretty URLs, AJAX submission, user-chosen passwords, honeypot, and the subscriber redirect.
2. Settings &mdash; Sign in with Google: enable the feature, add your Client ID and Secret (stored encrypted), choose whether new accounts are created automatically, and copy the authorized redirect URI for Google Cloud Console.
3. Settings &mdash; Widgets: enable or disable each form widget (Login, Registration, Lost Password, Reset Password, Account) for the Elementor panel and classic widget areas.
4. Settings &mdash; Rate Limiting: global max attempts and lockout window, plus per-form enable/disable and threshold overrides for Login, Registration, Lost Password, and Reset Password.
5. Settings &mdash; Security Hardening: block username enumeration, show generic login errors, block breached passwords via Have I Been Pwned, and disable XML-RPC.
6. Settings &mdash; Bot Protection (Cloudflare Turnstile): enable the challenge, add your Site Key and Secret Key, and choose which forms are protected.
7. Settings &mdash; Two-Factor Authentication and Passkeys: master switch for TOTP (users enroll from the Account page) and passkey (WebAuthn) sign-in.
8. Settings &mdash; New-Device Login Alerts and Login Activity: configure new-device email alerts with an optional custom body, and set the activity-log retention window.
9. Settings &mdash; Page Slugs: customise the URL slug for each auth action (Login, Logout, Register, Lost Password, Reset Pass, Account).
10. Settings &mdash; Tools: clear the activity log and manage auth pages (view status, create missing pages, or delete auto-created pages).
11. Front end &mdash; Log In form on a live page: username or email and password (with a Show/Hide toggle), Remember Me, the Log In button, and Register / Lost-password links &mdash; then, below the "or" divider, the "Sign in with a passkey" and "Continue with Google" buttons.
12. Front end &mdash; Registration form: username, email, and password plus confirm-password (each with a Show/Hide toggle), the Register button, a Log In link, and "Continue with Google" below the divider.
13. Front end &mdash; Lost Password form: request a reset link by username or email address, with a Log In link back to sign-in.
14. Front end &mdash; Reset Password form: choose and confirm a new password (with Show/Hide toggles) from the emailed reset link.

== Changelog ==

= 2.1.3 =
* Security hardening (post-audit): turning OFF two-factor authentication now requires a current authenticator or recovery code, and TOTP codes can no longer be replayed within their validity window.
* Auto-login after registration now fires the standard login hook, so new-device alerts and the activity log capture it.
* Passkey sign-in is now rate-limited and validates the authenticator signature counter (clone detection for hardware security keys).
* Changing your email address or password on the Account page now requires your current password (filterable for sites whose users sign in only with Google or passkeys).
* Added GDPR personal-data export and erasure support (Tools &rarr; Export/Erase Personal Data) covering devices, passkeys, two-factor, and Google links.
* Bundled WebAuthn library: added direct-access protection and switched to WordPress HTTP/filesystem/URL helpers.
* Uninstall now also clears the plugin's transients.

= 2.1.2 =
* Security/hardening: every Elementor editor-preview template now escapes interpolated field values (titles, labels, button/link text, passkey and Google button text). The editor preview previously used raw interpolation, which could render unescaped HTML inside the builder.
* The Google sign-in button preview is now built entirely from escaped, literal markup — removing a misleading "escaped during construction" suppression flagged in review.
* Added late output escaping / input unslashing throughout per the WordPress Plugin Directory review (Cloudflare request-method check, new-device cookie), and documented the unavoidable core-hook and cache-plugin signal names.
* No functional changes — forms, passkeys, two-factor, and new-device alerts behave exactly as in 2.1.1.

= 2.1.1 =
* Redesigned login, registration, and account forms: a polished default card surface, a refined "security blue" palette, full-width primary buttons, and an outline secondary style — all still controllable from the Elementor toolbar.
* The "Sign in with a passkey" button now has an icon and its own Normal/Hover style controls, and sits below the "or" divider with the other sign-in options.
* Cleaner input focus (solid border + soft ring, no floating outline) and no stray hover border on buttons.
* The new-device alert email is now a styled, mobile-friendly HTML message, with an optional admin-supplied custom body.
* Added the missing password placeholder controls on the Account widget; the Elementor editor now previews the passkey, Google, two-factor, and passkeys/sessions sections.

= 2.1.0 =
* New: **Passkeys (WebAuthn)**. Users can add passkeys from the Account page and sign in with no password using Face ID, a fingerprint, Windows Hello, or a security key. Passwordless sign-ins are phishing-resistant and count as multi-factor, so they skip the password and any two-factor step. Credentials are verified locally by the bundled lbuchs/WebAuthn library (MIT) using "none" attestation — no external request is made. Requires HTTPS.
* New: **New-device login alerts**. Emails the account owner the first time their account is signed in from an unrecognised device or browser (similar to the "new sign-in" alerts from Google or GitHub). Recognises devices with a long-lived cookie and sends with your site's normal email — no external service. On by default.

= 2.0.0 =
* New: **Two-factor authentication (TOTP)**. Opt-in per user, managed entirely from the Account page: scan a QR code (or enter the setup key) in any authenticator app, confirm a code to turn it on, and save one-time recovery codes. After the password, a second-factor step is required — enforced across the plugin's forms, AJAX submissions, and wp-login.php (REST/XML-RPC application passwords and Google sign-in are unaffected). The shared secret is stored encrypted at rest and recovery codes are stored hashed and single-use; the login challenge sets no auth cookie until the second factor verifies.
* The enrollment QR is rendered locally by the bundled qrcode-generator library (Kazuhiko Arase, MIT) — no external request is made.
* New: **Sign out of other devices** on the Account page — ends every active session except the current one, so users can recover from a shared or lost device.
* Hardening: the subscriber-redirect setting now keeps full URLs intact (sanitized with `esc_url_raw()` rather than `sanitize_text_field()`, which could mangle a valid URL).

= 1.9.0 =
* New: **Security Hardening** panel. Username-enumeration protection — blocks `?author=N` author scans and the REST `/wp/v2/users` listing for logged-out visitors, and makes login errors generic so a valid username is never confirmed — is **on by default**. Optional XML-RPC lockdown closes the `system.multicall` brute-force amplifier and pingback abuse.
* New: **Breached-password blocking** (optional). Rejects passwords found in the Have I Been Pwned corpus at registration, password reset, and account update, using the k-anonymity range API — only the first 5 characters of the password's SHA-1 hash leave the site, never the password — and failing open if the service is unreachable.
* New: **Cloudflare Turnstile** bot protection (optional) on the login, registration, and lost-password forms — both the plugin's forms and wp-login.php — with server-side token verification. The secret key is stored encrypted at rest.

= 1.8.1 =
* Housekeeping: removed the one-time pre-release prefix-migration routine (it had served its purpose; all known installs are already on the current `zenlogau` prefix). No change to normal installs or updates.

= 1.8.0 =
* Internal: the plugin's PHP/option prefix is now `zenlogau` (functions, classes, constants, options, transients, user/post meta, and the activity table). A one-time migration moves existing data automatically on update, so your settings, Google credentials, pages, and activity log carry over.

= 1.7.2 =
* Removed a read of WP Super Cache's `$file_prefix` global during cache purge; auth pages already set `DONOTCACHEPAGE`, which WP Super Cache honours, so no explicit purge is needed.

= 1.7.1 =
* Renamed the plugin to **Zen Login & Authentication** for a distinctive directory name.
* All admin CSS is now enqueued (no inline `<style>` blocks).
* Asset handles use a distinct prefix.
* The Google client secret is encrypted from its raw value (no lossy pre-sanitization).

= 1.7.0 =
* New: **Login activity dashboard widget.** A "Login Activity" panel on the WordPress dashboard shows, for the past week, the number of successful logins, failed attempts, and lockouts, plus the top failed usernames, the most-blocked IPs, and a recent-events feed. Successful and failed logins are captured for every login path (the plugin's forms, wp-login.php, and programmatic logins); lockouts come from the plugin's rate limiter. IP addresses are stored anonymised (the same value the rate limiter buckets on). Settings → Zen Login & Authentication → Login Activity lets you turn logging off, set a retention window (default 30 days; old entries auto-prune), and clear the log. The activity table is removed on uninstall.

= 1.6.3 =
* Improved: post-login redirects now run WordPress's standard `login_redirect` filter on every front-end login, so membership/LMS and other plugins are respected — wherever they send a user is honoured.
* Improved: restricted subscribers are never landed in wp-admin. A non-admin destination chosen by another plugin (a member area, a course page, an explicit redirect) is kept; only an empty or wp-admin target falls back to the Subscriber redirect. Administrators and editors are unaffected — their normal dashboard flow, including the "clicked Edit → login → back to Edit" round-trip, still works.

= 1.6.2 =
* New: **per-widget switches** under Settings → Zen Login & Authentication → Widgets — turn each form widget (Login, Registration, Lost Password, Reset Password, Account) on or off for both the Elementor panel and classic widget areas.
* Improved: the settings screen now uses 80% of the admin content area instead of a fixed narrow column.

= 1.6.1 =
* New: **Account page & widget** — frontend profile editing for logged-in users (read-only username, first and last name, a "Display name publicly as" dropdown that rebuilds live as you type — just like the wp-admin profile screen — plus email and an optional password change), available as an Elementor widget, a classic widget, and an auto-created `/account/` page with the usual virtual-URL fallback. Email changes are validated (format + uniqueness); password changes follow the same rules as the reset form (match + 8-character minimum), keep the current session logged in, and sign out all other sessions. Guests visiting the account page are redirected to the login form and return after signing in. The page is excluded from page caches like every other auth page.
* Fixed: `<select>` fields no longer clip their text on themes that set a fixed height on selects (e.g. Astra); the dropdown now uses the plugin's own styling with a consistent chevron.

= 1.5.0 =
* Security: the Google Client Secret is **encrypted at rest** (AES-256-GCM, keyed from your wp-config.php salts — a database dump alone cannot leak it) and is never re-displayed in the admin once saved. Both credentials can alternatively be defined as `ZENLOGAU_GOOGLE_CLIENT_ID` / `ZENLOGAU_GOOGLE_CLIENT_SECRET` constants in wp-config.php to keep them out of the database entirely. If you rotate your WordPress salts, re-enter the secret.
* Fixed: required-field asterisks were invisible — the honeypot's catch-all CSS rule (`.fauth [aria-hidden="true"]`) also hid the decorative asterisk spans. The rule is now scoped to the honeypot element only.
* New: **Sign in with Google** (optional). A server-side OpenID Connect flow — no Google JavaScript on your pages and no third-party libraries. Configure a Client ID/Secret under Settings → Zen Login & Authentication → Sign in with Google; a "Continue with Google" button then appears on the login and registration forms (toggleable per Elementor widget, with its own style section). First-time Google users can be auto-created (toggleable); existing accounts are linked by verified email. Google logins respect the Subscriber redirect, wp-admin blocking, rate limiting, and the hidden-toolbar default for new sign-ups. CSRF protection via a single-use state token bound to the browser; only verified Google emails are accepted.

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
* Security: rate-limit IP detection now uses `REMOTE_ADDR` by default, closing a header-spoofing bypass. Cloudflare sites can opt the real-client header back in via the `zenlogau_rate_limit_ip_headers` filter.
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

= 2.1.3 =
Security hardening from a full audit: 2FA-disable re-authentication, TOTP replay protection, passkey rate-limiting, account-change re-auth, and GDPR export/erasure. Recommended for everyone.

= 2.1.2 =
Security/review hardening: all Elementor editor-preview output is now properly escaped. No functional changes — recommended for everyone.

= 2.0.0 =
Adds opt-in two-factor authentication (TOTP) managed from the Account page, with QR enrollment and recovery codes. Existing logins are unaffected until a user turns it on for their own account.

= 1.9.0 =
Adds optional Cloudflare Turnstile and breached-password blocking, plus username-enumeration hardening (ON by default: ?author=N and guest REST user listings blocked, generic login errors). Review Security settings if you rely on numeric author archives or XML-RPC.

= 1.8.1 =
Internal housekeeping only — removed obsolete one-time migration code. No action needed.

= 1.8.0 =
Internal prefix changed to zenlogau. Existing settings, credentials, pages, and the activity log migrate automatically on update — no action needed.

= 1.7.2 =
Minor cleanup: dropped a read of WP Super Cache's global during cache purge (auth pages are already excluded via DONOTCACHEPAGE).

= 1.7.1 =
Renamed to Zen Login & Authentication, with WordPress.org compliance fixes (enqueued admin CSS, prefixed asset handles, raw-value secret encryption).

= 1.7.0 =
Adds a "Login Activity" dashboard widget showing successful logins, failed attempts, and lockouts. A small activity table is created on update and removed on uninstall.

= 1.6.3 =
Post-login redirects now respect other plugins (membership/LMS) while keeping subscribers out of wp-admin. Administrators are unaffected.

= 1.6.1 =
Adds a frontend Account page and widget — users can now edit their name, public display name, email, and password without wp-admin. The /account/ page is created automatically on upgrade.

= 1.5.0 =
Adds optional Sign in with Google — a secure server-side flow with no Google JavaScript on your pages. Configure it under Settings → Zen Login & Authentication.

= 1.4.20 =
Subscribers are now reliably sent to your configured destination on every login path and kept out of wp-admin. New subscriber registrations get the front-end toolbar hidden by default.

= 1.4.19 =
Security fix: rate-limit IP detection hardened against header spoofing. Uninstall no longer deletes edited or adopted pages. Adds a configurable subscriber redirect. Recommended update.
