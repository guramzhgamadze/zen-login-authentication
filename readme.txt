=== WP Frontend Auth ===
Contributors: guramzhgamadze
Tags: login, registration, authentication, elementor, frontend
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.4.23
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Frontend login, registration, and password recovery for WordPress and Elementor, with rate limiting, honeypot, and AJAX forms.

== Description ==

WP Frontend Auth replaces the default `wp-login.php` experience with clean, accessible, theme-integrated forms that live on your actual site. It works out of the box on any WordPress theme and ships with first-class Elementor support: four drag-and-drop widgets that fit any page-builder layout, with full Theme Builder compatibility.

The plugin works with no configuration, and adds no external service calls, tracking, or "phone home" behaviour.

= What it does =

* **Login** with username, email, or either (configurable).
* **Registration** with optional user-chosen passwords and auto-login.
* **Lost Password / Reset Password** with the full WordPress email flow.
* **URL rewriting** so every site-wide `wp-login.php` link is transparently redirected to your frontend pages.
* **Multisite support** — network-activated, per-site settings, signup/activation flow handled.
* **Smart redirects** — `?redirect_to=` is honoured everywhere. Subscribers are kept out of wp-admin and sent to a destination you set in **Settings &rarr; Frontend Auth &rarr; Subscriber redirect** (a page slug or URL; empty = site home). Privileged users always land where they intended.
* **Cache exclusion** — auth pages are automatically excluded from LiteSpeed Cache, Super Page Cache, WP Rocket, W3 Total Cache, and WP Super Cache.

= Security =

* **Nonce verification** on every form submission.
* **Rate limiting** — configurable max attempts per IP with a lockout window, per form (login, register, lost-password, reset-password), with optional per-form thresholds.
* **Honeypot spam protection** — rotating hidden field (hourly key rotation via HMAC) catches bots; trapped submissions get a fake success response.
* **Spoof-resistant IP detection** — rate-limit keys use the real socket address (`REMOTE_ADDR`) by default; forwarded headers are opt-in via a filter for sites genuinely behind Cloudflare.
* **No password pre-population**, bcrypt-compatible (`wp_set_password()` / `wp_signon()`), and an 8-character minimum on new passwords.

= Elementor integration =

Four native widgets registered under a "Frontend Auth" category:

* **Login Form** — custom labels, placeholders, toggle text, and link overrides; hidden when logged in (unless `reauth=1`); picks up `?redirect_to=` from the URL.
* **Registration Form** — password + confirm fields when user-chosen passwords are enabled, with a live strength meter.
* **Lost Password Form** — password-recovery request form.
* **Reset Password Form** — reads `?key=&login=` from the URL and shows a friendly message when the link is missing or expired.

Every widget has a full style panel (container, title, labels, fields with focus glow, button normal/hover, links, messages, password toggle, strength meter).

= Classic widgets =

Four `WP_Widget` subclasses are also registered for classic / block-based widget areas: Login, Register, Lost Password, and Reset Password.

= Pages =

On activation the plugin sets up a real WordPress page for each auth action so Elementor Theme Builder targeting works. For each default slug it **reuses** an existing page if one is there (never modifying or deleting it), otherwise **creates** one. The process is idempotent, so activate/deactivate cycles never duplicate pages, and the plugin also works with no real pages via its virtual URL-rewrite fallback.

== Installation ==

1. Upload the `wp-frontend-auth` folder to `/wp-content/plugins/`, or install it from **Plugins &rarr; Add New**.
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
`add_filter( 'wpfa_rate_limit_ip_headers', fn() => [ 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR' ] );`

= Is it multisite compatible? =

Yes. It is network-activatable, with per-site settings and signup/activation handling.

= What happens to my pages when I uninstall? =

Only pages the plugin created that you never edited (no content, no Elementor data) are removed. Pages you edited, or pre-existing pages the plugin merely reused, are always kept.

== Screenshots ==

1. The Frontend Auth settings screen (general options, rate limiting, page slugs).
2. A login form rendered on the frontend.
3. An Elementor Login Form widget with its style controls.
4. The registration form with the password strength meter.

== Changelog ==

= 1.4.23 =
* Fixed: the Elementor editor preview now shows the in-field password toggle layout, matching the front end (the preview templates were missing the password-field modifier class).

= 1.4.22 =
* Design: refreshed the default form styling for a modern, polished look out of the box — softer rounded inputs and buttons, refined focus rings, fully-rounded status notices, an updated password strength meter, a brand-tinted "Remember Me" checkbox, and a cleaner password field (label above, with the Show/Hide toggle inside the field's right edge so the input stays full-width like the other fields). Every value stays overridable via the `--wpfa-*` CSS custom properties and the Elementor style controls. Applies to all four forms and every widget type (Elementor, classic, and virtual pages).
* Fixed (Elementor): the Form Container background, border, padding, radius, and shadow now wrap the form title too — previously the title rendered outside the styled container.

= 1.4.20 =
* New: subscribers who register through the plugin have the front-end admin toolbar ("Show Toolbar when viewing site") hidden by default — a preference they can re-enable from their profile.
* New: subscribers are kept out of wp-admin and redirected to the Subscriber redirect destination (site home page by default). admin-ajax.php is exempt so front-end AJAX keeps working.
* Fixed: the Subscriber redirect now applies to every login path — the front-end form, wp-login.php, and third-party login flows — via a high-priority `login_redirect` filter. Previously it was only enforced inside the plugin's own login form, so a security/membership plugin or a wp-login.php login could bypass it.
* Fixed: the "Settings" link on the Plugins screen now works regardless of the plugin's folder name.
* Tested up to WordPress 7.0.

= 1.4.19 =
* Security: rate-limit IP detection now uses `REMOTE_ADDR` by default, closing a header-spoofing bypass. Cloudflare sites can opt the real-client header back in via the `wpfa_rate_limit_ip_headers` filter.
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

= 1.4.20 =
Subscribers are now reliably sent to your configured destination on every login path and kept out of wp-admin. New subscriber registrations get the front-end toolbar hidden by default.

= 1.4.19 =
Security fix: rate-limit IP detection hardened against header spoofing. Uninstall no longer deletes edited or adopted pages. Adds a configurable subscriber redirect. Recommended update.
