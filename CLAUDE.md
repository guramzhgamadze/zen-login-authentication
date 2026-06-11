# Claude development notes — WP Frontend Auth

Lessons from real mistakes made (and fixed) while developing this plugin.
Read before changing code. Every rule below exists because the opposite
shipped and broke something.

## Security mistakes

- **I stored the Google OAuth Client Secret as a plaintext option AND echoed it
  back into the settings-page HTML** (`<input value="<secret>">`). It was read
  in full by a DB-level tool that claimed to redact credentials. Rules:
  secrets are encrypted at rest via `includes/crypto.php` (AES-256-GCM keyed
  from wp-config salts), never re-rendered in admin HTML (empty field +
  "leave blank to keep" sanitizer), and never assume a third-party redaction
  layer knows your option names — verify empirically.
- **Rate limiting originally trusted forwarded IP headers** (X-Forwarded-For
  etc.) by default — trivially spoofable. Default to `REMOTE_ADDR`; forwarded
  headers are opt-in via `wpfa_rate_limit_ip_headers` for sites genuinely
  behind a proxy.
- **The subscriber redirect was originally enforced only inside the plugin's
  own login handler**, so wp-login.php and third-party login flows bypassed
  it. Policy decisions belong on the core filter (`login_redirect`,
  priority 100), not in one handler.

## Caching mistakes (the most expensive lesson here)

- **Elementor Element Caching froze auth forms**: widgets without
  `is_dynamic_content(): true` get their HTML cached — which froze nonces and
  `redirect_to` values, causing "An error occurred" logins and dead redirects
  that looked like logic bugs. Every auth widget MUST return `true` from
  `is_dynamic_content()`. More generally: **never put per-request values
  (nonces, state tokens, GET params) into markup that any cache may store.**
  The Google button shows the safe pattern: a static link to an
  `admin-post.php` start endpoint that generates state at click time.
- **CSS/JS changes are invisible without a version bump** — `WPFA_VERSION` is
  the cache-buster for enqueued assets. Bump it on every asset change.
- **Rewrite-rule changes need a permalink flush** — a new action slug 404'd
  (broken /logout/) until permalinks were regenerated. Don't rely on users
  flushing; the plugin now flushes on first load after an update.

## CSS / markup mistakes

- **`.wpfa [aria-hidden="true"] { display:none !important }`** (honeypot
  hiding) also hid the required-field asterisks and any decorative SVG — for
  many releases, unnoticed. Never select on bare ARIA attributes for styling;
  give the element its own class (`wpfa-hp`). Found only by inspecting
  computed styles in a live DOM — screenshots alone "looked fine."
- **Elementor Form Container controls targeted `.wpfa-form` instead of the
  outer `.wpfa-form-wrap`**, so the form title rendered outside the styled
  card. Style controls must target the outermost wrapper the widget owns.
- **Front-end markup changed without updating the editor previews**: the
  in-field password toggle worked on the page but the Elementor builder showed
  the old layout, because 7 password rows across the `content_template()`
  Backbone templates were missing the new modifier class. Any `render()`
  markup change must be mirrored in every widget's `content_template()`.

## Data-safety mistakes

- **Uninstall used to delete users' pages**: it removed pages by stored ID
  without checking provenance. Only delete pages that are plugin-created
  (`_wpfa_auto_created`), unedited (no `_elementor_edit_mode`), and empty.
  Activation must adopt-or-create idempotently — never duplicate, never
  overwrite.

## Process / tooling notes (Windows dev box)

- PHP CLI loads **no php.ini by default** here — `extension_loaded('openssl')`
  is false and crypto silently passes through. Always test with
  `-c C:\Users\Guram\Documents\wpfa-analysis\php.ini` (PHPStan workspace).
- The PowerShell sandbox false-flags commands that combine `Remove-Item` with
  regex-heavy strings (minifiers, here-strings). Keep deletions in a separate
  call. A blocked call executed NOTHING, including earlier lines.
- `gh release create --notes-from-tag` cannot be combined with `--repo`; run
  it from inside the repo.
- Verification = lint every file + PHPStan (8 known false positives are
  baseline) + the live-DOM preview harness, not screenshots alone.
