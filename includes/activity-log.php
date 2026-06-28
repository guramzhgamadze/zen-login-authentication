<?php
/**
 * Zen Login & Authentication – Login Activity Log
 *
 * Records three kinds of authentication events into a dedicated table so the
 * dashboard widget (admin/dashboard.php) can show recent activity at a glance:
 *
 *   • login_success — a successful login (any path: the plugin's front-end
 *                     forms, wp-login.php, or programmatic wp_signon()).
 *   • login_failed  — a failed login attempt.
 *   • lockout       — an IP that crossed the rate-limit threshold for a form
 *                     ("blocked for spamming the login").
 *
 * Privacy: IP addresses are stored ANONYMISED — the same value the rate limiter
 * buckets on (IPv4 last octet zeroed, IPv6 truncated to /48). No full IP is ever
 * written. Rows older than the retention window are pruned automatically, and the
 * whole table is dropped on uninstall.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/** Bump when the table schema changes. */
const ZENLOGAU_ACTIVITY_DB_VERSION = '1';

/** Transient key for the cached dashboard summary. */
const ZENLOGAU_ACTIVITY_CACHE_KEY = 'zenlogau_activity_summary';

/**
 * Fully-qualified activity table name for the current (switched) blog.
 */
function zenlogau_activity_table(): string {
    global $wpdb;
    return $wpdb->prefix . 'zenlogau_activity';
}

/**
 * Whether event logging is on. Default: on. Filterable + option-controlled.
 */
function zenlogau_activity_logging_enabled(): bool {
    return (bool) apply_filters(
        'zenlogau_activity_log_enabled',
        (bool) get_option( 'zenlogau_activity_log_enabled', true )
    );
}

/**
 * Days of history to keep. 0 = keep forever (not recommended). Default 30.
 */
function zenlogau_activity_retention_days(): int {
    return (int) apply_filters(
        'zenlogau_activity_retention_days',
        (int) get_option( 'zenlogau_activity_retention_days', 30 )
    );
}

/* -----------------------------------------------------------------------
 * Schema
 * -------------------------------------------------------------------- */

/**
 * Create or migrate the activity table. Version-gated so dbDelta only runs when
 * the schema actually changes. Called from activation and from the upgrade
 * routine, so it covers fresh installs, FTP updates, and every multisite blog.
 */
function zenlogau_activity_maybe_create_table(): void {
    if ( (string) get_option( 'zenlogau_activity_db_version', '' ) === ZENLOGAU_ACTIVITY_DB_VERSION ) {
        return;
    }

    global $wpdb;
    $table           = zenlogau_activity_table();
    $charset_collate = $wpdb->get_charset_collate();

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    // Note: dbDelta is whitespace- and format-sensitive (two spaces after
    // PRIMARY KEY, lowercase types, one field per line).
    $sql = "CREATE TABLE {$table} (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        event varchar(20) NOT NULL DEFAULT '',
        user_id bigint(20) unsigned NOT NULL DEFAULT 0,
        user_login varchar(180) NOT NULL DEFAULT '',
        ip varchar(100) NOT NULL DEFAULT '',
        created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY event_created (event, created_at),
        KEY created_at (created_at)
    ) {$charset_collate};";

    dbDelta( $sql );

    update_option( 'zenlogau_activity_db_version', ZENLOGAU_ACTIVITY_DB_VERSION, false );
}

/* -----------------------------------------------------------------------
 * Writing
 * -------------------------------------------------------------------- */

/**
 * Insert one activity row.
 *
 * @param string $event One of: login_success, login_failed, lockout.
 * @param array  $args  { user_id, user_login, ip } — any may be omitted.
 */
function zenlogau_activity_log( string $event, array $args = [] ): void {
    if ( ! zenlogau_activity_logging_enabled() ) {
        return;
    }

    global $wpdb;

    $ip = isset( $args['ip'] ) && '' !== (string) $args['ip']
        ? (string) $args['ip']
        : zenlogau_rate_limit_get_ip(); // already anonymised

    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one INSERT into the plugin's own custom table; no core API exists and caching does not apply to a write.
    $wpdb->insert(
        zenlogau_activity_table(),
        [
            'event'      => substr( $event, 0, 20 ),
            'user_id'    => isset( $args['user_id'] ) ? (int) $args['user_id'] : 0,
            'user_login' => substr( (string) ( $args['user_login'] ?? '' ), 0, 180 ),
            'ip'         => substr( $ip, 0, 100 ),
            'created_at' => current_time( 'mysql', true ), // UTC
        ],
        [ '%s', '%d', '%s', '%s', '%s' ]
    );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

    // The dashboard summary is cached; a new event makes it stale.
    delete_transient( ZENLOGAU_ACTIVITY_CACHE_KEY );

    // Opportunistic pruning on ~1% of writes keeps the table bounded without a cron job.
    if ( 1 === wp_rand( 1, 100 ) ) {
        zenlogau_activity_prune();
    }
}

/**
 * Delete rows older than the retention window.
 */
function zenlogau_activity_prune(): void {
    $days = zenlogau_activity_retention_days();
    if ( $days <= 0 ) {
        return;
    }
    global $wpdb;
    $table  = zenlogau_activity_table();
    $cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- retention DELETE on the plugin's own table; $table derives from $wpdb->prefix (never user input) and a DELETE cannot be cached.
    // LIMIT keeps each opportunistic prune bounded so a large backlog can't block
    // the DB in one query; the next write prunes the next batch.
    $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s LIMIT 500", $cutoff ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
}

/**
 * Delete every row (the settings "Clear log" button).
 */
function zenlogau_activity_clear(): void {
    global $wpdb;
    $table = zenlogau_activity_table();
    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- truncating the plugin's own log table on explicit admin request; $table derives from $wpdb->prefix.
    $wpdb->query( "DELETE FROM {$table}" );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    delete_transient( ZENLOGAU_ACTIVITY_CACHE_KEY );
}

/* -----------------------------------------------------------------------
 * Event hooks
 *
 * Core wp_login / wp_login_failed are used (not just the plugin's own actions)
 * so the dashboard reflects EVERY login path — the front-end forms, wp-login.php,
 * and any programmatic wp_signon() — which is what makes it useful as a security
 * overview. Lockouts come from the plugin's own rate limiter.
 * -------------------------------------------------------------------- */

add_action( 'wp_login', 'zenlogau_activity_record_login', 10, 2 );

/**
 * @param string $user_login
 * @param mixed  $user        WP_User on a normal login.
 */
function zenlogau_activity_record_login( $user_login, $user = null ): void {
    zenlogau_activity_log( 'login_success', [
        'user_id'    => $user instanceof WP_User ? $user->ID : 0,
        'user_login' => (string) $user_login,
    ] );
}

add_action( 'wp_login_failed', 'zenlogau_activity_record_failed', 10, 1 );

/**
 * @param string $username The attempted username/email.
 */
function zenlogau_activity_record_failed( $username ): void {
    zenlogau_activity_log( 'login_failed', [ 'user_login' => (string) $username ] );
}

add_action( 'zenlogau_rate_limit_locked', 'zenlogau_activity_record_lockout', 10, 3 );

/**
 * @param string $action   The form that locked out (login, register, …).
 * @param string $ip       The anonymised IP that was locked.
 * @param int    $attempts Attempt count at lockout.
 */
function zenlogau_activity_record_lockout( $action, $ip = '', $attempts = 0 ): void {
    zenlogau_activity_log( 'lockout', [
        'user_login' => (string) $action, // for lockouts the "who" is the IP; we keep the form here
        'ip'         => (string) $ip,
    ] );
}

/* -----------------------------------------------------------------------
 * Reading (dashboard)
 * -------------------------------------------------------------------- */

/**
 * Count rows for one event within the last N days.
 */
function zenlogau_activity_count_since( string $event, int $days ): int {
    global $wpdb;
    $table  = zenlogau_activity_table();
    $cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, $days ) * DAY_IN_SECONDS );
    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- dashboard read; the caller caches the whole summary in a transient and $table derives from $wpdb->prefix.
    $count = (int) $wpdb->get_var( $wpdb->prepare(
        "SELECT COUNT(*) FROM {$table} WHERE event = %s AND created_at >= %s",
        $event,
        $cutoff
    ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    return $count;
}

/**
 * Top values grouped by a column for an event within the last N days.
 *
 * @param string $event  Event name.
 * @param string $column 'user_login' or 'ip' (whitelisted below).
 * @param int    $days   Window.
 * @param int    $limit  Max rows.
 * @return array<int,object> Rows of { label, cnt }.
 */
function zenlogau_activity_top( string $event, string $column, int $days, int $limit ): array {
    $column = in_array( $column, [ 'user_login', 'ip' ], true ) ? $column : 'user_login';
    global $wpdb;
    $table  = zenlogau_activity_table();
    $cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, $days ) * DAY_IN_SECONDS );
    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- dashboard read, cached by the caller; $table derives from $wpdb->prefix and $column is whitelisted above.
    $rows = (array) $wpdb->get_results( $wpdb->prepare(
        "SELECT {$column} AS label, COUNT(*) AS cnt
         FROM {$table}
         WHERE event = %s AND created_at >= %s
         GROUP BY {$column}
         ORDER BY cnt DESC
         LIMIT %d",
        $event,
        $cutoff,
        $limit
    ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    return $rows;
}

/**
 * Most recent events (any type).
 *
 * @return array<int,object> Rows of { event, user_id, user_login, ip, created_at }.
 */
function zenlogau_activity_recent( int $limit ): array {
    global $wpdb;
    $table = zenlogau_activity_table();
    // phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- dashboard read, cached by the caller; $table derives from $wpdb->prefix.
    $rows = (array) $wpdb->get_results( $wpdb->prepare(
        "SELECT event, user_id, user_login, ip, created_at FROM {$table} ORDER BY id DESC LIMIT %d",
        $limit
    ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    return $rows;
}

/**
 * Build (and cache) the full data set the dashboard widget needs.
 *
 * Cached in a 5-minute transient so the dashboard never hammers the table; the
 * cache is invalidated whenever a new event is logged or the log is cleared.
 *
 * @return array
 */
function zenlogau_activity_get_summary(): array {
    $cached = get_transient( ZENLOGAU_ACTIVITY_CACHE_KEY );
    if ( is_array( $cached ) ) {
        return $cached;
    }

    $days = (int) apply_filters( 'zenlogau_activity_summary_days', 7 );

    $summary = [
        'days'         => $days,
        'success'      => zenlogau_activity_count_since( 'login_success', $days ),
        'failed'       => zenlogau_activity_count_since( 'login_failed', $days ),
        'lockouts'     => zenlogau_activity_count_since( 'lockout', $days ),
        'top_failed'   => zenlogau_activity_top( 'login_failed', 'user_login', $days, 5 ),
        'top_blocked'  => zenlogau_activity_top( 'lockout', 'ip', $days, 5 ),
        'recent'       => zenlogau_activity_recent( 8 ),
    ];

    set_transient( ZENLOGAU_ACTIVITY_CACHE_KEY, $summary, 5 * MINUTE_IN_SECONDS );
    return $summary;
}
