<?php
/**
 * Frontend Auth – Dashboard Widget
 *
 * A "Login Activity" widget on the main WordPress dashboard (wp-admin/index.php)
 * summarising successful logins, failed attempts, and rate-limit lockouts over
 * the past week, plus the worst offenders and recent events. Data comes from
 * includes/activity-log.php.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

add_action( 'wp_dashboard_setup', 'fauth_register_dashboard_widget' );

function fauth_register_dashboard_widget(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    wp_add_dashboard_widget(
        'fauth_activity_widget',
        __( 'Frontend Auth — Login Activity', 'frontend-auth' ),
        'fauth_render_dashboard_widget'
    );
}

/**
 * Render the dashboard widget body.
 */
function fauth_render_dashboard_widget(): void {
    if ( ! fauth_activity_logging_enabled() ) {
        echo '<p>' . wp_kses(
            sprintf(
                /* translators: %s: settings page URL */
                __( 'Login activity logging is turned off. Enable it under <a href="%s">Frontend Auth → Settings</a>.', 'frontend-auth' ),
                esc_url( admin_url( 'admin.php?page=frontend-auth' ) )
            ),
            [ 'a' => [ 'href' => [] ] ]
        ) . '</p>';
        return;
    }

    $data = fauth_activity_get_summary();
    $days = (int) $data['days'];
    ?>
    <style>
        #fauth_activity_widget .fauth-dash-stats { display:flex; gap:10px; margin:0 0 16px; }
        #fauth_activity_widget .fauth-dash-stat { flex:1; text-align:center; background:#f6f7f7; border:1px solid #e0e0e0; border-radius:10px; padding:12px 6px; }
        #fauth_activity_widget .fauth-dash-stat .num { display:block; font-size:1.5rem; font-weight:700; line-height:1.2; }
        #fauth_activity_widget .fauth-dash-stat .lbl { display:block; font-size:0.72rem; color:#646970; text-transform:uppercase; letter-spacing:.02em; margin-top:2px; }
        #fauth_activity_widget .fauth-dash-stat.ok   .num { color:#00794f; }
        #fauth_activity_widget .fauth-dash-stat.fail .num { color:#b32d2e; }
        #fauth_activity_widget .fauth-dash-stat.lock .num { color:#9a6700; }
        #fauth_activity_widget h4 { margin:14px 0 6px; font-size:0.82rem; text-transform:uppercase; letter-spacing:.02em; color:#1d2327; }
        #fauth_activity_widget table.fauth-dash-table { width:100%; border-collapse:collapse; }
        #fauth_activity_widget table.fauth-dash-table td { padding:5px 0; border-bottom:1px solid #f0f0f1; font-size:0.86rem; }
        #fauth_activity_widget table.fauth-dash-table tr:last-child td { border-bottom:none; }
        #fauth_activity_widget table.fauth-dash-table td.cnt { text-align:right; font-weight:600; color:#646970; white-space:nowrap; }
        #fauth_activity_widget .fauth-dash-cols { display:flex; gap:22px; flex-wrap:wrap; }
        #fauth_activity_widget .fauth-dash-cols > div { flex:1; min-width:180px; }
        #fauth_activity_widget .fauth-dash-empty { color:#646970; font-style:italic; font-size:0.85rem; }
        #fauth_activity_widget .fauth-pill { display:inline-block; font-size:0.7rem; font-weight:600; padding:1px 7px; border-radius:10px; }
        #fauth_activity_widget .fauth-pill.ok   { background:#edf7f1; color:#00794f; }
        #fauth_activity_widget .fauth-pill.fail { background:#fcefef; color:#b32d2e; }
        #fauth_activity_widget .fauth-pill.lock { background:#fdf6e7; color:#9a6700; }
        #fauth_activity_widget .fauth-dash-foot { margin:14px 0 0; font-size:0.8rem; }
    </style>

    <div class="fauth-dash-stats">
        <div class="fauth-dash-stat ok">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['success'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Successful', 'frontend-auth' ); ?></span>
        </div>
        <div class="fauth-dash-stat fail">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['failed'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Failed', 'frontend-auth' ); ?></span>
        </div>
        <div class="fauth-dash-stat lock">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['lockouts'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Lockouts', 'frontend-auth' ); ?></span>
        </div>
    </div>
    <p class="description" style="margin-top:-8px;">
        <?php
        printf(
            /* translators: %d: number of days */
            esc_html__( 'Last %d days.', 'frontend-auth' ),
            (int) $days
        );
        ?>
    </p>

    <div class="fauth-dash-cols">
        <div>
            <h4><?php esc_html_e( 'Top failed logins', 'frontend-auth' ); ?></h4>
            <?php fauth_dash_top_table( (array) $data['top_failed'], __( 'No failed logins.', 'frontend-auth' ) ); ?>
        </div>
        <div>
            <h4><?php esc_html_e( 'Top blocked IPs', 'frontend-auth' ); ?></h4>
            <?php fauth_dash_top_table( (array) $data['top_blocked'], __( 'No lockouts — nobody has been blocked.', 'frontend-auth' ) ); ?>
        </div>
    </div>

    <h4><?php esc_html_e( 'Recent activity', 'frontend-auth' ); ?></h4>
    <?php fauth_dash_recent_table( (array) $data['recent'] ); ?>

    <p class="fauth-dash-foot">
        <a href="<?php echo esc_url( admin_url( 'admin.php?page=frontend-auth' ) ); ?>"><?php esc_html_e( 'Activity log settings →', 'frontend-auth' ); ?></a>
    </p>
    <?php
}

/**
 * Render a two-column "label / count" table for the Top lists.
 *
 * @param array<int,object> $rows  Rows of { label, cnt }.
 * @param string            $empty Message when there are no rows.
 */
function fauth_dash_top_table( array $rows, string $empty ): void {
    if ( empty( $rows ) ) {
        echo '<p class="fauth-dash-empty">' . esc_html( $empty ) . '</p>';
        return;
    }
    echo '<table class="fauth-dash-table"><tbody>';
    foreach ( $rows as $row ) {
        $label = '' !== (string) $row->label ? (string) $row->label : '—';
        echo '<tr><td>' . esc_html( $label ) . '</td><td class="cnt">' . esc_html( number_format_i18n( (int) $row->cnt ) ) . '</td></tr>';
    }
    echo '</tbody></table>';
}

/**
 * Render the recent-events table.
 *
 * @param array<int,object> $rows Rows of { event, user_id, user_login, ip, created_at }.
 */
function fauth_dash_recent_table( array $rows ): void {
    if ( empty( $rows ) ) {
        echo '<p class="fauth-dash-empty">' . esc_html__( 'No activity recorded yet.', 'frontend-auth' ) . '</p>';
        return;
    }

    $labels = [
        'login_success' => [ 'ok',   __( 'Login', 'frontend-auth' ) ],
        'login_failed'  => [ 'fail', __( 'Failed', 'frontend-auth' ) ],
        'lockout'       => [ 'lock', __( 'Lockout', 'frontend-auth' ) ],
    ];

    $now = time();

    echo '<table class="fauth-dash-table"><tbody>';
    foreach ( $rows as $row ) {
        $meta  = $labels[ $row->event ] ?? [ '', $row->event ];
        $when  = strtotime( (string) $row->created_at . ' UTC' );
        $ago   = $when ? sprintf(
            /* translators: %s: human-readable time difference, e.g. "5 mins" */
            __( '%s ago', 'frontend-auth' ),
            human_time_diff( $when, $now )
        ) : '';

        // For lockouts the meaningful identifier is the IP; otherwise the username.
        if ( 'lockout' === $row->event ) {
            $who = '' !== (string) $row->ip ? (string) $row->ip : '—';
        } else {
            $who = '' !== (string) $row->user_login ? (string) $row->user_login : '—';
        }

        echo '<tr>';
        echo '<td><span class="fauth-pill ' . esc_attr( $meta[0] ) . '">' . esc_html( $meta[1] ) . '</span></td>';
        echo '<td>' . esc_html( $who ) . '</td>';
        echo '<td class="cnt">' . esc_html( $ago ) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table>';
}

/* -----------------------------------------------------------------------
 * "Clear activity log" handler (button lives on the settings page).
 * -------------------------------------------------------------------- */

add_action( 'admin_post_fauth_clear_activity', 'fauth_admin_handle_clear_activity' );

function fauth_admin_handle_clear_activity(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'frontend-auth' ), 403 );
    }
    check_admin_referer( 'fauth_clear_activity', 'fauth_activity_nonce' );
    fauth_activity_clear();
    wp_safe_redirect( add_query_arg( 'fauth_notice', 'activity_cleared', admin_url( 'admin.php?page=frontend-auth' ) ) );
    exit;
}
