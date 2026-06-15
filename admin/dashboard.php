<?php
/**
 * Zen Login & Authentication – Dashboard Widget
 *
 * A "Login Activity" widget on the main WordPress dashboard (wp-admin/index.php)
 * summarising successful logins, failed attempts, and rate-limit lockouts over
 * the past week, plus the worst offenders and recent events. Data comes from
 * includes/activity-log.php.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

add_action( 'wp_dashboard_setup', 'zenlogau_register_dashboard_widget' );

function zenlogau_register_dashboard_widget(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    wp_add_dashboard_widget(
        'zenlogau_activity_widget',
        __( 'Zen Login & Authentication — Login Activity', 'zen-login-authentication' ),
        'zenlogau_render_dashboard_widget'
    );
}

/**
 * Render the dashboard widget body.
 */
function zenlogau_render_dashboard_widget(): void {
    if ( ! zenlogau_activity_logging_enabled() ) {
        echo '<p>' . wp_kses(
            sprintf(
                /* translators: %s: settings page URL */
                __( 'Login activity logging is turned off. Enable it under <a href="%s">Zen Login & Authentication → Settings</a>.', 'zen-login-authentication' ),
                esc_url( admin_url( 'admin.php?page=zen-login-authentication' ) )
            ),
            [ 'a' => [ 'href' => [] ] ]
        ) . '</p>';
        return;
    }

    $data = zenlogau_activity_get_summary();
    $days = (int) $data['days'];
    ?>
    <div class="fauth-dash-stats">
        <div class="fauth-dash-stat ok">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['success'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Successful', 'zen-login-authentication' ); ?></span>
        </div>
        <div class="fauth-dash-stat fail">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['failed'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Failed', 'zen-login-authentication' ); ?></span>
        </div>
        <div class="fauth-dash-stat lock">
            <span class="num"><?php echo esc_html( number_format_i18n( (int) $data['lockouts'] ) ); ?></span>
            <span class="lbl"><?php esc_html_e( 'Lockouts', 'zen-login-authentication' ); ?></span>
        </div>
    </div>
    <p class="description" style="margin-top:-8px;">
        <?php
        printf(
            /* translators: %d: number of days */
            esc_html__( 'Last %d days.', 'zen-login-authentication' ),
            (int) $days
        );
        ?>
    </p>

    <div class="fauth-dash-cols">
        <div>
            <h4><?php esc_html_e( 'Top failed logins', 'zen-login-authentication' ); ?></h4>
            <?php zenlogau_dash_top_table( (array) $data['top_failed'], __( 'No failed logins.', 'zen-login-authentication' ) ); ?>
        </div>
        <div>
            <h4><?php esc_html_e( 'Top blocked IPs', 'zen-login-authentication' ); ?></h4>
            <?php zenlogau_dash_top_table( (array) $data['top_blocked'], __( 'No lockouts — nobody has been blocked.', 'zen-login-authentication' ) ); ?>
        </div>
    </div>

    <h4><?php esc_html_e( 'Recent activity', 'zen-login-authentication' ); ?></h4>
    <?php zenlogau_dash_recent_table( (array) $data['recent'] ); ?>

    <p class="fauth-dash-foot">
        <a href="<?php echo esc_url( admin_url( 'admin.php?page=zen-login-authentication' ) ); ?>"><?php esc_html_e( 'Activity log settings →', 'zen-login-authentication' ); ?></a>
    </p>
    <?php
}

/**
 * Render a two-column "label / count" table for the Top lists.
 *
 * @param array<int,object> $rows  Rows of { label, cnt }.
 * @param string            $empty Message when there are no rows.
 */
function zenlogau_dash_top_table( array $rows, string $empty ): void {
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
function zenlogau_dash_recent_table( array $rows ): void {
    if ( empty( $rows ) ) {
        echo '<p class="fauth-dash-empty">' . esc_html__( 'No activity recorded yet.', 'zen-login-authentication' ) . '</p>';
        return;
    }

    $labels = [
        'login_success' => [ 'ok',   __( 'Login', 'zen-login-authentication' ) ],
        'login_failed'  => [ 'fail', __( 'Failed', 'zen-login-authentication' ) ],
        'lockout'       => [ 'lock', __( 'Lockout', 'zen-login-authentication' ) ],
    ];

    $now = time();

    echo '<table class="fauth-dash-table"><tbody>';
    foreach ( $rows as $row ) {
        $meta  = $labels[ $row->event ] ?? [ '', $row->event ];
        $when  = strtotime( (string) $row->created_at . ' UTC' );
        $ago   = $when ? sprintf(
            /* translators: %s: human-readable time difference, e.g. "5 mins" */
            __( '%s ago', 'zen-login-authentication' ),
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

add_action( 'admin_post_zenlogau_clear_activity', 'zenlogau_admin_handle_clear_activity' );

function zenlogau_admin_handle_clear_activity(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'zen-login-authentication' ), 403 );
    }
    check_admin_referer( 'zenlogau_clear_activity', 'zenlogau_activity_nonce' );
    zenlogau_activity_clear();
    wp_safe_redirect( add_query_arg( 'zenlogau_notice', 'activity_cleared', admin_url( 'admin.php?page=zen-login-authentication' ) ) );
    exit;
}
