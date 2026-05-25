<?php
/**
 * Plugin Name: CSP Violation Reporter
 * Description: Collects Content Security Policy violation reports through a WordPress REST endpoint and displays them in the admin dashboard.
 * Version: 0.1.1
 * Requires at least: 6.5
 * Requires PHP: 7.4
 * Author: Guilherme Dumas Peres
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: csp-violation-reporter
 *
 * @package CSPViolationReporter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'CSPVR_VERSION', '0.1.1' );
define( 'CSPVR_TABLE_VERSION', '1' );
define( 'CSPVR_REST_NAMESPACE', 'csp-violation-reporter/v1' );
define( 'CSPVR_REST_ROUTE', '/report' );
define( 'CSPVR_CACHE_GROUP', 'cspvr_reports' );

/**
 * Returns the custom table name.
 *
 * @return string
 */
function cspvr_table_name() {
	global $wpdb;

	return $wpdb->prefix . 'cspvr_reports';
}

/**
 * Returns the cache version for report list queries.
 *
 * @return string
 */
function cspvr_get_reports_cache_last_changed() {
	$last_changed = wp_cache_get( 'last_changed', CSPVR_CACHE_GROUP );

	if ( false === $last_changed ) {
		$last_changed = microtime();
		wp_cache_set( 'last_changed', $last_changed, CSPVR_CACHE_GROUP );
	}

	return (string) $last_changed;
}

/**
 * Invalidates cached report list queries.
 *
 * @return void
 */
function cspvr_bump_reports_cache() {
	wp_cache_set( 'last_changed', microtime(), CSPVR_CACHE_GROUP );
}

/**
 * Creates or updates the reports table.
 *
 * @return void
 */
function cspvr_activate() {
	global $wpdb;

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	$table_name      = cspvr_table_name();
	$charset_collate = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE {$table_name} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		created_at_gmt datetime NOT NULL,
		document_uri text NOT NULL,
		referrer text NULL,
		blocked_uri text NULL,
		violated_directive varchar(255) NULL,
		effective_directive varchar(255) NULL,
		original_policy text NULL,
		disposition varchar(32) NULL,
		status_code smallint(5) unsigned NULL,
		source_file text NULL,
		line_number int(10) unsigned NULL,
		column_number int(10) unsigned NULL,
		sample text NULL,
		user_agent varchar(255) NULL,
		remote_addr_hash varchar(64) NULL,
		raw_report longtext NULL,
		PRIMARY KEY  (id),
		KEY created_at_gmt (created_at_gmt),
		KEY effective_directive (effective_directive(191)),
		KEY disposition (disposition)
	) {$charset_collate};";

	dbDelta( $sql );
	update_option( 'cspvr_table_version', CSPVR_TABLE_VERSION );
}
register_activation_hook( __FILE__, 'cspvr_activate' );

/**
 * Registers the public reporting endpoint.
 *
 * @return void
 */
function cspvr_register_rest_routes() {
	register_rest_route(
		CSPVR_REST_NAMESPACE,
		CSPVR_REST_ROUTE,
		array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => 'cspvr_receive_report',
			'permission_callback' => '__return_true',
		)
	);
}
add_action( 'rest_api_init', 'cspvr_register_rest_routes' );

/**
 * Handles incoming CSP violation reports.
 *
 * @param WP_REST_Request $request Request object.
 * @return WP_REST_Response|WP_Error
 */
function cspvr_receive_report( WP_REST_Request $request ) {
	$body = $request->get_body();

	if ( '' === trim( $body ) ) {
		return new WP_Error( 'cspvr_empty_body', __( 'The report body is empty.', 'csp-violation-reporter' ), array( 'status' => 400 ) );
	}

	if ( strlen( $body ) > 262144 ) {
		return new WP_Error( 'cspvr_body_too_large', __( 'The report body is too large.', 'csp-violation-reporter' ), array( 'status' => 413 ) );
	}

	$decoded = json_decode( $body, true );
	if ( JSON_ERROR_NONE !== json_last_error() ) {
		return new WP_Error( 'cspvr_invalid_json', __( 'The report body must be valid JSON.', 'csp-violation-reporter' ), array( 'status' => 400 ) );
	}

	$reports = cspvr_normalize_reports( $decoded );
	if ( empty( $reports ) ) {
		return new WP_Error( 'cspvr_invalid_report', __( 'No CSP violation report was found in the request.', 'csp-violation-reporter' ), array( 'status' => 400 ) );
	}

	$stored = 0;
	foreach ( $reports as $report ) {
		if ( cspvr_store_report( $report, $request ) ) {
			++$stored;
		}
	}

	return rest_ensure_response(
		array(
			'stored' => $stored,
		)
	);
}

/**
 * Normalizes supported CSP report formats into report bodies.
 *
 * @param mixed $decoded Decoded JSON payload.
 * @return array<int,array<string,mixed>>
 */
function cspvr_normalize_reports( $decoded ) {
	if ( isset( $decoded['csp-report'] ) && is_array( $decoded['csp-report'] ) ) {
		return array( $decoded['csp-report'] );
	}

	if ( isset( $decoded['type'], $decoded['body'] ) && is_array( $decoded['body'] ) && 'csp-violation' === $decoded['type'] ) {
		return array( $decoded['body'] );
	}

	if ( is_array( $decoded ) && wp_is_numeric_array( $decoded ) ) {
		$reports = array();
		foreach ( $decoded as $item ) {
			if ( is_array( $item ) && isset( $item['type'], $item['body'] ) && 'csp-violation' === $item['type'] && is_array( $item['body'] ) ) {
				$reports[] = $item['body'];
			} elseif ( is_array( $item ) && isset( $item['csp-report'] ) && is_array( $item['csp-report'] ) ) {
				$reports[] = $item['csp-report'];
			}
		}

		return $reports;
	}

	return array();
}

/**
 * Stores one normalized CSP report.
 *
 * @param array<string,mixed> $report  Normalized report body.
 * @param WP_REST_Request     $request Request object.
 * @return bool
 */
function cspvr_store_report( array $report, WP_REST_Request $request ) {
	global $wpdb;

	$document_uri = cspvr_get_string( $report, array( 'document-uri', 'documentURL', 'url' ) );
	if ( '' === $document_uri ) {
		return false;
	}

	$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$user_agent  = $request->get_header( 'user_agent' );

	$data = array(
		'created_at_gmt'      => current_time( 'mysql', true ),
		'document_uri'        => esc_url_raw( $document_uri ),
		'referrer'            => esc_url_raw( cspvr_get_string( $report, array( 'referrer' ) ) ),
		'blocked_uri'         => sanitize_text_field( cspvr_get_string( $report, array( 'blocked-uri', 'blockedURL' ) ) ),
		'violated_directive'  => sanitize_text_field( cspvr_get_string( $report, array( 'violated-directive' ) ) ),
		'effective_directive' => sanitize_text_field( cspvr_get_string( $report, array( 'effective-directive', 'effectiveDirective' ) ) ),
		'original_policy'     => sanitize_textarea_field( cspvr_get_string( $report, array( 'original-policy' ) ) ),
		'disposition'         => sanitize_key( cspvr_get_string( $report, array( 'disposition' ) ) ),
		'status_code'         => cspvr_get_int( $report, array( 'status-code', 'statusCode' ) ),
		'source_file'         => esc_url_raw( cspvr_get_string( $report, array( 'source-file', 'sourceFile' ) ) ),
		'line_number'         => cspvr_get_int( $report, array( 'line-number', 'lineNumber' ) ),
		'column_number'       => cspvr_get_int( $report, array( 'column-number', 'columnNumber' ) ),
		'sample'              => sanitize_textarea_field( cspvr_get_string( $report, array( 'sample' ) ) ),
		'user_agent'          => sanitize_text_field( substr( (string) $user_agent, 0, 255 ) ),
		'remote_addr_hash'    => '' !== $remote_addr ? hash_hmac( 'sha256', $remote_addr, wp_salt( 'nonce' ) ) : '',
		'raw_report'          => wp_json_encode( $report ),
	);

	$formats = array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d', '%d', '%s', '%s', '%s', '%s' );

	$inserted = false !== $wpdb->insert( cspvr_table_name(), $data, $formats ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Reports are stored in the plugin's custom table.

	if ( $inserted ) {
		cspvr_bump_reports_cache();
	}

	return $inserted;
}

/**
 * Reads a string value from the first matching key.
 *
 * @param array<string,mixed> $report Report body.
 * @param array<int,string>   $keys Possible keys.
 * @return string
 */
function cspvr_get_string( array $report, array $keys ) {
	foreach ( $keys as $key ) {
		if ( isset( $report[ $key ] ) && is_scalar( $report[ $key ] ) ) {
			return (string) $report[ $key ];
		}
	}

	return '';
}

/**
 * Reads an unsigned integer from the first matching key.
 *
 * @param array<string,mixed> $report Report body.
 * @param array<int,string>   $keys Possible keys.
 * @return int|null
 */
function cspvr_get_int( array $report, array $keys ) {
	foreach ( $keys as $key ) {
		if ( isset( $report[ $key ] ) && is_numeric( $report[ $key ] ) ) {
			return max( 0, absint( $report[ $key ] ) );
		}
	}

	return null;
}

/**
 * Registers the admin menu.
 *
 * @return void
 */
function cspvr_register_admin_menu() {
	add_management_page(
		__( 'CSP Violations', 'csp-violation-reporter' ),
		__( 'CSP Violations', 'csp-violation-reporter' ),
		'manage_options',
		'csp-violation-reporter',
		'cspvr_render_admin_page'
	);
}
add_action( 'admin_menu', 'cspvr_register_admin_menu' );

/**
 * Handles admin actions.
 *
 * @return void
 */
function cspvr_handle_admin_actions() {
	if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( empty( $_GET['page'] ) || 'csp-violation-reporter' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) {
		return;
	}

	if ( isset( $_POST['cspvr_clear_reports'] ) ) {
		check_admin_referer( 'cspvr_clear_reports' );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', cspvr_table_name() ) );
		cspvr_bump_reports_cache();
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'          => 'csp-violation-reporter',
					'cspvr_cleared' => '1',
				),
				admin_url( 'tools.php' )
			)
		);
		exit;
	}
}
add_action( 'admin_init', 'cspvr_handle_admin_actions' );

/**
 * Renders the admin reports page.
 *
 * @return void
 */
function cspvr_render_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to view CSP violation reports.', 'csp-violation-reporter' ) );
	}

	global $wpdb;

	$table_name = cspvr_table_name();
	$paged      = 1;
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only pagination parameter.
	if ( isset( $_GET['paged'] ) ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only pagination parameter.
		$paged = max( 1, absint( wp_unslash( $_GET['paged'] ) ) );
	}

	$per_page   = 20;
	$offset     = ( $paged - 1 ) * $per_page;
	$cache_salt = cspvr_get_reports_cache_last_changed();
	$total_key  = 'total_' . $cache_salt;
	$list_key   = 'list_' . md5( $per_page . ':' . $offset . ':' . $cache_salt );
	$total      = wp_cache_get( $total_key, CSPVR_CACHE_GROUP );
	$reports    = wp_cache_get( $list_key, CSPVR_CACHE_GROUP );

	if ( false === $total ) {
		$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Reports are read from the plugin's custom table.
		wp_cache_set( $total_key, $total, CSPVR_CACHE_GROUP, MINUTE_IN_SECONDS );
	}

	if ( false === $reports ) {
		$reports = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY created_at_gmt DESC, id DESC LIMIT %d OFFSET %d', $table_name, $per_page, $offset ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Reports are read from the plugin's custom table.
		wp_cache_set( $list_key, $reports, CSPVR_CACHE_GROUP, MINUTE_IN_SECONDS );
	}

	$endpoint   = rest_url( CSPVR_REST_NAMESPACE . CSPVR_REST_ROUTE );
	$total_page = max( 1, (int) ceil( $total / $per_page ) );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'CSP Violations', 'csp-violation-reporter' ); ?></h1>

		<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only success notice after a nonce-protected redirect. ?>
		<?php if ( isset( $_GET['cspvr_cleared'] ) ) : ?>
			<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'CSP violation reports cleared.', 'csp-violation-reporter' ); ?></p></div>
		<?php endif; ?>

		<p>
			<?php esc_html_e( 'Report endpoint:', 'csp-violation-reporter' ); ?>
			<code><?php echo esc_html( $endpoint ); ?></code>
		</p>
		<p>
			<?php esc_html_e( 'Use this URL as the endpoint in a Reporting API group, then reference that group from the CSP report-to directive.', 'csp-violation-reporter' ); ?>
		</p>

		<form method="post" action="">
			<?php wp_nonce_field( 'cspvr_clear_reports' ); ?>
			<p>
				<input type="submit" name="cspvr_clear_reports" class="button button-secondary" value="<?php esc_attr_e( 'Clear all reports', 'csp-violation-reporter' ); ?>" onclick="return confirm('<?php echo esc_js( __( 'Delete all stored CSP violation reports?', 'csp-violation-reporter' ) ); ?>');">
			</p>
		</form>

		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Date', 'csp-violation-reporter' ); ?></th>
					<th><?php esc_html_e( 'Directive', 'csp-violation-reporter' ); ?></th>
					<th><?php esc_html_e( 'Blocked URI', 'csp-violation-reporter' ); ?></th>
					<th><?php esc_html_e( 'Document', 'csp-violation-reporter' ); ?></th>
					<th><?php esc_html_e( 'Disposition', 'csp-violation-reporter' ); ?></th>
					<th><?php esc_html_e( 'Location', 'csp-violation-reporter' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $reports ) ) : ?>
					<tr><td colspan="6"><?php esc_html_e( 'No CSP violation reports have been received yet.', 'csp-violation-reporter' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $reports as $report ) : ?>
						<tr>
							<td><?php echo esc_html( get_date_from_gmt( $report->created_at_gmt, 'Y-m-d H:i:s' ) ); ?></td>
							<td><?php echo esc_html( $report->effective_directive ? $report->effective_directive : $report->violated_directive ); ?></td>
							<td><code><?php echo esc_html( $report->blocked_uri ); ?></code></td>
							<td><code><?php echo esc_html( $report->document_uri ); ?></code></td>
							<td><?php echo esc_html( $report->disposition ); ?></td>
							<td>
								<?php
								$location = '';
								if ( ! empty( $report->source_file ) ) {
									$location = $report->source_file;
									if ( null !== $report->line_number ) {
										$location .= ':' . $report->line_number;
									}
									if ( null !== $report->column_number ) {
										$location .= ':' . $report->column_number;
									}
								}
								echo esc_html( $location );
								?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $total_page > 1 ) : ?>
			<div class="tablenav bottom">
				<div class="tablenav-pages">
					<?php
					echo wp_kses_post(
						paginate_links(
							array(
								'base'      => add_query_arg( array( 'paged' => '%#%' ) ),
								'format'    => '',
								'current'   => $paged,
								'total'     => $total_page,
								'prev_text' => __( '&laquo;', 'csp-violation-reporter' ),
								'next_text' => __( '&raquo;', 'csp-violation-reporter' ),
							)
						)
					);
					?>
				</div>
			</div>
		<?php endif; ?>
	</div>
	<?php
}
