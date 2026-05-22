=== CSP Violation Reporter ===
Contributors: Guilherme Dumas Peres
Tags: csp, security, reporting, content-security-policy, reports
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Collect Content Security Policy violation reports through a WordPress REST endpoint and review them in the admin dashboard.

== Description ==

CSP Violation Reporter adds a public WordPress REST endpoint for browser Content Security Policy violation reports and stores received violations in a local database table.

Reports can be reviewed from Tools > CSP Violations. The plugin supports the modern Reporting API payload format as well as the older `csp-report` JSON shape.

Endpoint:

`/wp-json/csp-violation-reporter/v1/report`

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate the plugin through the Plugins screen in WordPress.
3. Open Tools > CSP Violations to copy the reporting endpoint.
4. Configure your CSP Reporting API group and reference it from your `report-to` directive.

== Frequently Asked Questions ==

= Does this plugin set my CSP header? =

No. This plugin receives and displays CSP violation reports. CSP header generation is intentionally left to your theme, server, security plugin, or hosting environment.

= Is the report endpoint public? =

Yes. Browser violation reports are sent without WordPress authentication. Admin views remain protected by the `manage_options` capability.

= Does the plugin store visitor IP addresses? =

No. The plugin stores a salted hash of the remote address to help with deduplication and abuse analysis without retaining the raw IP address.

== Changelog ==

= 0.1.0 =

* Initial development release.
