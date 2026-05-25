=== CSP Violation Reporter ===
Contributors: guidumasperes
Tags: csp, security, reporting, content-security-policy, reports
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 0.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Collect Content Security Policy violation reports through a WordPress REST endpoint and review them in the admin dashboard.

== Description ==

CSP Violation Reporter adds a public WordPress REST endpoint for browser Content Security Policy violation reports and stores received violations in a local database table.

Reports can be reviewed from Tools > CSP Violations. The plugin supports the modern Reporting API payload format as well as the older `csp-report` JSON shape.

Endpoint:

`/wp-json/csp-violation-reporter/v1/report`

The plugin does not create or modify Content Security Policy headers. Site owners should configure CSP headers in their web server, hosting dashboard, theme, or security tooling.

Example report endpoint configuration:

`Content-Security-Policy: default-src 'self'; report-uri https://example.com/wp-json/csp-violation-reporter/v1/report`

For the modern Reporting API, use an HTTPS endpoint:

`Reporting-Endpoints: csp-endpoint="https://example.com/wp-json/csp-violation-reporter/v1/report"`

`Content-Security-Policy: default-src 'self'; report-to csp-endpoint`

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

= Does the plugin send data to third parties? =

No. Reports are stored in the site's own WordPress database.

== Privacy ==

This plugin stores CSP violation reports submitted by browsers. Stored fields can include the document URL, referrer URL, blocked URI, violated directive, source file, line and column numbers, a user agent string, a salted hash of the remote address, and the raw report payload.

The plugin does not store raw IP addresses and does not transmit report data to external services.

== Changelog ==

= 0.1.1 =

* Prepared SQL statements that include the plugin's custom table name.

= 0.1.0 =

* Initial development release.
