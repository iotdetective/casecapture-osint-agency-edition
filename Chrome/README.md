# CaseCapture OSINT Chrome v0.6.3

CaseCapture OSINT is a local-first Chrome extension for investigator-initiated capture and documentation of HTTP and HTTPS webpages.

## Release highlights

- Uses Manifest V3.
- Uses `activeTab` rather than persistent `<all_urls>` host access.
- Supports HTTP and HTTPS webpage capture only.
- Creates a visible-viewport screenshot and attempts a supplemental full-page screenshot.
- Uses the Chrome `debugger` permission only for full-page screenshot generation and related page-rendering measurements.
- Does not use Chrome DevTools Protocol to collect remote IP addresses, ports, DNS, WHOIS, RDAP, CDN, VPN/proxy, or other network-attribution information.
- Generates a structured evidence ZIP and a separate SHA-256 checksum file locally.
- Opens an Investigator Supplement after a successful primary capture for separately documented observations, research, and supplemental files.
- Allows intentional reuse of the most recent Case Number, Item / Evidence Number, Investigator, and Agency during the current Chrome session.
- New capture forms always open blank; reusable information is loaded only when the user selects **Use Last Case Information**.
- Investigator Notes are never retained for reuse.
- Reusable case information and temporary supplement linkage are session-scoped and are cleared when the Chrome session ends.

## Installation from source

1. Extract the release ZIP.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Select the folder containing `manifest.json`.
6. Pin **CaseCapture OSINT** if desired.

CaseCapture is intended to capture ordinary HTTP and HTTPS webpages. Chrome internal pages, extension pages, and local files are outside the supported capture scope.

## Basic capture workflow

1. Navigate to the target HTTP or HTTPS webpage and allow it to load.
2. Open CaseCapture OSINT.
3. Enter the case information for the capture.
4. If continuing work on the same case during the same Chrome session, optionally select **Use Last Case Information** and review every populated field.
5. Enter capture-specific Investigator Notes, if appropriate.
6. Begin the capture and keep the target tab active until completion.
7. Preserve the generated evidence ZIP and its `.sha256.txt` checksum file together.
8. Complete the Investigator Supplement if additional observations, actions, or separately obtained research should be documented.

## Network attribution and infrastructure research

CaseCapture preserves the webpage and related capture information. It does not conduct IP-address attribution, DNS research, WHOIS/RDAP research, hosting-provider identification, CDN analysis, VPN/proxy attribution, traceroute, or similar infrastructure investigation.

The investigator is responsible for conducting any such research separately from the CaseCapture collection process and documenting relevant findings in the Investigator Supplement.

The evidence package may include `network/performance_resource_timing.json`. This file contains browser Performance API navigation/resource timing information associated with rendering the selected page. It is not a network-attribution artifact and does not contain CDP-observed remote IP/port data, request headers, cookie values, or the investigator's local/source IP address.

## Investigator Supplement

The supplement can document:

- Page interaction and access context.
- Investigator actions and purpose.
- Observations made during review.
- Separately obtained research such as WHOIS, RDAP, DNS, IP ownership, certificate, or social-media research.
- Supplemental files selected by the investigator.

Imported supplemental files are hashed with SHA-256. The supplement manifest records the SHA-256 of the completed primary evidence ZIP so the supplement can be linked to the original capture without modifying it.

Supplemental files are limited to 25 MB each and 100 MB total.

## Privacy and minimization

CaseCapture is local-first and does not require a developer-operated evidence server. It intentionally avoids collection of credential values, cookie values, request-header contents, local/source IP addresses, public-IP attribution, OS-level DNS-cache information, WHOIS/RDAP results, localStorage/sessionStorage values, local file paths, and unrelated files from the investigator's computer.

Case information retained for optional reuse is held only for the current Chrome session. Investigator Notes are not retained for reuse.

See the repository `PRIVACY.md` for the current public privacy policy.

## Important limitations

CaseCapture is a documentation aid. It does not independently authenticate the author of online content, account ownership, platform records, subscriber records, server-side records, or content that was not displayed during the capture.

Full-page screenshots are supplemental and may be affected by dynamic content, lazy loading, sticky/fixed elements, animations, embedded media, responsive layout changes, infinite scrolling, or browser image-size limitations.

The visible viewport screenshot should generally be treated as the primary visual record of what was directly displayed to the investigator. Review `method_log.json` for capture warnings or failures.

## License and use

Review the project repository for licensing, security, privacy, and disclaimer information. Users remain responsible for compliance with applicable law, court rules, agency policy, evidence-handling requirements, privacy obligations, and record-retention requirements.
