# Changelog

All notable changes to CaseCapture OSINT Agency Edition will be documented in this file.

This project uses simple version numbering during early development:

- Patch updates, such as `v0.5.2`, are for bug fixes, documentation updates, and small improvements.
- Minor updates, such as `v0.6.0`, are for new features or meaningful changes to capture behavior.
- A future `v1.0.0` release should represent a more stable baseline after testing and validation.

---

## v0.6.3 — 2026-08-23

### Chrome Release

- Promoted the tested Chrome v0.6.3 build to a production release.
- Added the CaseCapture icon set at 16, 32, 48, and 128 pixels and wired the icons into the extension manifest and toolbar action.
- Updated the manifest description for public distribution.

### Permissions and Capture Scope

- Removed persistent `<all_urls>` host access.
- Removed the `tabs` permission.
- Uses user-initiated `activeTab` access for the selected webpage.
- Limited supported capture targets to ordinary HTTP and HTTPS webpages.
- Retained the Chrome `debugger` permission only for full-page screenshot generation and related page-rendering measurements.
- Removed Chrome DevTools Protocol network-event collection, including remote IP/port observations.

### Network Research Separation

- Removed automatic network-attribution collection from the Chrome capture workflow.
- Clarified that IP, DNS, WHOIS/RDAP, hosting-provider, CDN, VPN/proxy, traceroute, and related network research is the investigator's responsibility and occurs separately from the CaseCapture collection process.
- Added/updated notices directing investigators to document separately obtained network or infrastructure findings in the Investigator Supplement.
- Retained browser Performance API resource timing information as a rendering/resource observation, not as a network-attribution artifact.

### Investigator Supplement

- Added the linked Investigator Supplement workflow for investigator-authored observations, actions, access context, separately obtained research, and supplemental files.
- Supplemental files are individually hashed with SHA-256.
- The supplement records the SHA-256 of the completed primary evidence ZIP, linking the two packages without modifying the original capture.
- Supports multiple separately obtained research entries.
- Supports repeated file selections, descriptions/provenance, and removal before supplement finalization.
- Supplemental files are limited to 25 MB each and 100 MB total.

### Case Information Reuse

- New capture forms always open blank.
- Added **Use Last Case Information** to intentionally restore the most recent Case Number, Item / Evidence Number, Investigator, and Agency during the current Chrome session.
- Added **Clear Saved Case Information**.
- Investigator Notes are never retained for reuse.
- Reusable case information is saved only after a successful primary capture.
- Reusable case information and temporary supplement linkage use Chrome session storage and are cleared when the browser session ends.
- Legacy persistent case information from earlier test builds is migrated into the current session once and removed from persistent local storage.

### Documentation and Privacy

- Updated capture reports, manifests, method logs, artifact guidance, limitations, and privacy-minimization documentation to match the narrower Chrome collection behavior.
- Added a public privacy policy in `PRIVACY.md`.

## v0.5.1

### Added

- Added plain-English quick link explanations to the exported `index.html` review page.
- Added local-first ZIP evidence package generation.
- Added visible viewport screenshot capture.
- Added supplemental full-page screenshot capture.
- Added rendered HTML snapshot.
- Added readable HTML review copy.
- Added visible text extraction.
- Added link extraction.
- Added image reference extraction.
- Added meta tag extraction.
- Added browser environment metadata.
- Added DOM summary.
- Added resource inventory.
- Added privacy-limited storage inventory.
- Added limited Chrome DevTools network observations.
- Added method log.
- Added SHA-256 hash documentation.
- Added embedded documentation inside exported capture packages.

### Documentation

- Added collection guidance for clean investigative environments.
- Added artifact guide explaining generated files.
- Added validation guidance.
- Added privacy and limitation guidance.
- Added installation instructions.
- Added troubleshooting guidance.

### Privacy / Minimization

- Avoids intentional collection of cookie values.
- Avoids intentional collection of credential values.
- Avoids intentional collection of request headers.
- Avoids intentional collection of local/source IP address.
- Avoids intentional collection of public IP address.
- Avoids traceroute collection.
- Avoids OS-level DNS, WHOIS, and RDAP collection.
- Avoids sensitive browser storage values.

### Known Limitations

- Full-page screenshots are supplemental and may be affected by dynamic content, lazy loading, sticky headers, animations, embedded media, or page resizing.
- HTML snapshots may not visually match the live page because many websites depend on live scripts, stylesheets, images, and session state.
- The tool documents what was observed in the investigator’s Chrome browser session; it does not independently authenticate authorship, account ownership, platform records, or server-side records.
- The tool is not NIST-certified, court-certified, or guaranteed admissible.

---

## Pre-v0.5.1

Initial development versions used for testing core capture functions, ZIP export, screenshots, reports, documentation, and hashing.
