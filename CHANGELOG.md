# Changelog

All notable changes to CaseCapture OSINT Agency Edition will be documented in this file.

This project uses simple version numbering during early development:

- Patch updates, such as `v0.5.2`, are for bug fixes, documentation updates, and small improvements.
- Minor updates, such as `v0.6.0`, are for new features or meaningful changes to capture behavior.
- A future `v1.0.0` release should represent a more stable baseline after testing and validation.

---

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
