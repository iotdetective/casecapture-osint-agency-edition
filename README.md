# CaseCapture OSINT Agency Edition

<img width="1024" height="1024" alt="ChatGPT Image Aug 1, 2026, 06_56_49 PM" src="https://github.com/user-attachments/assets/2bc1a153-7898-4a00-9cff-37df82226f85" />


CaseCapture OSINT Agency Edition is a local-first browser extension designed to help investigators, analysts, agencies, and other authorized users document web content observed during OSINT and online investigations.

The project includes editions for:

* Google Chrome and compatible Chromium-based browsers
* Mozilla Firefox

CaseCapture OSINT collects browser-observed information and exports it into a structured, reviewable evidence package.

<img width="378" height="487" alt="CaseCapture OSINT extension interface" src="https://github.com/user-attachments/assets/997a053d-98fc-4c13-93f4-b35282f7f314" />

---

## Overview

CaseCapture OSINT is designed to document what was displayed in the investigator’s browser at the time of capture.

Depending on the browser edition and the webpage being collected, the exported package may include:

* Visible viewport screenshot
* Supplemental full-page screenshot
* Page URL and title
* Capture date and time
* Browser and environment information
* Rendered HTML snapshot
* Readable HTML review copy
* Visible text extraction
* Extracted links
* Image references
* Meta tags
* DOM summary
* Resource inventory
* Privacy-limited browser-storage inventory
* Browser-supported network or performance observations
* Collection method log
* SHA-256 hashes
* ZIP evidence package
* Separate SHA-256 hash file for the completed ZIP
* Human-readable reports
* Embedded documentation
* `index.html` evidence-package landing page

The resulting package is intended to make captured material easier to preserve, review, explain, and validate.

---

## Browser Support

### Google Chrome

The Chrome edition uses browser APIs available in Google Chrome and other compatible Chromium-based browsers.

Depending on the release, Chrome-specific functionality may include limited use of Chrome DevTools Protocol features for:

* Page-rendering measurements
* Supplemental full-page screenshots
* Limited browser-observed network information

### Mozilla Firefox

The Firefox edition provides the same general interface, branding, case-information fields, hashing process, and evidence-package structure.

Firefox does not expose the same Chrome debugger interface to ordinary extensions. The Firefox edition therefore uses Firefox-compatible methods, including:

* Visible viewport capture
* Automated page scrolling
* Segmented screenshot capture
* Canvas-based full-page image stitching
* Resource Timing and Navigation Timing information
* DOM and resource inventories

The generated `method_log.json` identifies the browser and collection method used.

Because the underlying browser APIs differ, Chrome and Firefox captures should not be assumed to be technically identical even when they document the same webpage.

---

## Local-First Design

CaseCapture OSINT performs its collection and package-generation functions locally in the browser.

The extension does not require a CaseCapture cloud service or remote evidence-processing platform.

The tool is designed for controlled investigative environments such as:

* Windows Sandbox
* Clean virtual machines
* Ephemeral desktops
* Dedicated OSINT browser profiles
* Agency-managed forensic workstations
* Isolated research systems
* Controlled training environments

Using a separate investigative environment can help reduce contamination from personal accounts, unrelated browser history, saved credentials, extensions, cookies, and other investigator-specific information.

---

## Privacy-Conscious Collection

CaseCapture OSINT does not intentionally collect:

* Cookie values
* Passwords
* Credential values
* Authorization tokens
* Request-header contents
* Local IP addresses
* Public IP addresses
* Traceroute information
* Operating-system DNS-cache information
* WHOIS or RDAP data
* Sensitive browser-storage values
* Investigator file paths
* Unrelated files from the investigator’s computer

The extension may record the presence, name, size, or type of certain browser-accessible items without collecting their sensitive values.

Investigators should review generated packages before sharing them outside their agency or investigative team.

---

## Important Limitations

CaseCapture OSINT is a documentation tool.

It records what was displayed in the investigator’s browser session at the time of capture.

It does not independently authenticate:

* The author of online content
* The person controlling an online account
* The owner of an online account
* The operator of a website
* The creator of a webpage
* Subscriber information
* Login records
* Platform records
* Server-side records
* Historical content that was not displayed
* Content that changed before or after capture

The tool does not replace:

* Preservation requests
* Subpoenas
* Search warrants
* Court orders
* Platform disclosures
* Subscriber records
* Device examinations
* Forensic imaging
* Witness statements
* Admissions
* Agency validation
* Other lawful investigative methods

CaseCapture output should be evaluated together with the totality of the investigation.

---

## Full-Page Screenshot Limitations

The full-page screenshot is a supplemental artifact.

It may be affected by:

* Sticky or fixed headers
* Lazy-loaded content
* Infinite scrolling
* Animations
* Embedded media
* Popups
* Consent notices
* Rotating advertisements
* Responsive layout changes
* Content that changes while the page is being captured
* Browser canvas or image-size limitations

The visible viewport screenshot should generally be treated as the primary visual record of what was directly displayed to the investigator.

The `method_log.json` file should be reviewed for capture warnings, failures, or browser-specific collection details.

---

## Installation

### Chrome

1. Download and extract the Chrome source package.
2. Open:

```text
chrome://extensions/
```

3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Select the Chrome extension folder containing:

```text
manifest.json
```

6. Pin CaseCapture OSINT from the Chrome Extensions menu.

Chrome may restrict manually installed `.crx` files. The unpacked source method is recommended for testing and internal use.

### Firefox

1. Download and extract the Firefox source package.
2. Open:

```text
about:debugging
```

3. Select **This Firefox**.
4. Select **Load Temporary Add-on**.
5. Select the Firefox edition’s:

```text
manifest.json
```

6. Pin CaseCapture OSINT from the Firefox Extensions menu.

A temporarily loaded Firefox extension is removed when Firefox closes.

Permanent installation in standard Firefox releases generally requires a Mozilla-signed `.xpi` package.

---

## Basic Use

1. Open a normal public webpage.
2. Allow the page to fully load.
3. Open CaseCapture OSINT.
4. Enter the case information.
5. Begin the capture.
6. Keep the target tab active until the capture finishes.
7. Save both generated files:

```text
CaseCapture_....zip
CaseCapture_....zip.sha256.txt
```

8. Preserve the original ZIP.
9. Extract a working copy for review.
10. Open:

```text
index.html
```

Do not test the extension on protected browser pages such as:

```text
chrome://extensions/
chrome://settings/
about:debugging
about:addons
about:preferences
```

Regular browser extensions cannot capture many internal browser pages.

---

## Evidence Package

A successful capture may contain a structure similar to:

```text
CaseCapture_Package/
├── index.html
├── report.html
├── manifest.json
├── method_log.json
├── screenshots/
│   ├── screenshot_visible.png
│   └── screenshot_fullpage.png
├── page/
│   ├── page_snapshot.html
│   ├── page_snapshot_readable.html
│   └── visible_text.txt
├── extracted/
│   ├── links.json
│   ├── images.json
│   ├── meta_tags.json
│   ├── browser_environment.json
│   ├── storage_inventory.json
│   ├── dom_summary.json
│   └── resources.json
├── network/
├── documentation/
└── hashes/
```

The exact contents may vary by browser, webpage, extension version, and collection outcome.

---

## Integrity Verification

CaseCapture generates a SHA-256 hash for the completed evidence ZIP.

On Windows, the ZIP can be checked using PowerShell:

```powershell
Get-FileHash .\CaseCapture_PACKAGE.zip -Algorithm SHA256
```

Compare the result to:

```text
CaseCapture_PACKAGE.zip.sha256.txt
```

A matching hash confirms that the ZIP has not changed since the hash was generated.

Hash verification confirms file consistency. It does not independently establish the truth, ownership, authorship, or authenticity of the captured online content.

---

## Recommended Investigative Workflow

A suggested workflow is:

```text
1. Start a clean VM, sandbox, or dedicated OSINT browser profile.
2. Confirm the system date and time.
3. Load the appropriate Chrome or Firefox edition.
4. Navigate to the target webpage.
5. Allow the page to fully load.
6. Avoid unnecessary interaction.
7. Open CaseCapture OSINT.
8. Enter case and item information.
9. Start the capture.
10. Keep the target tab active.
11. Save the ZIP and SHA-256 file together.
12. Preserve the original ZIP.
13. Review from a working copy.
14. Verify hashes when needed.
15. Document any errors or unusual page behavior.
```

Investigators should also consider documenting:

* Browser used
* Extension version
* Target URL
* Date and time
* Whether authentication was required
* Whether dynamic content was present
* Whether the page changed during collection
* Whether screenshots appeared complete
* Any errors or limitations identified in the method log

---

## Repository Structure

A multi-browser repository may be organized as:

```text
CaseCapture-OSINT/
├── chrome/
├── firefox/
├── docs/
├── screenshots/
├── release/
├── README.md
├── LICENSE
├── CHANGELOG.md
└── SECURITY.md
```

Chrome and Firefox source files should remain in clearly labeled folders because browser-specific manifests and background scripts may not be interchangeable.

---

## Release Files

Release assets may include:

```text
CaseCapture_OSINT_Chrome_VERSION_source.zip
CaseCapture_OSINT_Chrome_VERSION.crx
CaseCapture_OSINT_Firefox_VERSION_source.zip
```

For most users:

* Use the unpacked source folder for Chrome.
* Use temporary source loading for Firefox.

---

## Development Status

CaseCapture OSINT is under active development.

Browser behavior, extension APIs, website designs, dynamic content, and browser security restrictions may affect collection results.

Users should test each release in a controlled environment before operational deployment.

Bug reports, compatibility findings, enhancement requests, and documentation improvements may be submitted through the repository’s Issues page.

When reporting a problem, include:

* Browser name and version
* CaseCapture version
* Operating system
* Type of webpage tested
* Error message
* Relevant `method_log.json` entries
* Screenshots with sensitive information removed

DO NOT upload evidence packages or sensitive investigative information to a public GitHub issue.

---

## Documentation

Additional documentation may be maintained in the project Wiki, including:

* Detailed Chrome installation
* Detailed Firefox installation
* Evidence-package structure
* Collection methodology
* Hash verification
* Troubleshooting
* Browser-specific limitations
* Investigative workflow recommendations
* Release validation procedures
* Security considerations
* Frequently asked questions

---

## Disclaimer

CaseCapture OSINT is intended for lawful, authorized use. Consult with your agency policy on proper use, authorization, and implementation of software or browser extensions. The source code is open for inspection to allow forensic experts to validate and confirm tool operation, the repository author offers no warranty or guarantee as to operation or use. **AI WARNING:** Artificial intelligence was utilized to help create and maintain these packages.

Users are responsible for complying with:

* Applicable law
* Court rules
* Agency policy
* Terms of service
* Evidence-handling requirements
* Privacy obligations
* Record-retention requirements
* Legal-process requirements

The software is provided as a documentation aid and should not be treated as a substitute for legal advice, forensic validation, agency policy, or independent investigative judgment.
