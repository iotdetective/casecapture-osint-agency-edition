# CaseCapture OSINT Privacy Policy

**Effective Date:** August 23, 2026
**Last Updated:** August 23, 2026

## Overview

CaseCapture OSINT is an independently developed browser extension designed to assist users with the intentional capture and documentation of publicly accessible webpages for investigative, research, and open-source intelligence purposes.

CaseCapture is designed with a local-first approach. Captured webpage content, screenshots, case information, reports, hashes, and related evidence artifacts are processed on the user's device and are not transmitted to the developer.

CaseCapture is not affiliated with, sponsored by, or endorsed by any law enforcement agency, government entity, commercial organization, or other third party.

## User-Initiated Operation

CaseCapture does not continuously monitor browsing activity.

The extension interacts with webpage content only when the user intentionally activates CaseCapture and initiates a capture.

CaseCapture is designed to operate on standard HTTP and HTTPS webpages. It is not intended to capture local files, Chrome internal pages, or other browser-restricted resources.

## Information Processed During a Capture

When a user initiates a capture, CaseCapture may locally process information necessary to document the webpage and the circumstances of the capture, including:

* webpage URL;
* webpage title;
* rendered webpage content;
* webpage HTML;
* visible text and page structure;
* referenced resources associated with the webpage;
* browser-observed page metadata;
* screenshots of the webpage;
* capture date and time;
* technical information necessary to document the capture environment;
* case number entered by the user;
* item or evidence number entered by the user;
* investigator name or identifier entered by the user;
* agency or organization entered by the user;
* investigator notes entered for the specific capture; and
* information entered by the user into an Investigator Supplement.

This information is processed for the purpose of generating the evidence and documentation selected by the user.

## Local Evidence Processing

CaseCapture generates its evidence materials locally on the user's device.

Depending on the selected capture workflow, generated materials may include:

* webpage capture information;
* screenshots;
* preserved webpage content;
* capture metadata;
* evidence manifests;
* investigator documentation;
* Investigator Supplements;
* SHA-256 cryptographic hashes; and
* downloadable evidence packages.

CaseCapture does not upload these materials to a CaseCapture server or developer-operated cloud service.

The user is responsible for determining where generated files are stored after download and for protecting, retaining, transferring, or deleting those files in accordance with the user's applicable policies, procedures, laws, and evidentiary requirements.

## Case Information Stored During the Browser Session

To assist users who are capturing multiple webpages associated with the same investigation, CaseCapture may temporarily retain the following information during the current Chrome browser session:

* case number;
* item or evidence number;
* investigator name or identifier; and
* agency or organization.

This information is retained only so the user may intentionally select **Use Last Case Information** during a later capture in the same browser session.

CaseCapture does not automatically populate a new capture with previously entered case information.

The user must intentionally choose to reuse the retained information and remains responsible for reviewing the information before using it in another capture.

Users may remove the retained information at any time by selecting **Clear Saved Case Information**.

Session-retained case information is cleared when the Chrome browser session ends.

## Investigator Notes

Investigator Notes are specific to an individual capture.

CaseCapture does not retain Investigator Notes for reuse in later captures.

## Investigator Supplement Information

CaseCapture may temporarily retain information necessary to associate an Investigator Supplement with the capture that immediately preceded it.

This information is maintained within the current browser session for the purpose of completing the user-requested documentation workflow.

It is not transmitted to the developer or used to monitor the user's activity.

## Network Attribution and Infrastructure Research

CaseCapture does not conduct IP address attribution, WHOIS research, DNS research, hosting-provider research, CDN analysis, VPN or proxy attribution, or similar network-infrastructure investigation on behalf of the user.

Investigators and other users are responsible for conducting any such research independently from the CaseCapture collection process.

Relevant findings may be documented by the user in the Investigator Supplement when appropriate.

## Information CaseCapture Does Not Intentionally Collect

CaseCapture is not designed to collect or transmit:

* user account passwords;
* authentication credentials;
* browser passwords;
* payment card information;
* authentication tokens for developer use;
* browsing history unrelated to a user-initiated capture;
* background browsing activity;
* advertising identifiers;
* analytics or telemetry for the developer;
* user location for tracking purposes;
* IP attribution or WHOIS information gathered through external lookup services; or
* information from webpages the user has not intentionally selected for capture.

CaseCapture does not sell user information.

## Cookies, Authentication Data, and Browser Storage

CaseCapture is designed to document the webpage presented to the user rather than to extract or preserve browser authentication secrets.

The extension does not intentionally collect browser passwords, authentication credentials, cookies, authentication tokens, or the contents of browser storage for the purpose of identifying or authenticating the user.

Information that is visibly rendered as part of the webpage itself may, however, be represented in a screenshot or preserved webpage content because it forms part of the page intentionally selected for capture.

Users should review captured evidence for sensitive information before distributing it.

## Chrome Permissions

CaseCapture requests only browser permissions necessary to provide its user-facing capture and documentation features.

These may include:

### activeTab

Used to obtain temporary access to the active HTTP or HTTPS webpage after the user intentionally invokes CaseCapture.

CaseCapture does not use this permission to continuously monitor browsing activity.

### scripting

Used to execute packaged CaseCapture collection functionality within the webpage selected by the user.

### downloads

Used to save evidence packages, reports, screenshots, hashes, and related documentation generated by the user.

### storage

Used for limited session-based information necessary to support the CaseCapture workflow, including optional reuse of recent case-identification information and temporary association of an Investigator Supplement with its related capture.

### debugger

Used during a user-initiated capture to access Chrome functionality necessary to generate a full-page screenshot, including portions of the webpage outside the currently visible browser viewport.

CaseCapture does not use the debugger permission to monitor unrelated tabs, collect network-attribution information, collect credentials, or continuously monitor browsing activity.

The debugging connection is used as part of the capture operation and is released after the operation is completed.

## External Transmission and Third-Party Sharing

CaseCapture does not transmit captured evidence, case information, Investigator Notes, Investigator Supplements, screenshots, webpage content, or generated hashes to the developer.

CaseCapture does not sell, rent, or provide this information to advertisers, data brokers, or other third parties.

CaseCapture does not contain developer-operated advertising or behavioral tracking functionality.

If a user independently transfers or uploads CaseCapture-generated files to another service, system, agency, cloud provider, evidence-management platform, or other third party, that activity is outside the operation and control of CaseCapture.

## Analytics and Telemetry

CaseCapture does not currently use developer analytics, behavioral tracking, crash-reporting services, advertising trackers, or telemetry services.

If this functionality is introduced in a future version, this Privacy Policy will be updated before such functionality is released where required.

## Data Retention by the Developer

Because CaseCapture does not transmit captured evidence or case information to the developer, the developer does not maintain a repository of user captures, case records, screenshots, Investigator Notes, or Investigator Supplements.

Files created by CaseCapture remain under the control of the user after they are generated.

## Security

CaseCapture is designed to minimize unnecessary collection and transmission of information.

Users remain responsible for securing the computer, browser profile, downloaded evidence files, generated reports, and any other systems on which CaseCapture-generated information is stored.

No software system can guarantee absolute security.

## Intended Use

CaseCapture is a documentation tool.

Users are responsible for determining whether use of CaseCapture is appropriate for a particular investigation, organization, jurisdiction, proceeding, or evidentiary purpose.

Use of CaseCapture does not replace applicable legal requirements, agency policies, evidence-handling procedures, preservation obligations, validation requirements, or professional judgment.

## Children

CaseCapture is not designed or marketed as a service directed toward children.

## Changes to This Privacy Policy

This Privacy Policy may be updated when CaseCapture functionality, browser permissions, data-processing practices, or applicable requirements change.

Material changes will be reflected by updating the **Last Updated** date at the beginning of this policy.

The version of the Privacy Policy publicly available through the CaseCapture project should be considered the current policy.

## Chrome Web Store User Data Requirements

Use of information received from Chrome APIs by CaseCapture OSINT will adhere to applicable Chrome Web Store User Data Policy requirements, including applicable Limited Use requirements.

## Contact

Questions, concerns, or privacy inquiries relating to CaseCapture OSINT may be directed to:

**[rich@nhletoolkit.com](mailto:rich@nhletoolkit.com)**
