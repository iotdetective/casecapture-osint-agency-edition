# Artifact Guide

This guide explains the files created by CaseCapture OSINT.

## Main Files

### `index.html`

The main landing page. Open this first after extracting the ZIP.

### `report.html`

A human-readable report with case information, capture time, URL, artifact hashes, and notes.

### `manifest.json`

The main technical record. It lists tool details, timestamps, artifacts, and SHA-256 hashes.

### `method_log.json`

Explains how the capture was performed.

## Screenshots

### `screenshots/screenshot_visible.png`

The primary screenshot. This shows what was visible in the browser window.

### `screenshots/screenshot_fullpage.png`

A supplemental full-page capture. This is useful, but may be affected by dynamic content.

## Page Files

### `page/page_snapshot.html`

Raw rendered HTML collected from the page.

### `page/page_snapshot_readable.html`

A review-friendly copy of the HTML snapshot. It adds a banner and base URL.

### `page/visible_text.txt`

Text extracted from the visible page.

## Extracted Data

### `extracted/links.json`

Links found on the page.

### `extracted/images.json`

Image references found on the page.

This does not necessarily save the actual image files.

### `extracted/meta_tags.json`

Hidden metadata from the page header.

### `extracted/browser_environment.json`

Browser and display details.

### `extracted/storage_inventory.json`

Privacy-limited summary of browser storage use.

### `extracted/dom_summary.json`

Summary of headings, buttons, forms, frames, and media elements.

### `extracted/resources.json`

Resource inventory such as scripts, stylesheets, fonts, images, videos, and frames.

## Network Files

### `network/performance_resource_timing.json`

Browser resource timing data.

### `network/cdp_network_observation.json`

Limited Chrome DevTools Protocol network observations.

## Important Image Warning

`images.json` records image URLs. It does not prove those images will be the same later.

If HTML files are opened later, image URLs may load current/live images from the internet.

The screenshots are the best visual record of what was observed at capture time.
