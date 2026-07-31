# Developer Notes

This file explains the extension in simple technical terms.

## Main Files

### `manifest.json`

Defines extension permissions and entry points.

### `popup.html`

User interface form.

### `popup.js`

Reads the form and starts capture.

### `content.js`

Runs inside the target webpage and collects page-level information.

### `background.js`

Main capture engine.

### `jszip.min.js`

Creates ZIP files.

## Capture Flow

1. User opens popup.
2. User enters case information.
3. User clicks capture.
4. `popup.js` sends a message to `background.js`.
5. `background.js` asks Chrome for the active tab.
6. `content.js` collects page data.
7. `background.js` captures screenshots.
8. `background.js` collects limited DevTools information.
9. Files are hashed.
10. HTML reports are created.
11. ZIP is created.
12. ZIP and SHA-256 file are downloaded.

## Development Safety

Avoid collecting:

- cookies,
- request headers,
- storage values,
- local IP address,
- public IP address,
- local file paths,
- full extension inventory.

## Versioning

Update the version number when changing capture behavior.

Suggested version changes:

- patch: small wording or UI changes,
- minor: new metadata or report fields,
- major: major capture behavior changes.
