# Troubleshooting

## The extension will not load

Check:

- all files are in the extension folder,
- `manifest.json` is valid JSON,
- `jszip.min.js` exists,
- Developer mode is enabled.

## Capture fails

Try:

- reload the target page,
- reload the extension,
- test on a simple public website,
- avoid Chrome internal pages.

Extensions cannot capture some pages, such as:

```text
chrome://settings/
chrome://extensions/
```

## Full-page screenshot is wrong

Use the visible screenshot as the primary visual record.

Full-page screenshots can be affected by:

- page resizing,
- lazy loading,
- sticky headers,
- animations,
- dynamic content.

## HTML snapshot looks broken

This is normal for many websites.

Use:

```text
page/page_snapshot_readable.html
```

for review, and use screenshots as the visual record.

## Hash mismatch

Make sure you are verifying the original file.

Do not edit and re-save files before verifying.
