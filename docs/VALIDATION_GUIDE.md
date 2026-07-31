# Validation Guide

Before operational use, validate the tool.

## Simple Validation Test

1. Open a simple static webpage.
2. Capture it.
3. Extract the ZIP.
4. Open `index.html`.
5. Confirm the URL is correct.
6. Confirm the title is correct.
7. Confirm timestamps are correct.
8. Confirm `screenshot_visible.png` matches the browser viewport.
9. Confirm `report.html` opens.
10. Confirm `manifest.json` lists all files.

## Hash Verification

Use PowerShell:

```powershell
Get-FileHash .\screenshot_visible.png -Algorithm SHA256
```

Compare the result to `manifest.json`.

For the ZIP:

```powershell
Get-FileHash .\CaseCapture_PACKAGE.zip -Algorithm SHA256
```

Compare the result to the `.zip.sha256.txt` file.

## Dynamic Page Testing

Also test:

- long pages,
- pages with videos,
- pages with lazy-loaded images,
- login pages,
- social media pages,
- search result pages.

Document known issues.

## Repeat After Changes

Repeat validation after changing:

- `background.js`,
- `content.js`,
- screenshot logic,
- hashing logic,
- ZIP layout,
- metadata collection.
