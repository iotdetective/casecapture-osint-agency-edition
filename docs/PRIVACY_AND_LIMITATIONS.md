# Privacy and Limitations

CaseCapture OSINT is designed to collect useful case documentation while avoiding unnecessary exposure of the investigator's machine or accounts.

## Intentionally Not Collected

The tool should not collect:

- source machine public IP address,
- source machine local IP address,
- traceroute data,
- cookie values,
- cookie names,
- request headers,
- stored credentials,
- localStorage values,
- sessionStorage values,
- storage keys,
- local file paths,
- hardware concurrency,
- device memory.

## Why This Matters

Some browser data can expose sensitive information.

Examples:

- cookies may act like login tokens,
- request headers may contain authorization values,
- storage values may contain account/session data,
- IP data may expose the investigator's network.

The tool avoids these by design.

## Limitations

The tool does not authenticate:

- account ownership,
- content authorship,
- server records,
- platform records,
- website operator identity.

It documents what was observed in the browser.

## Best Evidence Within the Package

The strongest files are usually:

- `screenshots/screenshot_visible.png`,
- `screenshots/screenshot_fullpage.png`,
- `manifest.json`,
- `method_log.json`,
- `.zip.sha256.txt`.

HTML and JSON files provide supporting context.
