# Collection Guide

This guide explains the recommended way to use CaseCapture OSINT during an investigation.

## Goal

The goal is to document web content in a clean, repeatable, and explainable way.

The tool should help answer:

- What page was viewed?
- When was it viewed?
- What did the investigator see?
- What files were generated?
- How can those files be verified later?

## Start Clean

Whenever possible, use a clean environment.

Recommended options:

- Windows Sandbox
- Clean virtual machine
- Dedicated OSINT VM
- Ephemeral desktop
- Dedicated browser profile
- Controlled forensic workstation

A clean environment reduces unrelated artifacts from personal browsing and unrelated casework.

## Basic Collection Steps

1. Start the clean environment.
2. Confirm system time and time zone.
3. Open Chrome.
4. Load the CaseCapture OSINT extension.
5. Navigate to the target page.
6. Let the page load.
7. Avoid unnecessary interaction.
8. Open the extension.
9. Enter case information.
10. Click capture.
11. Save the ZIP and SHA-256 file.
12. Move them to the correct case evidence location.
13. Verify the ZIP hash when practical.
14. Preserve the original ZIP.
15. Work from a copy if review is needed.

## If Login Is Required

Document:

- the account used,
- the authority or consent basis,
- whether the page was public or private,
- whether personalization may affect the display,
- whether cookies/session state may affect the display.

## Dynamic Content

Dynamic pages can change.

Examples:

- comments,
- reactions,
- ads,
- timestamps,
- recommendations,
- videos,
- search results,
- lazy-loaded images.

Capture what you can, document limitations, and preserve the package.
