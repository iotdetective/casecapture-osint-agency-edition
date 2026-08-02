const TOOL_INFO = {
  name: "CaseCapture OSINT",
  version: "0.5.1",
  author: "Richard Theberge",
  code_license: "MIT License",
  documentation_license: "Creative Commons Attribution 4.0 International",
  modification_notice:
    "This tool is locally installed and may be modified by the user. Output should be evaluated based on the tool version, source code, documentation, validation testing, and agency policy.",
  nist_notice:
    "This tool is designed to support NIST-aligned forensic documentation practices, including artifact preservation, metadata recording, hash generation, method logging, and reporting. It is not certified by NIST and should not be described as NIST-certified."
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "capturePage") {
    capturePage(message.caseInfo)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
});

async function capturePage(caseInfo) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) throw new Error("No active tab found.");

  const captureStarted = new Date();
  const utcTimestamp = captureStarted.toISOString();
  const localTimestamp = getLocalTimestamp(captureStarted);
  const captureId = makeCaptureId(caseInfo.case_number, captureStarted);
  const safeCaseNumber = sanitizeFilename(caseInfo.case_number || "NoCase");
  const packageBaseName = sanitizeFilename(`CaseCapture_${safeCaseNumber}_${captureId}`);

  const pageDataResult = await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
  const pageData = pageDataResult[0].result;

  const visibleScreenshotDataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  const visibleScreenshotBytes = dataUrlToUint8Array(visibleScreenshotDataUrl);

  let fullPageScreenshotBytes = null;
  let fullPageMethodLog = null;
  let fullPageCaptureStatus = "not_attempted";
  let browserNetworkObservation = buildEmptyCdpNetworkObservation();

  try {
    const fullPageResult = await captureFullPageWithFirefox(tab);
    fullPageScreenshotBytes = fullPageResult.bytes;
    fullPageMethodLog = fullPageResult.methodLog;
    browserNetworkObservation = buildEmptyCdpNetworkObservation();
    fullPageCaptureStatus = "success";
  } catch (error) {
    fullPageMethodLog = {
      method: "chrome.tabs.captureVisibleTab viewport segmentation and canvas stitching",
      success: false,
      status: "failed",
      error: error.message,
      failed_utc: new Date().toISOString()
    };
    fullPageCaptureStatus = "failed";
  }

  const captureCompleted = new Date();

  const linksJson = JSON.stringify(pageData.links || [], null, 2);
  const imagesJson = JSON.stringify(pageData.images || [], null, 2);
  const metaTagsJson = JSON.stringify(pageData.metaTags || [], null, 2);
  const visibleText = pageData.text || "";
  const htmlSnapshot = pageData.html || "";
  const browserEnvironmentJson = JSON.stringify(pageData.browser_environment || {}, null, 2);
  const storageInventoryJson = JSON.stringify(pageData.storage_inventory || {}, null, 2);
  const domSummaryJson = JSON.stringify(pageData.dom_summary || {}, null, 2);
  const resourcesJson = JSON.stringify(pageData.resource_inventory || {}, null, 2);
  const performanceJson = JSON.stringify(pageData.performance_summary || {}, null, 2);
  const networkObservationJson = JSON.stringify(browserNetworkObservation, null, 2);

  const readableHtmlSnapshot = buildReadableHtmlSnapshot(htmlSnapshot, tab.url, {
    case_number: caseInfo.case_number,
    capture_id: captureId,
    local_time: localTimestamp,
    utc_time: utcTimestamp
  });

  const methodLog = {
    visible_screenshot: {
      method: "chrome.tabs.captureVisibleTab",
      description: "Captured the visible viewport of the active tab.",
      status: "success",
      captured_utc: utcTimestamp
    },
    fullpage_screenshot: fullPageMethodLog || { method: "not_attempted", status: "not_attempted" },
    network_metadata: {
      method: "Privacy-minimized browser observation",
      description: "Resource timing data was collected from the page. Limited DevTools Protocol network events may be collected during the full-page screenshot step. Request headers, cookies, credential values, local/source IP address, public IP address, traceroute, RDAP, WHOIS, and OS-level DNS lookups are not collected by this edition.",
      status: "success"
    },
    notes: [
      "The visible screenshot is the primary unmodified viewport screenshot.",
      "The full-page screenshot, when successful, is a supplemental browser-rendered capture created by viewport segmentation and canvas stitching.",
      "The full-page capture method scrolls through viewport-sized segments, captures each segment, stitches them into one PNG, and restores the original page position.",
      "Network metadata is privacy-minimized. Cookie values, credential values, request headers, local/source IP address, public IP address, traceroute, RDAP, WHOIS, and OS-level DNS lookups are not collected.",
      "Dynamic content, lazy-loaded content, animations, embedded media, authentication state, and page changes may affect browser-rendered captures."
    ]
  };
  const methodLogJson = JSON.stringify(methodLog, null, 2);

  const hashes = {
    visibleScreenshotHash: await sha256Bytes(visibleScreenshotBytes),
    fullPageScreenshotHash: fullPageScreenshotBytes ? await sha256Bytes(fullPageScreenshotBytes) : null,
    htmlHash: await sha256Text(htmlSnapshot),
    readableHtmlHash: await sha256Text(readableHtmlSnapshot),
    textHash: await sha256Text(visibleText),
    linksHash: await sha256Text(linksJson),
    imagesHash: await sha256Text(imagesJson),
    metaTagsHash: await sha256Text(metaTagsJson),
    methodLogHash: await sha256Text(methodLogJson),
    browserEnvironmentHash: await sha256Text(browserEnvironmentJson),
    storageInventoryHash: await sha256Text(storageInventoryJson),
    domSummaryHash: await sha256Text(domSummaryJson),
    resourcesHash: await sha256Text(resourcesJson),
    performanceHash: await sha256Text(performanceJson),
    networkObservationHash: await sha256Text(networkObservationJson)
  };

  const documentationFiles = buildDocumentationFiles();
  const documentationHashes = {};
  for (const [path, content] of Object.entries(documentationFiles)) {
    documentationHashes[path] = await sha256Text(content);
  }

  const artifacts = [
    { path: "screenshots/screenshot_visible.png", description: "Primary visible viewport screenshot captured by the Firefox tabs.captureVisibleTab API.", sha256: hashes.visibleScreenshotHash },
    { path: "page/page_snapshot.html", description: "Raw HTML snapshot collected from document.documentElement.outerHTML.", sha256: hashes.htmlHash },
    { path: "page/page_snapshot_readable.html", description: "Readable review copy generated from the captured HTML with a base URL and capture banner added.", sha256: hashes.readableHtmlHash },
    { path: "page/visible_text.txt", description: "Visible text collected from document.body.innerText.", sha256: hashes.textHash },
    { path: "extracted/links.json", description: "Links extracted from document.links.", sha256: hashes.linksHash },
    { path: "extracted/images.json", description: "Image element references extracted from document.images. This does not preserve image binaries.", sha256: hashes.imagesHash },
    { path: "extracted/meta_tags.json", description: "Meta tags extracted from document.querySelectorAll('meta').", sha256: hashes.metaTagsHash },
    { path: "extracted/browser_environment.json", description: "Privacy-minimized browser environment and rendering metadata.", sha256: hashes.browserEnvironmentHash },
    { path: "extracted/storage_inventory.json", description: "Privacy-minimized storage inventory. Counts only; no cookie values, cookie names, localStorage keys/values, or sessionStorage keys/values.", sha256: hashes.storageInventoryHash },
    { path: "extracted/dom_summary.json", description: "DOM summary including headings, buttons, forms, and frames. Form values and credential values are not collected.", sha256: hashes.domSummaryHash },
    { path: "extracted/resources.json", description: "Resource inventory of scripts, stylesheets, media elements, canvas count, and shadow DOM count.", sha256: hashes.resourcesHash },
    { path: "network/performance_resource_timing.json", description: "Browser Performance API navigation/resource timing summary. Does not include request headers, cookies, or local/source IP.", sha256: hashes.performanceHash },
    { path: "network/browser_network_observation.json", description: "Firefox network-capture capability notice. No privileged request/response events are collected; Performance API observations are preserved separately.", sha256: hashes.networkObservationHash },
    { path: "method_log.json", description: "Technical log describing screenshot and metadata capture methods.", sha256: hashes.methodLogHash }
  ];

  if (hashes.fullPageScreenshotHash) {
    artifacts.splice(1, 0, {
      path: "screenshots/screenshot_fullpage.png",
      description: "Supplemental full-page browser-rendered screenshot captured using Firefox viewport segmentation and canvas stitching.",
      sha256: hashes.fullPageScreenshotHash
    });
  }

  for (const [path, hash] of Object.entries(documentationHashes)) {
    artifacts.push({ path, description: "Embedded CaseCapture OSINT documentation.", sha256: hash });
  }

  const manifest = {
    tool: {
      name: TOOL_INFO.name,
      version: TOOL_INFO.version,
      author: TOOL_INFO.author,
      manifest_version: 3,
      license: { code: TOOL_INFO.code_license, documentation: TOOL_INFO.documentation_license },
      modification_notice: TOOL_INFO.modification_notice,
      nist_notice: TOOL_INFO.nist_notice
    },
    case: {
      case_number: caseInfo.case_number,
      item_number: caseInfo.item_number,
      investigator: caseInfo.investigator,
      agency: caseInfo.agency,
      investigator_notes: caseInfo.notes
    },
    capture: {
      capture_id: captureId,
      started_utc: utcTimestamp,
      completed_utc: captureCompleted.toISOString(),
      local_time_observed: localTimestamp,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      fullpage_capture_status: fullPageCaptureStatus
    },
    browser_observation: {
      tab_url: tab.url,
      tab_title: tab.title,
      page_reported_url: pageData.observed_url_from_page,
      page_title: pageData.title,
      canonical_url: pageData.canonical_url,
      referrer: pageData.referrer,
      user_agent: navigator.userAgent
    },
    page_observation: {
      page_dimensions: pageData.page_dimensions,
      viewport: pageData.viewport,
      link_count: Array.isArray(pageData.links) ? pageData.links.length : 0,
      image_count: Array.isArray(pageData.images) ? pageData.images.length : 0,
      meta_tag_count: Array.isArray(pageData.metaTags) ? pageData.metaTags.length : 0,
      frame_count: pageData.dom_summary?.frames?.length || 0,
      resource_count: pageData.performance_summary?.resources?.length || 0
    },
    privacy_minimization: {
      local_source_ip_collected: false,
      public_ip_collected: false,
      traceroute_collected: false,
      whois_collected: false,
      rdap_collected: false,
      os_dns_lookup_collected: false,
      cookie_values_collected: false,
      cookie_names_collected: false,
      request_headers_collected: false,
      credential_values_collected: false,
      local_storage_values_collected: false,
      session_storage_values_collected: false,
      local_file_paths_collected: false
    },
    artifacts,
    forensic_notice: {
      limitation: "This package documents what was observed in the browser session at the stated time. It does not independently authenticate the source account, server records, platform records, website operator, or identity of the content author.",
      screenshot_notice: "The visible screenshot is the primary unmodified viewport capture. The full-page screenshot, if present, is a supplemental browser-rendered artifact generated using Firefox viewport segmentation and canvas stitching. Dynamic content, lazy loading, animations, embedded media, authentication state, personalization, localization, browser state, or page changes may affect its appearance.",
      html_notice: "The raw page_snapshot.html is preserved as a technical artifact. The page_snapshot_readable.html file is a review copy that adds a base URL and capture banner to improve readability. The readable version should not be treated as the original page source.",
      image_reference_notice: "The images.json file records image element references observed in the rendered page, including source URLs and alt text when available. It does not necessarily preserve the image binary files as they existed at the time of capture. If page_snapshot.html or page_snapshot_readable.html is opened later, referenced image URLs may retrieve current/live versions from the web, may fail to load, or may load content that has changed since capture. For that reason, screenshot_visible.png and screenshot_fullpage.png are the best visual records of what was observed at the time of capture.",
      network_metadata_notice: "Network metadata in this package is privacy-minimized and browser-observed through the Performance API. It may help explain what the browser rendered, but it does not include local/source IP address, public IP address, cookies, credential values, request headers, traceroute, WHOIS, RDAP, or OS-level DNS lookup results.",
      original_and_notes_separated: true
    }
  };

  const reportHtml = buildReportHtml({ manifest, visibleTextPreview: visibleText.slice(0, 5000) });
  const reportHash = await sha256Text(reportHtml);
  manifest.artifacts.push({ path: "report.html", description: "Human-readable capture report.", sha256: reportHash });

  const indexHtml = buildIndexHtml({ manifest, hasFullPageScreenshot: Boolean(fullPageScreenshotBytes) });
  const indexHash = await sha256Text(indexHtml);
  manifest.artifacts.push({ path: "index.html", description: "Main evidence package landing page with links to reports, artifacts, screenshots, extracted data, network metadata, and documentation.", sha256: indexHash });

  const manifestBeforeIntegrity = JSON.stringify(manifest, null, 2);
  const manifestHash = await sha256Text(manifestBeforeIntegrity);
  manifest.integrity = {
    hash_algorithm: "SHA-256",
    manifest_sha256_before_integrity_field: manifestHash,
    note: "This value is the SHA-256 hash of manifest.json before the integrity field was added."
  };
  const finalManifestJson = JSON.stringify(manifest, null, 2);

  const zipFiles = {
    "index.html": toUtf8(indexHtml),
    "report.html": toUtf8(reportHtml),
    "manifest.json": toUtf8(finalManifestJson),
    "method_log.json": toUtf8(methodLogJson),
    "screenshots/screenshot_visible.png": visibleScreenshotBytes,
    "page/page_snapshot.html": toUtf8(htmlSnapshot),
    "page/page_snapshot_readable.html": toUtf8(readableHtmlSnapshot),
    "page/visible_text.txt": toUtf8(visibleText),
    "extracted/links.json": toUtf8(linksJson),
    "extracted/images.json": toUtf8(imagesJson),
    "extracted/meta_tags.json": toUtf8(metaTagsJson),
    "extracted/browser_environment.json": toUtf8(browserEnvironmentJson),
    "extracted/storage_inventory.json": toUtf8(storageInventoryJson),
    "extracted/dom_summary.json": toUtf8(domSummaryJson),
    "extracted/resources.json": toUtf8(resourcesJson),
    "network/performance_resource_timing.json": toUtf8(performanceJson),
    "network/browser_network_observation.json": toUtf8(networkObservationJson)
  };

  if (fullPageScreenshotBytes) zipFiles["screenshots/screenshot_fullpage.png"] = fullPageScreenshotBytes;
  for (const [path, content] of Object.entries(documentationFiles)) zipFiles[path] = toUtf8(content);

  const finalZipBytes = createZipStore(zipFiles);
  const finalZipHash = await sha256Bytes(finalZipBytes);

  await downloadBytesAsFile(`${packageBaseName}.zip`, finalZipBytes, "application/zip");
  await downloadTextAsFile(`${packageBaseName}.zip.sha256.txt`, `${finalZipHash}  ${packageBaseName}.zip\n`, "text/plain");

  return { capture_id: captureId, package_name: `${packageBaseName}.zip`, package_sha256: finalZipHash, fullpage_capture_status: fullPageCaptureStatus };
}

async function captureFullPageWithFirefox(tab) {
  const tabId = tab.id;
  const windowId = tab.windowId;
  const startedUtc = new Date().toISOString();
  let prepared = false;
  let captureState = null;

  try {
    const prepResults = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const doc = document.documentElement;
        const body = document.body;
        const original = {
          scrollX: window.scrollX,
          scrollY: window.scrollY,
          scrollBehavior: doc.style.scrollBehavior,
          bodyScrollBehavior: body ? body.style.scrollBehavior : ""
        };
        doc.style.scrollBehavior = "auto";
        if (body) body.style.scrollBehavior = "auto";
        const width = Math.max(doc.scrollWidth, body ? body.scrollWidth : 0, window.innerWidth);
        const height = Math.max(doc.scrollHeight, body ? body.scrollHeight : 0, window.innerHeight);
        return {
          original,
          pageWidth: width,
          pageHeight: height,
          viewportWidth: window.innerWidth,
          viewportHeight: window.innerHeight,
          devicePixelRatio: window.devicePixelRatio || 1
        };
      }
    });
    captureState = prepResults?.[0]?.result;
    if (!captureState) throw new Error("Firefox could not determine the page dimensions.");
    prepared = true;

    const maxCanvasDimension = 32767;
    const pixelWidth = Math.ceil(captureState.pageWidth * captureState.devicePixelRatio);
    const pixelHeight = Math.ceil(captureState.pageHeight * captureState.devicePixelRatio);
    if (pixelWidth > maxCanvasDimension || pixelHeight > maxCanvasDimension) {
      throw new Error(`Page is too large for a single Firefox canvas (${pixelWidth} x ${pixelHeight} pixels; limit ${maxCanvasDimension} per dimension).`);
    }

    const canvas = document.createElement("canvas");
    canvas.width = pixelWidth;
    canvas.height = pixelHeight;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) throw new Error("Firefox could not create the full-page stitching canvas.");

    const segments = [];
    const stepX = Math.max(1, captureState.viewportWidth);
    const stepY = Math.max(1, captureState.viewportHeight);

    for (let y = 0; y < captureState.pageHeight; y += stepY) {
      for (let x = 0; x < captureState.pageWidth; x += stepX) {
        const actualX = Math.min(x, Math.max(0, captureState.pageWidth - captureState.viewportWidth));
        const actualY = Math.min(y, Math.max(0, captureState.pageHeight - captureState.viewportHeight));
        await chrome.scripting.executeScript({
          target: { tabId },
          func: ({ scrollX, scrollY }) => {
            window.scrollTo(scrollX, scrollY);
            return new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          },
          args: [{ scrollX: actualX, scrollY: actualY }]
        });
        await sleep(150);
        const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: "png" });
        const image = await loadImage(dataUrl);
        const sourceScaleX = image.naturalWidth / captureState.viewportWidth;
        const sourceScaleY = image.naturalHeight / captureState.viewportHeight;
        const remainingCssWidth = Math.min(captureState.viewportWidth, captureState.pageWidth - actualX);
        const remainingCssHeight = Math.min(captureState.viewportHeight, captureState.pageHeight - actualY);
        const sourceWidth = Math.max(1, Math.round(remainingCssWidth * sourceScaleX));
        const sourceHeight = Math.max(1, Math.round(remainingCssHeight * sourceScaleY));
        const destX = Math.round(actualX * captureState.devicePixelRatio);
        const destY = Math.round(actualY * captureState.devicePixelRatio);
        const destWidth = Math.round(remainingCssWidth * captureState.devicePixelRatio);
        const destHeight = Math.round(remainingCssHeight * captureState.devicePixelRatio);
        ctx.drawImage(image, 0, 0, sourceWidth, sourceHeight, destX, destY, destWidth, destHeight);
        segments.push({ x: actualX, y: actualY, css_width: remainingCssWidth, css_height: remainingCssHeight });
      }
    }

    const blob = await new Promise((resolve, reject) => {
      canvas.toBlob(value => value ? resolve(value) : reject(new Error("Firefox failed to encode the stitched screenshot.")), "image/png");
    });
    const bytes = new Uint8Array(await blob.arrayBuffer());
    return {
      bytes,
      methodLog: {
        method: "chrome.tabs.captureVisibleTab viewport segmentation and canvas stitching",
        success: true,
        status: "success",
        started_utc: startedUtc,
        completed_utc: new Date().toISOString(),
        page_css_dimensions: { width: captureState.pageWidth, height: captureState.pageHeight },
        output_pixel_dimensions: { width: pixelWidth, height: pixelHeight },
        viewport_css_dimensions: { width: captureState.viewportWidth, height: captureState.viewportHeight },
        device_pixel_ratio: captureState.devicePixelRatio,
        segment_count: segments.length,
        description: "The extension scrolled the page through viewport-sized positions, captured each visible segment with tabs.captureVisibleTab, stitched the segments into a PNG, and restored the original scroll position and scroll behavior."
      }
    };
  } finally {
    if (prepared && captureState?.original) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          func: original => {
            const doc = document.documentElement;
            const body = document.body;
            doc.style.scrollBehavior = original.scrollBehavior || "";
            if (body) body.style.scrollBehavior = original.bodyScrollBehavior || "";
            window.scrollTo(original.scrollX || 0, original.scrollY || 0);
          },
          args: [captureState.original]
        });
      } catch (_e) {}
    }
  }
}

function loadImage(dataUrl) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Firefox could not decode a captured viewport image."));
    image.src = dataUrl;
  });
}

function buildEmptyCdpNetworkObservation() {
  return {
    collection_method: "Firefox capability notice; no privileged network-event capture performed",
    privacy_minimization: {
      request_headers_collected: false,
      response_headers_collected: false,
      cookies_collected: false,
      credential_values_collected: false,
      local_source_ip_collected: false,
      public_ip_collected: false,
      traceroute_collected: false,
      whois_collected: false,
      rdap_collected: false,
      os_dns_lookup_collected: false
    },
    limitation: "Firefox does not provide the Chrome debugger API used by the Chrome edition. This edition does not create a HAR or collect privileged request/response events. Use performance_resource_timing.json for browser-observed resource timing records.",
    requests: [],
    responses: [],
    failures: [],
    collection_errors: []
  };
}

function summarizeSecurityDetails(d) {
  return {
    protocol: d.protocol || "",
    keyExchange: d.keyExchange || "",
    cipher: d.cipher || "",
    certificateId: d.certificateId || null,
    subjectName: d.subjectName || "",
    issuer: d.issuer || "",
    validFrom: d.validFrom || null,
    validTo: d.validTo || null,
    sanList: Array.isArray(d.sanList) ? d.sanList.slice(0, 50) : [],
    certificateTransparencyCompliance: d.certificateTransparencyCompliance || ""
  };
}

function buildIndexHtml({ manifest, hasFullPageScreenshot }) {
  const fullPageBlock = hasFullPageScreenshot ? `
<section><h2>Supplemental Full-Page Screenshot</h2><p>This is a browser-rendered full-page capture. It may be affected by dynamic content, lazy loading, personalization, and rendering changes.</p><p><a href="screenshots/screenshot_fullpage.png">Open full-page screenshot</a></p><a href="screenshots/screenshot_fullpage.png"><img src="screenshots/screenshot_fullpage.png" alt="Full-page screenshot"></a></section>` :
`<section><h2>Supplemental Full-Page Screenshot</h2><p>No full-page screenshot was included. See method_log.json for details.</p></section>`;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CaseCapture OSINT Evidence Package</title>${sharedStyle()}</head><body>
<h1>CaseCapture OSINT Evidence Package</h1>
<div class="notice"><strong>Important:</strong> This package documents what was observed in a Firefox browser session at the time of capture. It does not independently authenticate the website, account holder, content author, server records, or platform data.</div>
<section><h2>Case Summary</h2><table>
<tr><th>Case Number</th><td>${escapeHtml(manifest.case.case_number)}</td></tr>
<tr><th>Item / Evidence Number</th><td>${escapeHtml(manifest.case.item_number)}</td></tr>
<tr><th>Investigator</th><td>${escapeHtml(manifest.case.investigator)}</td></tr>
<tr><th>Agency</th><td>${escapeHtml(manifest.case.agency)}</td></tr>
<tr><th>Capture ID</th><td><code>${escapeHtml(manifest.capture.capture_id)}</code></td></tr>
<tr><th>Observed Local Time</th><td>${escapeHtml(manifest.capture.local_time_observed)}</td></tr>
<tr><th>Observed UTC</th><td>${escapeHtml(manifest.capture.started_utc)}</td></tr>
<tr><th>URL</th><td><code>${escapeHtml(manifest.browser_observation.tab_url)}</code></td></tr>
<tr><th>Page Title</th><td>${escapeHtml(manifest.browser_observation.page_title)}</td></tr>
</table></section>
<section>
<h2>Quick Links</h2>
<p>These links open the main parts of the capture package. The screenshots are usually the best visual record of what was observed. The other files provide supporting technical details, extracted text, metadata, and documentation.</p>
<div class="grid">
<a class="card" href="report.html"><span class="card-title">Open Report</span><span class="card-desc">A plain-language report summarizing the case information, URL, capture time, screenshots, investigator notes, and file hashes.</span></a>
<a class="card" href="manifest.json"><span class="card-title">Open Manifest</span><span class="card-desc">The main technical record for the capture. It lists the tool version, case data, timestamps, artifact names, and SHA-256 hashes.</span></a>
<a class="card" href="method_log.json"><span class="card-title">Open Method Log</span><span class="card-desc">Explains how the tool performed the capture, including visible and stitched full-page screenshot methods.</span></a>
<a class="card" href="screenshots/screenshot_visible.png"><span class="card-title">Open Visible Screenshot</span><span class="card-desc">The primary screenshot of what was visible in the browser window at the time of capture.</span></a>
${hasFullPageScreenshot ? `<a class="card" href="screenshots/screenshot_fullpage.png"><span class="card-title">Open Full-Page Screenshot</span><span class="card-desc">A supplemental full-page image created by the browser. Useful for seeing content below the visible screen, but may be affected by dynamic pages.</span></a>` : ""}
<a class="card" href="page/page_snapshot_readable.html"><span class="card-title">Open Readable Page Snapshot</span><span class="card-desc">A review-friendly version of the captured page HTML with a banner and base URL added. This is for viewing, not the original source.</span></a>
<a class="card" href="page/page_snapshot.html"><span class="card-title">Open Raw HTML Snapshot</span><span class="card-desc">The raw HTML captured from the page as rendered in the browser. It may not display perfectly when opened later.</span></a>
<a class="card" href="page/visible_text.txt"><span class="card-title">Open Visible Text</span><span class="card-desc">The text the browser reported as visible on the page. Useful for searching, copying, or quoting page text.</span></a>
<a class="card" href="extracted/links.json"><span class="card-title">Open Links</span><span class="card-desc">A list of hyperlinks found on the page, including link text and destination URLs.</span></a>
<a class="card" href="extracted/images.json"><span class="card-title">Open Image References</span><span class="card-desc">A list of image URLs and alt text found on the page. This does not save the actual image files; screenshots are the better visual record.</span></a>
<a class="card" href="extracted/meta_tags.json"><span class="card-title">Open Meta Tags</span><span class="card-desc">Page metadata such as title, description, OpenGraph tags, Twitter card tags, and other hidden page information.</span></a>
<a class="card" href="extracted/browser_environment.json"><span class="card-title">Open Browser Environment</span><span class="card-desc">Basic browser and display details, such as user agent, screen size, viewport size, language, time zone, and device pixel ratio.</span></a>
<a class="card" href="extracted/storage_inventory.json"><span class="card-title">Open Storage Inventory</span><span class="card-desc">A privacy-limited summary of whether the page used browser storage. It does not collect cookie values, credentials, or stored data values.</span></a>
<a class="card" href="extracted/dom_summary.json"><span class="card-title">Open DOM Summary</span><span class="card-desc">A simplified outline of the page structure, such as headings, buttons, forms, frames, and media elements.</span></a>
<a class="card" href="extracted/resources.json"><span class="card-title">Open Resource Inventory</span><span class="card-desc">A list of page resources such as scripts, stylesheets, fonts, images, videos, and frames that helped build the page.</span></a>
<a class="card" href="network/performance_resource_timing.json"><span class="card-title">Open Resource Timing</span><span class="card-desc">Browser timing data showing resources the page loaded and how long they took. Useful for documenting what the browser requested.</span></a>
<a class="card" href="network/browser_network_observation.json"><span class="card-title">Open Browser Network Observation</span><span class="card-desc">Firefox does not expose Chrome DevTools Protocol observations to this extension. This file documents that limitation and identifies the browser-observed Performance API data preserved separately.</span></a>
</div>
</section>
<section><h2>Primary Visible Screenshot</h2><p>This is the primary visual record of the visible browser viewport at the time of capture.</p><p><a href="screenshots/screenshot_visible.png">Open visible screenshot</a></p><a href="screenshots/screenshot_visible.png"><img src="screenshots/screenshot_visible.png" alt="Visible screenshot"></a></section>
${fullPageBlock}
<section><h2>Documentation</h2><ul><li><a href="documentation/README.html">README</a></li><li><a href="documentation/COLLECTION_GUIDE.html">Collection Guide</a></li><li><a href="documentation/ARTIFACT_GUIDE.html">Artifact Guide</a></li><li><a href="documentation/NIST_ALIGNMENT.html">NIST Alignment</a></li><li><a href="documentation/TOOL_LIMITATIONS.html">Tool Limitations</a></li><li><a href="documentation/PRIVACY_MINIMIZATION.html">Privacy Minimization</a></li><li><a href="documentation/VALIDATION_GUIDE.html">Validation Guide</a></li><li><a href="documentation/LICENSE.html">License</a></li></ul></section>
<section><h2>Artifact Hashes</h2><table><tr><th>File</th><th>SHA-256</th></tr>${manifest.artifacts.map(a => `<tr><td>${escapeHtml(a.path)}</td><td><code>${escapeHtml(a.sha256)}</code></td></tr>`).join("")}</table></section>
<div class="warning"><strong>Privacy note:</strong> This edition does not collect local/source IP address, public IP address, traceroute, WHOIS, RDAP, OS-level DNS lookups, cookie values, cookie names, request headers, credential values, localStorage values, sessionStorage values, or local file paths.</div>
<div class="warning"><strong>Image reference warning:</strong> images.json records image URLs and metadata, not preserved image binaries. HTML snapshots may load live/current external resources if opened later. The screenshots are the best visual record of what was observed at capture time.</div>
</body></html>`;
}

function buildReportHtml({ manifest, visibleTextPreview }) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CaseCapture OSINT Report</title>${sharedStyle()}</head><body><h1>CaseCapture OSINT Report</h1>
<section><h2>Case Information</h2><table><tr><th>Case Number</th><td>${escapeHtml(manifest.case.case_number)}</td></tr><tr><th>Item / Evidence Number</th><td>${escapeHtml(manifest.case.item_number)}</td></tr><tr><th>Investigator</th><td>${escapeHtml(manifest.case.investigator)}</td></tr><tr><th>Agency</th><td>${escapeHtml(manifest.case.agency)}</td></tr></table></section>
<section><h2>Capture Information</h2><table><tr><th>Capture ID</th><td><code>${escapeHtml(manifest.capture.capture_id)}</code></td></tr><tr><th>Observed Local Time</th><td>${escapeHtml(manifest.capture.local_time_observed)}</td></tr><tr><th>Started UTC</th><td>${escapeHtml(manifest.capture.started_utc)}</td></tr><tr><th>Completed UTC</th><td>${escapeHtml(manifest.capture.completed_utc)}</td></tr><tr><th>Time Zone</th><td>${escapeHtml(manifest.capture.timezone)}</td></tr><tr><th>Full-Page Capture Status</th><td>${escapeHtml(manifest.capture.fullpage_capture_status)}</td></tr></table></section>
<section><h2>Browser Observation</h2><table><tr><th>Tab URL</th><td><code>${escapeHtml(manifest.browser_observation.tab_url)}</code></td></tr><tr><th>Page Reported URL</th><td><code>${escapeHtml(manifest.browser_observation.page_reported_url)}</code></td></tr><tr><th>Canonical URL</th><td><code>${escapeHtml(manifest.browser_observation.canonical_url || "")}</code></td></tr><tr><th>Tab Title</th><td>${escapeHtml(manifest.browser_observation.tab_title)}</td></tr><tr><th>Page Title</th><td>${escapeHtml(manifest.browser_observation.page_title)}</td></tr><tr><th>Referrer</th><td><code>${escapeHtml(manifest.browser_observation.referrer || "")}</code></td></tr><tr><th>User Agent</th><td><code>${escapeHtml(manifest.browser_observation.user_agent)}</code></td></tr></table></section>
<section><h2>Privacy-Minimized Metadata</h2><table><tr><th>Local/source IP collected</th><td>${manifest.privacy_minimization.local_source_ip_collected}</td></tr><tr><th>Public IP collected</th><td>${manifest.privacy_minimization.public_ip_collected}</td></tr><tr><th>Cookie values collected</th><td>${manifest.privacy_minimization.cookie_values_collected}</td></tr><tr><th>Cookie names collected</th><td>${manifest.privacy_minimization.cookie_names_collected}</td></tr><tr><th>Request headers collected</th><td>${manifest.privacy_minimization.request_headers_collected}</td></tr><tr><th>Traceroute / WHOIS / RDAP collected</th><td>false</td></tr></table></section>
<section><h2>Artifact Hashes</h2><table><tr><th>File</th><th>SHA-256</th></tr>${manifest.artifacts.map(a => `<tr><td>${escapeHtml(a.path)}</td><td><code>${escapeHtml(a.sha256)}</code></td></tr>`).join("")}</table></section>
<section><h2>Investigator Notes</h2><pre>${escapeHtml(manifest.case.investigator_notes || "")}</pre></section><section><h2>Visible Text Preview</h2><pre>${escapeHtml(visibleTextPreview || "")}</pre></section>
<section><h2>Forensic Notice</h2><div class="notice">${escapeHtml(manifest.forensic_notice.limitation)}</div><div class="notice">${escapeHtml(manifest.forensic_notice.screenshot_notice)}</div><div class="warning">${escapeHtml(manifest.forensic_notice.html_notice)}</div><div class="warning">${escapeHtml(manifest.forensic_notice.image_reference_notice)}</div><div class="warning">${escapeHtml(manifest.forensic_notice.network_metadata_notice)}</div></section></body></html>`;
}

function buildDocumentationFiles() {
  return {
    "documentation/README.html": buildDocPage("README", `<p><strong>CaseCapture OSINT</strong> is a local Firefox extension used to document web content observed in a browser session.</p><p>The tool was created by <strong>Richard Theberge</strong> as a local-first OSINT web documentation utility.</p><p>This Firefox edition adds privacy-minimized metadata collection, including browser environment, viewport/screen details, DOM summary, resource inventory, performance resource timing, and a browser-network capability notice.</p><p>The tool does not independently authenticate the identity of a website operator, social media account holder, content author, or server-side record.</p>`),
    "documentation/COLLECTION_GUIDE.html": buildDocPage("Collection Guide", `<h2>Recommended Collection Environment</h2><p>Whenever practical, investigators should conduct OSINT and online evidence documentation from a clean, temporary, or controlled environment, such as Windows Sandbox, a clean virtual machine, a dedicated OSINT VM, a non-persistent/ephemeral desktop, a dedicated browser profile, or a controlled forensic workstation.</p><h2>Suggested Collection Steps</h2><ol><li>Start from a clean or controlled environment.</li><li>Confirm the system date, time, and time zone.</li><li>Avoid logging into personal accounts unless necessary and legally appropriate.</li><li>Document whether the content was public, authenticated, or otherwise access-controlled.</li><li>Navigate to the target URL and allow the page to load.</li><li>Avoid unnecessary interaction before capture.</li><li>Run the capture and save the ZIP and external SHA-256 file to the evidence location.</li><li>Preserve the original exported ZIP without editing it; review from a copy.</li></ol><h2>Authentication Warning</h2><p>If the page requires authentication, document the account used, the legal authority or consent basis, and whether displayed content may be affected by account permissions, location, language, personalization, cookies, or browser state.</p>`),
    "documentation/ARTIFACT_GUIDE.html": buildDocPage("Artifact Guide", `<table><tr><th>File</th><th>Description</th></tr><tr><td>index.html</td><td>Main evidence package landing page.</td></tr><tr><td>report.html</td><td>Human-readable capture report.</td></tr><tr><td>manifest.json</td><td>Primary technical metadata and hash manifest.</td></tr><tr><td>method_log.json</td><td>Technical log showing how the capture was performed.</td></tr><tr><td>screenshots/screenshot_visible.png</td><td>Primary screenshot of the visible browser viewport.</td></tr><tr><td>screenshots/screenshot_fullpage.png</td><td>Supplemental browser-rendered full-page capture, if successful.</td></tr><tr><td>page/page_snapshot.html</td><td>Raw HTML snapshot from the rendered DOM.</td></tr><tr><td>page/page_snapshot_readable.html</td><td>Review copy of the HTML snapshot with a banner and base URL added.</td></tr><tr><td>page/visible_text.txt</td><td>Visible text extracted from document.body.innerText.</td></tr><tr><td>extracted/browser_environment.json</td><td>Browser, viewport, screen, language, and timezone details. Local/source IP and public IP are not collected.</td></tr><tr><td>extracted/storage_inventory.json</td><td>Counts only. Cookie names/values and storage keys/values are not collected.</td></tr><tr><td>network/performance_resource_timing.json</td><td>Browser Performance API resource timing summary.</td></tr><tr><td>network/browser_network_observation.json</td><td>Firefox browser-network capability notice and limitations.</td></tr></table><h2>Image Reference Warning</h2><p>images.json records image URLs and metadata, not preserved image binaries. HTML snapshots may load live/current external resources if opened later. The screenshots are the best visual record of what was observed at capture time.</p>`),
    "documentation/NIST_ALIGNMENT.html": buildDocPage("NIST Alignment", `<p>This tool is designed to support NIST-aligned forensic documentation practices. It is not certified by NIST and should not be described as NIST-certified.</p><ul><li>Preservation of generated digital artifacts.</li><li>Recording date, time, time zone, URL, title, browser, viewport, and environment metadata.</li><li>Separating automated observations from investigator notes.</li><li>Generating SHA-256 hashes for artifact integrity verification.</li><li>Creating method logs for repeatability and review.</li><li>Creating human-readable reports describing acquisition methods and limitations.</li><li>Applying privacy minimization by excluding cookie values, credential values, request headers, and source-machine network identifiers.</li></ul>`),
    "documentation/TOOL_LIMITATIONS.html": buildDocPage("Tool Limitations", `<ul><li>The tool documents what was observed in the browser session; it does not authenticate source accounts or server-side records.</li><li>Screenshots are browser-rendered representations of observed content.</li><li>Dynamic pages may change during or after capture.</li><li>Full-page screenshots may be affected by lazy loading, animations, viewport resizing, sticky elements, and scripts.</li><li>HTML snapshots may not display correctly when opened later.</li><li>Network observations are not a full HAR of the original page load.</li><li>DNS, RDAP, WHOIS, traceroute, local/source IP, and public IP are intentionally not collected in this edition.</li><li>Cookie values, credential values, request headers, localStorage values, and sessionStorage values are not collected.</li></ul>`),
    "documentation/PRIVACY_MINIMIZATION.html": buildDocPage("Privacy Minimization", `<p>This edition intentionally avoids collecting data that could expose too much about the investigator's source machine or credentials.</p><h2>Not Collected</h2><ul><li>Local/source IP address</li><li>Public IP address</li><li>Traceroute results</li><li>WHOIS/RDAP data</li><li>OS-level DNS lookup results</li><li>Request headers</li><li>Cookie values</li><li>Cookie names</li><li>Credential values</li><li>localStorage/sessionStorage keys or values</li><li>Local file paths</li><li>Hardware concurrency and device memory</li></ul><h2>Collected</h2><ul><li>Browser version/user agent</li><li>Viewport and screen dimensions</li><li>Language and time zone</li><li>Resource timing URLs and performance metadata</li><li>No remote server IP/port collection in this Firefox edition</li><li>Rendered DOM summaries that exclude form/credential values</li></ul>`),
    "documentation/VALIDATION_GUIDE.html": buildDocPage("Validation Guide", `<ol><li>Capture a simple static webpage.</li><li>Confirm screenshot_visible.png matches the browser viewport.</li><li>Confirm screenshot_fullpage.png reasonably represents the full rendered page.</li><li>Confirm report.html accurately lists URL, title, timestamps, privacy-minimization fields, and hashes.</li><li>Confirm hashes using an external tool such as PowerShell Get-FileHash.</li><li>Test dynamic pages, login pages, lazy-loaded images, long pages, and pages with embedded media.</li><li>Document known limitations before operational use.</li></ol><pre>Get-FileHash .\\screenshot_visible.png -Algorithm SHA256
Get-FileHash .\\manifest.json -Algorithm SHA256
Get-FileHash .\\CaseCapture_PACKAGE.zip -Algorithm SHA256</pre>`),
    "documentation/LICENSE.html": buildDocPage("License", `<p><strong>Tool Author:</strong> Richard Theberge</p><p><strong>Tool Name:</strong> CaseCapture OSINT</p><p><strong>Code License:</strong> MIT License</p><p><strong>Documentation License:</strong> Creative Commons Attribution 4.0 International</p><h2>Modification Notice</h2><p>This tool is locally installed and may be modified by the user. Any use should consider the tool version, source code, documentation, validation testing, and agency policy.</p><h2>No Certification Claim</h2><p>This tool is not certified by NIST, any court, or any forensic laboratory unless separately validated and approved by the using agency or organization.</p>`)
  };
}

function buildDocPage(title, body) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${escapeHtml(title)} - CaseCapture OSINT</title>${sharedStyle()}</head><body><h1>${escapeHtml(title)}</h1><p><a href="../index.html">Back to Evidence Package Index</a></p>${body}</body></html>`;
}

function buildReadableHtmlSnapshot(originalHtml, pageUrl, captureInfo) {
  const banner = `<div id="casecapture-banner" style="position: sticky; top: 0; z-index: 2147483647; background: #111; color: #fff; font-family: Arial, sans-serif; font-size: 14px; line-height: 1.4; padding: 10px; border-bottom: 3px solid #ffcc00;"><strong>CaseCapture OSINT Review Copy</strong><br>Case: ${escapeHtml(captureInfo.case_number || "")} | Capture ID: ${escapeHtml(captureInfo.capture_id || "")}<br>Observed Local: ${escapeHtml(captureInfo.local_time || "")}<br>Observed UTC: ${escapeHtml(captureInfo.utc_time || "")}<br>URL: ${escapeHtml(pageUrl || "")}<br><em>This is a readable review copy generated from the captured HTML. Use the screenshot, raw snapshot, manifest, and report for the primary capture record.</em></div>`;
  let html = originalHtml || "";
  const baseTag = `<base href="${escapeHtml(pageUrl || "")}">`;
  if (html.match(/<head[^>]*>/i)) html = html.replace(/<head[^>]*>/i, match => `${match}\n${baseTag}`); else html = `<head>${baseTag}</head>` + html;
  if (html.match(/<body[^>]*>/i)) html = html.replace(/<body[^>]*>/i, match => `${match}\n${banner}`); else html = banner + html;
  return html;
}

function sharedStyle() {
  return `<style>body{font-family:Arial,sans-serif;margin:32px;color:#111;line-height:1.45;max-width:1200px}h1{border-bottom:2px solid #333;padding-bottom:8px}h2{margin-top:28px;border-bottom:1px solid #aaa;padding-bottom:4px}section{margin-top:24px}table{border-collapse:collapse;width:100%;margin-top:8px}th,td{border:1px solid #bbb;padding:6px;vertical-align:top;text-align:left;font-size:13px}th{background:#eee;width:260px}code{word-break:break-all}pre{white-space:pre-wrap;border:1px solid #ccc;padding:10px;background:#f7f7f7;max-height:500px;overflow:auto}img{max-width:100%;border:1px solid #999;margin-top:8px}.notice{background:#fff4d6;border:1px solid #d6b656;padding:10px;margin-top:12px}.warning{background:#ffecec;border:1px solid #cc7777;padding:10px;margin-top:12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin-top:12px}.card{display:block;padding:12px;border:1px solid #aaa;background:#f7f7f7;text-decoration:none;color:#111;min-height:110px}.card:hover{background:#eaeaea}.card-title{display:block;font-weight:bold;font-size:16px;margin-bottom:8px}.card-desc{display:block;font-size:13px;line-height:1.35;font-weight:normal;color:#333}</style>`;
}

async function sha256Text(input) { return sha256Bytes(toUtf8(input || "")); }
async function sha256Bytes(bytes) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuffer)).map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function toUtf8(text) { return new TextEncoder().encode(String(text ?? "")); }
function dataUrlToUint8Array(dataUrl) {
  const base64 = dataUrl.split(",")[1];
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes;
}
async function downloadBytesAsFile(filename, bytes, mimeType) {
  const blob = new Blob([bytes], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  try {
    await chrome.downloads.download({ url: objectUrl, filename, saveAs: true });
  } finally {
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
  }
}
async function downloadTextAsFile(filename, text, mimeType) {
  const blob = new Blob([text || ""], { type: `${mimeType};charset=utf-8` });
  const objectUrl = URL.createObjectURL(blob);
  try {
    await chrome.downloads.download({ url: objectUrl, filename, saveAs: true });
  } finally {
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
  }
}
function uint8ArrayToBase64(bytes) {
  let binary = ""; const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  return btoa(binary);
}
function getLocalTimestamp(date) { return date.toLocaleString("en-US", { year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit", timeZoneName:"short" }); }
function makeCaptureId(caseNumber, date) { const stamp = date.toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z"); const cleanCase = (caseNumber || "NOCASE").replace(/[^a-zA-Z0-9]/g, ""); return `${cleanCase}_${stamp}`; }
function sanitizeFilename(filename) { return String(filename || "NoName").replace(/[<>:"/\\|?*]+/g, "_"); }
function escapeHtml(value) { return String(value ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;"); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

/* Minimal ZIP writer, store/no compression. Avoids external JSZip dependency. */
function createZipStore(files) {
  const encoder = new TextEncoder();
  const entries = [];
  let offset = 0;
  const fileParts = [];
  for (const [name, data] of Object.entries(files)) {
    const filename = encoder.encode(name);
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const crc = crc32(bytes);
    const local = new Uint8Array(30 + filename.length);
    const v = new DataView(local.buffer);
    v.setUint32(0, 0x04034b50, true); v.setUint16(4, 20, true); v.setUint16(6, 0, true); v.setUint16(8, 0, true);
    v.setUint16(10, 0, true); v.setUint16(12, 0, true); v.setUint32(14, crc, true); v.setUint32(18, bytes.length, true); v.setUint32(22, bytes.length, true); v.setUint16(26, filename.length, true); v.setUint16(28, 0, true);
    local.set(filename, 30);
    fileParts.push(local, bytes);
    entries.push({ name, filename, crc, size: bytes.length, offset });
    offset += local.length + bytes.length;
  }
  const centralParts = [];
  let centralSize = 0;
  for (const e of entries) {
    const central = new Uint8Array(46 + e.filename.length);
    const v = new DataView(central.buffer);
    v.setUint32(0, 0x02014b50, true); v.setUint16(4, 20, true); v.setUint16(6, 20, true); v.setUint16(8, 0, true); v.setUint16(10, 0, true);
    v.setUint16(12, 0, true); v.setUint16(14, 0, true); v.setUint32(16, e.crc, true); v.setUint32(20, e.size, true); v.setUint32(24, e.size, true); v.setUint16(28, e.filename.length, true);
    v.setUint16(30, 0, true); v.setUint16(32, 0, true); v.setUint16(34, 0, true); v.setUint16(36, 0, true); v.setUint32(38, 0, true); v.setUint32(42, e.offset, true);
    central.set(e.filename, 46);
    centralParts.push(central); centralSize += central.length;
  }
  const eocd = new Uint8Array(22); const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(4, 0, true); ev.setUint16(6, 0, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true); ev.setUint32(12, centralSize, true); ev.setUint32(16, offset, true); ev.setUint16(20, 0, true);
  return concatUint8Arrays([...fileParts, ...centralParts, eocd]);
}
function concatUint8Arrays(arrays) { const total = arrays.reduce((n,a)=>n+a.length,0); const out = new Uint8Array(total); let o=0; for (const a of arrays){out.set(a,o); o+=a.length;} return out; }
let CRC_TABLE = null;
function crc32(bytes) {
  if (!CRC_TABLE) { CRC_TABLE = new Uint32Array(256); for (let n=0;n<256;n++){let c=n; for(let k=0;k<8;k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n]=c>>>0;} }
  let c = 0xffffffff;
  for (let i=0;i<bytes.length;i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
