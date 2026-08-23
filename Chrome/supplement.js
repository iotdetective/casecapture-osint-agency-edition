const SUPPLEMENT_VERSION = "0.6.3";
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_TOTAL_BYTES = 100 * 1024 * 1024;
let linkedCapture = null;
let selectedFiles = [];
let supplementalFileCounter = 0;
let researchEntryCounter = 0;

const $ = id => document.getElementById(id);

document.addEventListener("DOMContentLoaded", async () => {
  const stored = await chrome.storage.session.get("pendingSupplementCapture");
  linkedCapture = stored.pendingSupplementCapture || null;
  $("investigator").value = linkedCapture?.investigator || "";
  $("agency").value = linkedCapture?.agency || "";
  const now = toLocalDateTimeInput(new Date());
  $("interactionTime").value = now;
  addResearchEntry({ reported_query_time_local: now });
  renderLinkedCapture();
});

$("addResearchBtn").addEventListener("click", () => addResearchEntry({ reported_query_time_local: toLocalDateTimeInput(new Date()) }));

$("addFilesBtn").addEventListener("click", () => $("files").click());

$("files").addEventListener("change", () => {
  const additions = Array.from($("files").files || []);
  for (const file of additions) {
    supplementalFileCounter += 1;
    selectedFiles.push({
      id: supplementalFileCounter,
      file,
      description: ""
    });
  }
  // Reset the picker so the same filename may be selected again if needed.
  $("files").value = "";
  renderFiles();
});

$("clearBtn").addEventListener("click", () => {
  $("supplementForm").reset();
  selectedFiles = [];
  supplementalFileCounter = 0;
  $("files").value = "";
  $("title").value = "Investigator Web Capture Supplement";
  const now = toLocalDateTimeInput(new Date());
  $("interactionTime").value = now;
  $("researchEntries").replaceChildren();
  researchEntryCounter = 0;
  addResearchEntry({ reported_query_time_local: now });
  renderFiles();
  setStatus("");
});

$("supplementForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("createBtn");
  button.disabled = true;
  try {
    if (!linkedCapture?.capture_id || !linkedCapture?.package_sha256) {
      throw new Error("No completed primary capture is linked. Create a new CaseCapture capture and open the supplement page from the completion step.");
    }
    validateFiles();
    setStatus("Hashing supplemental files and creating the linked supplement…");
    const result = await createSupplement();
    setStatus(`Supplement created successfully.\nZIP SHA-256: ${result.zipHash}`, "success");
  } catch (error) {
    setStatus(`Supplement creation failed: ${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
});


function addResearchEntry(values = {}) {
  researchEntryCounter += 1;
  const entryId = researchEntryCounter;
  const card = document.createElement("div");
  card.className = "research-entry";
  card.dataset.researchEntry = String(entryId);
  card.innerHTML = `
    <div class="research-entry-header">
      <h3>Research Entry ${entryId}</h3>
      <button type="button" class="remove-research">Remove Section</button>
    </div>
    <div class="grid">
      <label>Research type
        <select data-field="type">
          <option value="None">None</option>
          <option value="WHOIS">WHOIS</option>
          <option value="RDAP">RDAP</option>
          <option value="DNS">DNS</option>
          <option value="IP ownership">IP ownership</option>
          <option value="Certificate information">Certificate information</option>
          <option value="Social media research">Social media research</option>
          <option value="Other">Other</option>
        </select>
      </label>
      <label>Source or service used<input data-field="source" type="text" placeholder="ARIN RDAP, ICANN Lookup, nslookup, dig, etc."></label>
      <label>Query performed<input data-field="query" type="text" placeholder="Domain, IP address, record type, username, or other query"></label>
      <label>Research date/time<input data-field="time" type="datetime-local"></label>
    </div>
    <label>Raw or pasted results<textarea data-field="results" placeholder="Paste the returned results. Identify whether they are complete or excerpted."></textarea></label>
    <label>Investigator interpretation<textarea data-field="interpretation" placeholder="Describe your interpretation separately from the raw results."></textarea></label>`;

  card.querySelector('[data-field="type"]').value = values.type || "None";
  card.querySelector('[data-field="source"]').value = values.source_or_service || "";
  card.querySelector('[data-field="query"]').value = values.query || "";
  card.querySelector('[data-field="time"]').value = values.reported_query_time_local || toLocalDateTimeInput(new Date());
  card.querySelector('[data-field="results"]').value = values.raw_or_pasted_results || "";
  card.querySelector('[data-field="interpretation"]').value = values.investigator_interpretation || "";
  card.querySelector('.remove-research').addEventListener('click', () => {
    card.remove();
    renumberResearchEntries();
  });
  $("researchEntries").appendChild(card);
}

function renumberResearchEntries() {
  Array.from(document.querySelectorAll('.research-entry')).forEach((entry, index) => {
    entry.querySelector('h3').textContent = `Research Entry ${index + 1}`;
  });
}

function collectResearchEntries() {
  return Array.from(document.querySelectorAll('.research-entry')).map((entry, index) => {
    const get = field => entry.querySelector(`[data-field="${field}"]`);
    return {
      entry_number: index + 1,
      type: get('type').value,
      source_or_service: get('source').value.trim(),
      query: get('query').value.trim(),
      reported_query_time: localInputToIso(get('time').value),
      raw_or_pasted_results: get('results').value.trim(),
      investigator_interpretation: get('interpretation').value.trim(),
      changing_data_notice: "WHOIS, RDAP, DNS, platform, and other third-party information may change. This entry reflects investigator-supplied information at the reported time and source."
    };
  }).filter(entry => entry.type !== "None" || entry.source_or_service || entry.query || entry.raw_or_pasted_results || entry.investigator_interpretation);
}

function renderLinkedCapture() {
  $("linkedCase").textContent = linkedCapture?.case_number || "Not available";
  $("linkedItem").textContent = linkedCapture?.item_number || "Not available";
  $("linkedCaptureId").textContent = linkedCapture?.capture_id || "No completed capture linked";
  $("linkedPackage").textContent = linkedCapture?.package_name || "Not available";
  $("linkedHash").textContent = linkedCapture?.package_sha256 || "Not available";
}

function renderFiles() {
  const box = $("fileList");
  box.replaceChildren();
  $("noFilesMessage").hidden = selectedFiles.length > 0;

  selectedFiles.forEach((item, index) => {
    const { file } = item;
    const card = document.createElement("div");
    card.className = "file-card";

    const header = document.createElement("div");
    header.className = "file-card-header";

    const summary = document.createElement("div");
    summary.className = "file-summary";
    summary.textContent = `${index + 1}. ${file.name} — ${formatBytes(file.size)} — ${file.type || "unknown type"}`;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-file";
    remove.textContent = "Remove File";
    remove.addEventListener("click", () => {
      selectedFiles = selectedFiles.filter(candidate => candidate.id !== item.id);
      renderFiles();
    });

    header.append(summary, remove);

    const label = document.createElement("label");
    label.textContent = "Description / provenance";
    const input = document.createElement("input");
    input.type = "text";
    input.value = item.description;
    input.placeholder = "Where the file came from and why it is included";
    input.addEventListener("input", () => { item.description = input.value; });
    label.appendChild(input);

    card.append(header, label);
    box.appendChild(card);
  });
}

function validateFiles() {
  let total = 0;
  for (const item of selectedFiles) {
    const file = item.file;
    if (file.size > MAX_FILE_BYTES) throw new Error(`${file.name} exceeds the 25 MB limit.`);
    total += file.size;
  }
  if (total > MAX_TOTAL_BYTES) throw new Error("The selected files exceed the 100 MB total limit.");
}

async function createSupplement() {
  const created = new Date();
  const supplementId = `${linkedCapture.capture_id}_SUPP_${created.toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z")}`;
  const files = {};
  const imported = [];

  for (let i = 0; i < selectedFiles.length; i++) {
    const item = selectedFiles[i];
    const file = item.file;
    const bytes = new Uint8Array(await file.arrayBuffer());
    const safeName = sanitizeFilename(file.name || `file_${i + 1}`);
    const path = `supplemental_files/${String(i + 1).padStart(3, "0")}_${safeName}`;
    const hash = await sha256Bytes(bytes);
    files[path] = bytes;
    imported.push({
      path,
      original_filename: file.name,
      media_type: file.type || "application/octet-stream",
      size_bytes: file.size,
      sha256: hash,
      description: item.description.trim(),
      import_method: "Investigator-selected local file",
      preserved_byte_for_byte: true
    });
  }

  const notes = collectNotes(created, supplementId);
  const notesJson = JSON.stringify(notes, null, 2);
  const notesHash = await sha256Text(notesJson);

  const artifacts = [
    { path: "investigator_notes.json", description: "Structured investigator-authored supplement information.", size_bytes: toUtf8(notesJson).length, sha256: notesHash, provenance: "investigator_authored" },
    ...imported.map(item => ({ path: item.path, description: item.description || "Investigator-imported supplemental file.", size_bytes: item.size_bytes, sha256: item.sha256, provenance: "investigator_imported" }))
  ];

  const manifest = {
    supplement_format: { name: "CaseCapture Investigator Supplement", version: 2 },
    tool: { name: "CaseCapture OSINT", version: SUPPLEMENT_VERSION, edition: "Firefox", author: "Richard Theberge" },
    supplement: { supplement_id: supplementId, created_utc: created.toISOString(), created_local: created.toLocaleString(), timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, status: "finalized" },
    linked_primary_capture: {
      capture_id: linkedCapture.capture_id,
      package_filename: linkedCapture.package_name,
      package_sha256: linkedCapture.package_sha256,
      case_number: linkedCapture.case_number || "",
      item_number: linkedCapture.item_number || "",
      captured_url: linkedCapture.captured_url || "",
      primary_capture_remained_unmodified: true
    },
    provenance_notice: "This supplement contains investigator-authored information and investigator-imported files obtained separately from the automatic browser capture. It is linked to, but does not alter, the finalized primary capture.",
    artifacts
  };

  const reportHtml = buildReport(notes, manifest, imported);
  const reportHash = await sha256Text(reportHtml);
  manifest.artifacts.push({ path: "supplement_report.html", description: "Human-readable investigator supplement report.", size_bytes: toUtf8(reportHtml).length, sha256: reportHash, provenance: "generated_from_supplement" });

  const manifestBeforeIntegrity = JSON.stringify(manifest, null, 2);
  const manifestHash = await sha256Text(manifestBeforeIntegrity);
  manifest.integrity = { hash_algorithm: "SHA-256", manifest_sha256_before_integrity_field: manifestHash, note: "SHA-256 of supplement_manifest.json before the integrity field was added." };
  const manifestJson = JSON.stringify(manifest, null, 2);

  files["investigator_notes.json"] = toUtf8(notesJson);
  files["supplement_report.html"] = toUtf8(reportHtml);
  files["supplement_manifest.json"] = toUtf8(manifestJson);

  const zipBytes = createZipStore(files);
  const zipHash = await sha256Bytes(zipBytes);
  const baseName = sanitizeFilename(`CaseCapture_${linkedCapture.case_number || "NoCase"}_${supplementId}`);
  await downloadBlob(`${baseName}.zip`, new Blob([zipBytes], { type: "application/zip" }));
  await downloadBlob(`${baseName}.zip.sha256.txt`, new Blob([`${zipHash}  ${baseName}.zip\n`], { type: "text/plain;charset=utf-8" }));
  return { zipHash };
}

function collectNotes(created, supplementId) {
  return {
    supplement_id: supplementId,
    investigator: $("investigator").value.trim(),
    agency: $("agency").value.trim(),
    title: $("title").value.trim(),
    authored_utc: created.toISOString(),
    interaction: {
      reported_interaction_time: localInputToIso($("interactionTime").value),
      access_method: $("accessMethod").value,
      account_or_access_context: $("accountContext").value.trim(),
      actions_taken: $("actionsTaken").value.trim(),
      purpose_and_relevance: $("purpose").value.trim(),
      observations: $("observations").value.trim(),
      warning: "Do not treat investigator-authored descriptions as automatically collected browser data."
    },
    separately_obtained_research: collectResearchEntries()
  };
}

function buildReport(notes, manifest, imported) {
  const rows = imported.length ? imported.map(file => {
    const href = file.path.split("/").map(encodeURIComponent).join("/");
    return `<tr><td><a class="package-link" href="${escapeHtml(href)}">${escapeHtml(file.path)}</a></td><td>${escapeHtml(file.original_filename)}</td><td>${escapeHtml(file.description)}</td><td>${file.size_bytes}</td><td><code>${file.sha256}</code></td></tr>`;
  }).join("") : '<tr><td colspan="5">No supplemental files were imported.</td></tr>';

  const researchEntries = notes.separately_obtained_research || [];
  const researchHtml = researchEntries.length ? researchEntries.map((entry, index) => `
    <h3>Research Entry ${index + 1}: ${escapeHtml(entry.type || "Unspecified")}</h3>
    <table><tr><th>Type</th><td>${escapeHtml(entry.type)}</td></tr><tr><th>Source/service</th><td>${escapeHtml(entry.source_or_service)}</td></tr><tr><th>Query</th><td>${escapeHtml(entry.query)}</td></tr><tr><th>Reported query time</th><td>${escapeHtml(entry.reported_query_time)}</td></tr><tr><th>Raw/pasted results</th><td><pre>${escapeHtml(entry.raw_or_pasted_results)}</pre></td></tr><tr><th>Investigator interpretation</th><td><pre>${escapeHtml(entry.investigator_interpretation)}</pre></td></tr></table>`).join("") : '<p>No separately obtained research entries were supplied.</p>';

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${escapeHtml(notes.title)}</title><style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.45;color:#111;max-width:1200px}h1{border-bottom:2px solid #333;padding-bottom:8px}h2{margin-top:28px;border-bottom:1px solid #aaa}h3{margin-top:22px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:7px;text-align:left;vertical-align:top}th{background:#eee}pre{white-space:pre-wrap;border:1px solid #ccc;padding:10px;background:#f7f7f7}code{word-break:break-all}.notice{padding:12px;background:#fff4d6;border:1px solid #d6b656}a{color:#0645ad}.package-link{font-weight:700}</style></head><body>
  <h1>${escapeHtml(notes.title)}</h1>
  <div class="notice">${escapeHtml(manifest.provenance_notice)}</div>
  <h2>Linked Primary Capture</h2><table><tr><th>Case</th><td>${escapeHtml(manifest.linked_primary_capture.case_number)}</td></tr><tr><th>Item</th><td>${escapeHtml(manifest.linked_primary_capture.item_number)}</td></tr><tr><th>Capture ID</th><td><code>${escapeHtml(manifest.linked_primary_capture.capture_id)}</code></td></tr><tr><th>Primary ZIP</th><td>${escapeHtml(manifest.linked_primary_capture.package_filename)}</td></tr><tr><th>Primary ZIP SHA-256</th><td><code>${escapeHtml(manifest.linked_primary_capture.package_sha256)}</code></td></tr></table>
  <h2>Investigator</h2><table><tr><th>Name</th><td>${escapeHtml(notes.investigator)}</td></tr><tr><th>Agency</th><td>${escapeHtml(notes.agency)}</td></tr><tr><th>Authored UTC</th><td>${escapeHtml(notes.authored_utc)}</td></tr></table>
  <h2>Page Interaction</h2><table><tr><th>Reported interaction time</th><td>${escapeHtml(notes.interaction.reported_interaction_time)}</td></tr><tr><th>Access method</th><td>${escapeHtml(notes.interaction.access_method)}</td></tr><tr><th>Account/access context</th><td><pre>${escapeHtml(notes.interaction.account_or_access_context)}</pre></td></tr><tr><th>Actions taken</th><td><pre>${escapeHtml(notes.interaction.actions_taken)}</pre></td></tr><tr><th>Purpose/relevance</th><td><pre>${escapeHtml(notes.interaction.purpose_and_relevance)}</pre></td></tr><tr><th>Observations</th><td><pre>${escapeHtml(notes.interaction.observations)}</pre></td></tr></table>
  <h2>Separately Obtained Research</h2>${researchHtml}
  <h2>Imported Supplemental Files</h2><p>Open a file by selecting its package path. The report and the <code>supplemental_files</code> folder must remain in their original relative locations after extraction.</p><table><tr><th>Package Path</th><th>Original Filename</th><th>Description</th><th>Bytes</th><th>SHA-256</th></tr>${rows}</table>
  <h2>Artifact Hashes</h2><table><tr><th>Artifact</th><th>Provenance</th><th>SHA-256</th></tr>${manifest.artifacts.map(a=>`<tr><td>${escapeHtml(a.path)}</td><td>${escapeHtml(a.provenance)}</td><td><code>${escapeHtml(a.sha256)}</code></td></tr>`).join("")}</table>
  </body></html>`;
}

async function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  try { await chrome.downloads.download({ url, filename, saveAs: true }); }
  finally { setTimeout(() => URL.revokeObjectURL(url), 60000); }
}

async function sha256Text(text) { return sha256Bytes(toUtf8(text)); }
async function sha256Bytes(bytes) { const hash = await crypto.subtle.digest("SHA-256", bytes); return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join(""); }
function toUtf8(text) { return new TextEncoder().encode(String(text ?? "")); }
function sanitizeFilename(name) { return String(name || "file").replace(/[<>:"/\\|?*\x00-\x1F]+/g, "_").slice(0, 180); }
function escapeHtml(value) { return String(value ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;"); }
function toLocalDateTimeInput(date) { const pad=n=>String(n).padStart(2,"0"); return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`; }
function localInputToIso(value) { if (!value) return ""; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toISOString(); }
function formatBytes(bytes) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1048576) return `${(bytes/1024).toFixed(1)} KB`; return `${(bytes/1048576).toFixed(1)} MB`; }
function setStatus(message, type="") { const el=$("status"); el.textContent=message; el.className=type; }

function createZipStore(files) {
  const encoder = new TextEncoder(), entries=[], fileParts=[]; let offset=0;
  for (const [name,data] of Object.entries(files)) { const filename=encoder.encode(name), bytes=data instanceof Uint8Array?data:new Uint8Array(data), crc=crc32(bytes), local=new Uint8Array(30+filename.length), v=new DataView(local.buffer); v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);v.setUint16(6,0,true);v.setUint16(8,0,true);v.setUint16(10,0,true);v.setUint16(12,0,true);v.setUint32(14,crc,true);v.setUint32(18,bytes.length,true);v.setUint32(22,bytes.length,true);v.setUint16(26,filename.length,true);v.setUint16(28,0,true);local.set(filename,30);fileParts.push(local,bytes);entries.push({filename,crc,size:bytes.length,offset});offset+=local.length+bytes.length; }
  const centralParts=[]; let centralSize=0;
  for(const e of entries){const c=new Uint8Array(46+e.filename.length),v=new DataView(c.buffer);v.setUint32(0,0x02014b50,true);v.setUint16(4,20,true);v.setUint16(6,20,true);v.setUint16(8,0,true);v.setUint16(10,0,true);v.setUint16(12,0,true);v.setUint16(14,0,true);v.setUint32(16,e.crc,true);v.setUint32(20,e.size,true);v.setUint32(24,e.size,true);v.setUint16(28,e.filename.length,true);v.setUint16(30,0,true);v.setUint16(32,0,true);v.setUint16(34,0,true);v.setUint16(36,0,true);v.setUint32(38,0,true);v.setUint32(42,e.offset,true);c.set(e.filename,46);centralParts.push(c);centralSize+=c.length;}
  const eocd=new Uint8Array(22),ev=new DataView(eocd.buffer);ev.setUint32(0,0x06054b50,true);ev.setUint16(4,0,true);ev.setUint16(6,0,true);ev.setUint16(8,entries.length,true);ev.setUint16(10,entries.length,true);ev.setUint32(12,centralSize,true);ev.setUint32(16,offset,true);ev.setUint16(20,0,true);return concat([...fileParts,...centralParts,eocd]);
}
function concat(arrays){const total=arrays.reduce((n,a)=>n+a.length,0),out=new Uint8Array(total);let o=0;for(const a of arrays){out.set(a,o);o+=a.length}return out}
let CRC_TABLE=null;function crc32(bytes){if(!CRC_TABLE){CRC_TABLE=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xedb88320^(c>>>1):c>>>1;CRC_TABLE[n]=c>>>0}}let c=0xffffffff;for(let i=0;i<bytes.length;i++)c=CRC_TABLE[(c^bytes[i])&255]^(c>>>8);return(c^0xffffffff)>>>0}
