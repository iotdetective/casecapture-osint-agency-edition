const LAST_CASE_INFO_KEY = "lastCaseInfo";
const LEGACY_CASE_KEYS = ["caseNumber", "itemNumber", "investigator", "agency"];

document.addEventListener("DOMContentLoaded", async () => {
  // New captures intentionally begin with blank fields. The investigator must
  // explicitly choose to reuse information from the most recent successful
  // capture during the current Chrome session.
  clearCaseFields();

  // Migrate any reusable case information left by 0.6.2 or earlier from
  // persistent local storage into session storage, then remove the persistent
  // copy. Session storage is cleared by Chrome when the browser session ends.
  const legacyStored = await chrome.storage.local.get([LAST_CASE_INFO_KEY, ...LEGACY_CASE_KEYS, "pendingSupplementCapture"]);
  let sessionLastCaseInfo = legacyStored[LAST_CASE_INFO_KEY] || null;

  if (!sessionLastCaseInfo) {
    const legacyInfo = {
      caseNumber: (legacyStored.caseNumber || "").trim(),
      itemNumber: (legacyStored.itemNumber || "").trim(),
      investigator: (legacyStored.investigator || "").trim(),
      agency: (legacyStored.agency || "").trim()
    };
    if (Object.values(legacyInfo).some(Boolean)) sessionLastCaseInfo = legacyInfo;
  }

  const migrateToSession = {};
  if (sessionLastCaseInfo) migrateToSession[LAST_CASE_INFO_KEY] = sessionLastCaseInfo;
  if (legacyStored.pendingSupplementCapture) migrateToSession.pendingSupplementCapture = legacyStored.pendingSupplementCapture;
  if (Object.keys(migrateToSession).length) await chrome.storage.session.set(migrateToSession);

  // Remove all legacy persistent copies. Investigator notes were never included
  // in reusable case data.
  await chrome.storage.local.remove([LAST_CASE_INFO_KEY, ...LEGACY_CASE_KEYS, "pendingSupplementCapture"]);
  await updateSavedCaseControls();
});

document.getElementById("useLastCaseBtn").addEventListener("click", async () => {
  const status = document.getElementById("status");
  const stored = await chrome.storage.session.get(LAST_CASE_INFO_KEY);
  const lastCaseInfo = stored[LAST_CASE_INFO_KEY];

  if (!lastCaseInfo) {
    status.textContent = "No saved case information is available yet.";
    await updateSavedCaseControls();
    return;
  }

  document.getElementById("caseNumber").value = lastCaseInfo.caseNumber || "";
  document.getElementById("itemNumber").value = lastCaseInfo.itemNumber || "";
  document.getElementById("investigator").value = lastCaseInfo.investigator || "";
  document.getElementById("agency").value = lastCaseInfo.agency || "";

  // Investigator notes are deliberately never restored or retained for reuse.
  document.getElementById("notes").value = "";
  status.textContent = "Last case information loaded. Review all fields before capture.";
});

document.getElementById("clearSavedCaseBtn").addEventListener("click", async () => {
  await chrome.storage.session.remove(LAST_CASE_INFO_KEY);
  await updateSavedCaseControls();
  document.getElementById("status").textContent = "Saved case information cleared.";
});

document.getElementById("captureBtn").addEventListener("click", async () => {
  const status = document.getElementById("status");
  const button = document.getElementById("captureBtn");

  status.textContent = "Capturing page...";
  button.disabled = true;

  const caseInfo = {
    case_number: document.getElementById("caseNumber").value.trim(),
    item_number: document.getElementById("itemNumber").value.trim(),
    investigator: document.getElementById("investigator").value.trim(),
    agency: document.getElementById("agency").value.trim(),
    notes: document.getElementById("notes").value.trim()
  };

  try {
    const response = await chrome.runtime.sendMessage({
      action: "capturePage",
      caseInfo
    });

    if (response && response.success) {
      // Reusable case information is saved by the background worker only after
      // the primary evidence package has been successfully finalized. This is
      // necessary because opening the Investigator Supplement closes the popup.
      status.textContent = "Primary capture finalized. The investigator supplement page has been opened in a new tab.";
    } else {
      status.textContent = "Capture failed: " + (response?.error || "Unknown error");
    }
  } catch (err) {
    status.textContent = "Capture failed: " + err.message;
  } finally {
    button.disabled = false;
  }
});

document.getElementById("openSupplementBtn").addEventListener("click", async () => {
  const status = document.getElementById("status");
  const stored = await chrome.storage.session.get("pendingSupplementCapture");
  if (!stored.pendingSupplementCapture) {
    status.textContent = "No completed primary capture is available for a supplement yet.";
    return;
  }
  await chrome.tabs.create({ url: chrome.runtime.getURL("supplement.html"), active: true });
});

function clearCaseFields() {
  document.getElementById("caseNumber").value = "";
  document.getElementById("itemNumber").value = "";
  document.getElementById("investigator").value = "";
  document.getElementById("agency").value = "";
  document.getElementById("notes").value = "";
}

async function updateSavedCaseControls() {
  const stored = await chrome.storage.session.get(LAST_CASE_INFO_KEY);
  const hasSavedInfo = Boolean(stored[LAST_CASE_INFO_KEY]);
  document.getElementById("useLastCaseBtn").disabled = !hasSavedInfo;
  document.getElementById("clearSavedCaseBtn").disabled = !hasSavedInfo;
}
