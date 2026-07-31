document.addEventListener("DOMContentLoaded", async () => {
  const saved = await chrome.storage.local.get([
    "caseNumber",
    "itemNumber",
    "investigator",
    "agency"
  ]);

  document.getElementById("caseNumber").value = saved.caseNumber || "";
  document.getElementById("itemNumber").value = saved.itemNumber || "";
  document.getElementById("investigator").value = saved.investigator || "";
  document.getElementById("agency").value = saved.agency || "";
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

  await chrome.storage.local.set({
    caseNumber: caseInfo.case_number,
    itemNumber: caseInfo.item_number,
    investigator: caseInfo.investigator,
    agency: caseInfo.agency
  });

  try {
    const response = await chrome.runtime.sendMessage({
      action: "capturePage",
      caseInfo
    });

    if (response && response.success) {
      status.textContent = "Capture exported successfully.";
    } else {
      status.textContent = "Capture failed: " + (response?.error || "Unknown error");
    }
  } catch (err) {
    status.textContent = "Capture failed: " + err.message;
  } finally {
    button.disabled = false;
  }
});
