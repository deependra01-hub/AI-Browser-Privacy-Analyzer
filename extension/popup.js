const DEFAULT_BACKEND_BASE = "http://localhost:8000";

function sanitizeBackendBaseUrl(rawValue) {
  const candidate = typeof rawValue === "string" ? rawValue.trim() : "";
  if (!candidate) {
    return DEFAULT_BACKEND_BASE;
  }

  try {
    const parsedUrl = new URL(candidate);
    if (!/^https?:$/i.test(parsedUrl.protocol)) {
      return DEFAULT_BACKEND_BASE;
    }
    return parsedUrl.origin;
  } catch (error) {
    return DEFAULT_BACKEND_BASE;
  }
}

async function loadState() {
  const state = await chrome.storage.local.get([
    "backendBaseUrl",
    "requestCount",
    "lastAlert",
    "lastStatus"
  ]);

  const backendBaseUrl = sanitizeBackendBaseUrl(state.backendBaseUrl);
  if (backendBaseUrl !== state.backendBaseUrl) {
    await chrome.storage.local.set({ backendBaseUrl });
  }

  document.getElementById("backend-url").value = backendBaseUrl;
  document.getElementById("count").textContent = state.requestCount || 0;
  document.getElementById("alert").textContent = state.lastAlert || "No alerts yet";
  document.getElementById("status").textContent = state.lastStatus || "Waiting for network traffic";
}

document.getElementById("save-settings").addEventListener("click", async () => {
  const backendUrl = sanitizeBackendBaseUrl(document.getElementById("backend-url").value);
  await chrome.storage.local.set({
    backendBaseUrl: backendUrl,
    lastStatus: `Saved backend: ${backendUrl}`
  });
  loadState();
});

document.getElementById("open-dashboard").addEventListener("click", () => {
  const backendUrl = sanitizeBackendBaseUrl(document.getElementById("backend-url").value);
  chrome.tabs.create({ url: backendUrl });
});

loadState();
