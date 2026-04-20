const DEFAULT_BACKEND_BASE = "http://localhost:8000";

function isHttpUrl(value) {
  return typeof value === "string" && /^https?:\/\//i.test(value);
}

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

function normalizeDomain(rawUrl) {
  try {
    return new URL(rawUrl).hostname.replace(/^www\./, "");
  } catch (error) {
    return "";
  }
}

function shouldIgnore(url) {
  return (
    !url ||
    !url.startsWith("http") ||
    url.includes("localhost:8000") ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("devtools://")
  );
}

function buildPayload(details, cookieHeader, tabUrl) {
  const requestUrl = details.url;
  const domain = normalizeDomain(requestUrl);
  const pageUrl =
    [details.documentUrl, tabUrl, details.initiator].find((candidate) => isHttpUrl(candidate)) || requestUrl;

  return {
    url: requestUrl,
    domain,
    method: details.method || "GET",
    cookies: cookieHeader || "",
    timestamp: new Date(details.timeStamp || Date.now()).toISOString(),
    tab_url: pageUrl,
    website: normalizeDomain(pageUrl),
    source: "chrome_extension"
  };
}

async function rememberState(updates) {
  return chrome.storage.local.set(updates);
}

async function getBackendBaseUrl() {
  const { backendBaseUrl = DEFAULT_BACKEND_BASE } = await chrome.storage.local.get(["backendBaseUrl"]);
  const sanitizedUrl = sanitizeBackendBaseUrl(backendBaseUrl);

  if (sanitizedUrl !== backendBaseUrl) {
    await chrome.storage.local.set({ backendBaseUrl: sanitizedUrl });
  }

  return sanitizedUrl;
}

function getTabUrl(tabId) {
  return new Promise((resolve) => {
    if (tabId < 0) {
      resolve("");
      return;
    }

    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) {
        resolve("");
        return;
      }
      resolve(tab.url || "");
    });
  });
}

async function sendToBackend(payload) {
  try {
    const backendBaseUrl = await getBackendBaseUrl();
    const response = await fetch(`${backendBaseUrl}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    const { requestCount = 0 } = await chrome.storage.local.get(["requestCount"]);
    const latestAlert = result.alerts && result.alerts.length ? result.alerts[0] : "No alerts";

    await rememberState({
      requestCount: requestCount + 1,
      lastRequest: payload.url,
      lastWebsite: payload.website,
      lastAlert: latestAlert,
      lastStatus: response.ok ? `Connected to ${backendBaseUrl}` : "Backend returned an error"
    });
  } catch (error) {
    await rememberState({
      lastStatus: "Backend offline or unreachable",
      lastError: error.message
    });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    backendBaseUrl: DEFAULT_BACKEND_BASE,
    requestCount: 0,
    lastAlert: "No alerts yet",
    lastStatus: "Waiting for network traffic"
  });
});

chrome.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    if (shouldIgnore(details.url)) {
      return;
    }

    const cookieHeader = (details.requestHeaders || []).find(
      (header) => header.name.toLowerCase() === "cookie"
    );
    const tabUrl = await getTabUrl(details.tabId);
    const payload = buildPayload(details, cookieHeader ? cookieHeader.value : "", tabUrl);
    await sendToBackend(payload);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders", "extraHeaders"]
);
