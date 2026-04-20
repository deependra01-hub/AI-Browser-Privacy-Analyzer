const endpoints = {
  summary: "/api/summary",
  websites: "/api/websites",
  domains: "/api/domains",
  alerts: "/api/alerts",
};

const elements = {
  refresh: document.getElementById("last-refresh"),
  latestAlert: document.getElementById("latest-alert"),
  requests: document.getElementById("metric-requests"),
  websites: document.getElementById("metric-websites"),
  highRisk: document.getElementById("metric-high-risk"),
  trackers: document.getElementById("metric-trackers"),
  websiteTable: document.getElementById("website-table"),
  alertsList: document.getElementById("alerts-list"),
  domainChart: document.getElementById("domain-chart"),
};

function riskBadge(category) {
  const level = category.toLowerCase().includes("high")
    ? "high"
    : category.toLowerCase().includes("medium")
      ? "medium"
      : "low";
  return `<span class="badge ${level}">${category}</span>`;
}

function formatTime(value) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Request failed: ${url}`);
  }
  return response.json();
}

function renderSummary(summary) {
  elements.requests.textContent = summary.total_requests;
  elements.websites.textContent = summary.total_websites;
  elements.highRisk.textContent = summary.high_risk_websites;
  elements.trackers.textContent = summary.trackers_detected;
  elements.latestAlert.textContent = summary.latest_alert;
  elements.refresh.textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
}

function renderWebsites(websites) {
  if (!websites.length) {
    elements.websiteTable.innerHTML = `<tr><td colspan="6" class="empty">No website data yet.</td></tr>`;
    return;
  }

  elements.websiteTable.innerHTML = websites
    .map(
      (site) => `
        <tr>
          <td>${site.website}</td>
          <td>${site.risk_score}</td>
          <td>${riskBadge(site.category)}</td>
          <td>${site.tracker_count}</td>
          <td>${site.third_party_count}</td>
          <td>${site.sensitive_hits}</td>
        </tr>
      `
    )
    .join("");
}

function renderAlerts(alerts) {
  if (!alerts.length) {
    elements.alertsList.innerHTML = `<div class="empty-card">No alerts generated yet.</div>`;
    return;
  }

  elements.alertsList.innerHTML = alerts
    .map(
      (alert) => `
        <article class="alert-card severity-${alert.severity}">
          <strong>${alert.message}</strong>
          <div class="alert-meta">${alert.website} • ${alert.domain}</div>
          <div class="alert-meta">${formatTime(alert.timestamp)}</div>
        </article>
      `
    )
    .join("");
}

function renderDomains(domains) {
  if (!domains.length) {
    elements.domainChart.innerHTML = `<div class="empty-card">No domain behavior data yet.</div>`;
    return;
  }

  elements.domainChart.innerHTML = domains
    .slice(0, 8)
    .map((domain) => {
      const width = Math.max(8, Math.round(domain.anomaly_score * 100));
      return `
        <article class="chart-row">
          <strong>${domain.domain}</strong>
          <div class="chart-meta">${domain.profile} • ${domain.status}</div>
          <div class="chart-meta">RPM: ${domain.requests_per_minute} • Sites: ${domain.sites_detected_on}</div>
          <div class="chart-bar"><span style="width:${width}%"></span></div>
        </article>
      `;
    })
    .join("");
}

async function refreshDashboard() {
  try {
    const [summary, websites, domains, alerts] = await Promise.all([
      fetchJson(endpoints.summary),
      fetchJson(endpoints.websites),
      fetchJson(endpoints.domains),
      fetchJson(endpoints.alerts),
    ]);

    renderSummary(summary);
    renderWebsites(websites);
    renderDomains(domains);
    renderAlerts(alerts);
  } catch (error) {
    elements.refresh.textContent = "Dashboard failed to load. Check whether the backend is running.";
    console.error(error);
  }
}

refreshDashboard();
setInterval(refreshDashboard, 5000);
