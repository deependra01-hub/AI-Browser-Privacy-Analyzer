const endpoints = {
  summary: "/api/summary",
  websites: "/api/websites",
  domains: "/api/domains",
  alerts: "/api/alerts",
  websiteDetails: (website) => `/api/websites/${encodeURIComponent(website)}`,
};

let selectedWebsite = null;

const elements = {
  refresh: document.getElementById("last-refresh"),
  latestAlert: document.getElementById("latest-alert"),
  requests: document.getElementById("metric-requests"),
  websites: document.getElementById("metric-websites"),
  highRisk: document.getElementById("metric-high-risk"),
  trackers: document.getElementById("metric-trackers"),
  websiteTable: document.getElementById("website-table"),
  websiteDetail: document.getElementById("website-detail"),
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

function renderTagList(items, emptyLabel = "None observed") {
  if (!items || !items.length) {
    return `<span class="tag muted-tag">${emptyLabel}</span>`;
  }
  return items.map((item) => `<span class="tag">${item}</span>`).join("");
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
    elements.websiteTable.innerHTML = `<tr><td colspan="7" class="empty">No website data yet.</td></tr>`;
    elements.websiteDetail.innerHTML = `<div class="empty-card">No website details yet.</div>`;
    return;
  }

  if (!selectedWebsite || !websites.some((site) => site.website === selectedWebsite)) {
    selectedWebsite = websites[0].website;
  }

  elements.websiteTable.innerHTML = websites
    .map(
      (site) => `
        <tr class="website-row risk-${site.category.toLowerCase().replace(/\s+/g, "-")} ${site.website === selectedWebsite ? "selected-row" : ""}" data-website="${site.website}">
          <td>${site.website}</td>
          <td>${formatTime(site.last_updated)}</td>
          <td>${site.risk_score}</td>
          <td>${riskBadge(site.category)}</td>
          <td>${renderTagList(site.risk_types, "Low observable risk")}</td>
          <td>${renderTagList(site.data_shared, "No sensitive metadata seen")}</td>
          <td>${site.tracker_count}</td>
        </tr>
      `
    )
    .join("");

  document.querySelectorAll(".website-row").forEach((row) => {
    row.addEventListener("click", async () => {
      selectedWebsite = row.dataset.website;
      renderWebsites(websites);
      await loadWebsiteDetails(selectedWebsite);
    });
  });
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
          <div class="alert-meta">${alert.website} | ${alert.domain}</div>
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
          <div class="chart-meta">${domain.profile} | ${domain.status}</div>
          <div class="chart-meta">RPM: ${domain.requests_per_minute} | Sites: ${domain.sites_detected_on}</div>
          <div class="chart-meta">${domain.reason}</div>
          <div class="tag-list compact-tags">${renderTagList(domain.risk_types, "No major risk type")}</div>
          <div class="chart-bar"><span style="width:${width}%"></span></div>
        </article>
      `;
    })
    .join("");
}

function renderWebsiteDetail(detail) {
  const score = detail.score;
  const requests = detail.requests || [];
  elements.websiteDetail.innerHTML = `
    <div class="detail-summary">
      <h3>${detail.website}</h3>
      <p>${riskBadge(score.category)} <span class="score-inline">Risk score: ${score.risk_score} | Last seen: ${formatTime(score.last_updated)}</span></p>
      <div class="detail-block">
        <div class="detail-label">Risk types</div>
        <div class="tag-list">${renderTagList(score.risk_types, "Low observable risk")}</div>
      </div>
      <div class="detail-block">
        <div class="detail-label">Information categories observed</div>
        <div class="tag-list">${renderTagList(score.data_shared, "No sensitive metadata seen")}</div>
      </div>
      <div class="detail-block">
        <div class="detail-label">Tracker domains</div>
        <div class="tag-list">${renderTagList(score.tracker_domains, "No tracker domains yet")}</div>
      </div>
    </div>
    <div class="detail-block">
      <div class="detail-label">Recent requests</div>
      <div class="request-list">
        ${
          requests.length
            ? requests
                .map(
                  (request) => `
                    <article class="request-card">
                      <strong>${request.domain}</strong>
                      <div class="alert-meta">${request.request_url}</div>
                      <div class="alert-meta">${request.tracker_status} | ${request.behavior_profile} | ${request.risk_level}</div>
                      <div class="tag-list compact-tags">${renderTagList(request.risk_types, "Low observable risk")}</div>
                      <div class="tag-list compact-tags">${renderTagList(request.data_shared, "No sensitive metadata seen")}</div>
                      <div class="alert-meta">${request.analysis_reason}</div>
                      <div class="alert-meta">${formatTime(request.timestamp)}</div>
                    </article>
                  `
                )
                .join("")
            : `<div class="empty-card">No recent requests recorded.</div>`
        }
      </div>
    </div>
  `;
}

async function loadWebsiteDetails(website) {
  if (!website) {
    return;
  }

  try {
    const detail = await fetchJson(endpoints.websiteDetails(website));
    renderWebsiteDetail(detail);
  } catch (error) {
    elements.websiteDetail.innerHTML = `<div class="empty-card">Failed to load website details.</div>`;
    console.error(error);
  }
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
    if (selectedWebsite) {
      await loadWebsiteDetails(selectedWebsite);
    }
  } catch (error) {
    elements.refresh.textContent = "Dashboard failed to load. Check whether the backend is running.";
    console.error(error);
  }
}

refreshDashboard();
setInterval(refreshDashboard, 5000);
