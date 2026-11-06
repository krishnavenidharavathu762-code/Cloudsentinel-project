(() => {
  const $ = (s) => document.querySelector(s);
  let latest = null;
  let toastTimer;
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const toast = (message) => {
    const el = $("#toast"); el.textContent = message; el.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 3000);
  };
  const riskClass = (risk) => {
    const r = String(risk || "").toLowerCase();
    if (r.includes("critical")) return "risk-critical";
    if (r.includes("high")) return "risk-high";
    if (r.includes("medium")) return "risk-medium";
    if (r.includes("low")) return "risk-low";
    if (r.includes("info")) return "risk-informational";
    return "";
  };
  const riskBadge = (risk) => `<span class="risk ${riskClass(risk)}">${esc(risk || "Unknown")}</span>`;
  const dateText = (v) => { if (!v) return "—"; const d = new Date(v); return Number.isNaN(d.getTime()) ? esc(v) : d.toLocaleString(); };

  // Authentication and session handling
  const authPanels = ["login", "register", "verify", "forgot", "reset"];

  function authNotice(message, isError = false) {
    const box = $("#auth-message");
    if (!box) return;
    box.textContent = message;
    box.classList.add("visible");
    box.classList.toggle("error", isError);
  }

  function showAuth(panel = "login", message = "", isError = false) {
    $("#dashboard-shell").hidden = true;
    $("#auth-screen").hidden = false;
    authPanels.forEach(name => {
      const el = document.getElementById(`${name}-panel`);
      if (el) el.hidden = name !== panel;
    });
    const box = $("#auth-message");
    box.classList.remove("visible", "error");
    box.textContent = "";
    if (message) authNotice(message, isError);
  }

  async function authRequest(url, payload) {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json", "Accept": "application/json"},
      body: JSON.stringify(payload)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data.detail;
      throw new Error(typeof detail === "string" ? detail : `Request failed (${response.status})`);
    }
    return data;
  }

  function showDashboard(user) {
    $("#auth-screen").hidden = true;
    $("#dashboard-shell").hidden = false;
    $("#account-email").textContent = user.email || "Signed in";
    health();
    history();
    loadGitHubRepositories();
  }

  async function loadGitHubRepositories() {
    const select = $("#gitleaks-repository");
    const status = $("#github-gitleaks-status");
    const branchInput = $("#gitleaks-branch");

    if (!select || !status || !branchInput) return;

    status.textContent = "Loading your GitHub repositories...";
    select.replaceChildren(new Option("Loading repositories...", ""));

    try {
      const response = await fetch("/api/github/repos", {
        credentials: "same-origin",
        cache: "no-store"
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : response.status === 404
              ? "Connect your GitHub account first."
              : `Could not load repositories (HTTP ${response.status}).`
        );
      }

      const repos = Array.isArray(data.repositories) ? data.repositories : [];
      select.replaceChildren();

      if (!repos.length) {
        select.add(new Option("No repositories found", ""));
        status.textContent = "No accessible repositories were returned by GitHub.";
        return;
      }

      repos.forEach(repo => {
        const option = new Option(
          `${repo.full_name} (${repo.private ? "Private" : "Public"})`,
          repo.full_name
        );
        option.dataset.defaultBranch = repo.default_branch || "main";
        select.add(option);
      });

      branchInput.value = select.selectedOptions[0]?.dataset.defaultBranch || "main";
      status.textContent = `${repos.length} GitHub repositories loaded.`;
    } catch (error) {
      select.replaceChildren(new Option("Connect or reload GitHub", ""));
      status.textContent = error.message;
    }
  }

  async function authBoot() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const path = window.location.pathname;

    if (token && path.endsWith("/reset-password")) {
      $("#reset-token").value = token;
      showAuth("reset", "Password-reset token loaded. Choose your new password.");
      return;
    }

    try {
      const response = await fetch("/api/auth/me", {
        credentials: "same-origin",
        cache: "no-store"
      });
      if (!response.ok) {
        showAuth("login");
        return;
      }
      const user = await response.json();
      showDashboard(user);
    } catch {
      showAuth("login", "Unable to contact CloudSentinel. Please try again.", true);
    }
  }

  document.querySelectorAll("[data-auth-show]").forEach(button => {
    button.addEventListener("click", () => showAuth(button.dataset.authShow));
  });

  $("#login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const data = await authRequest("/api/auth/login", {
        email: $("#login-email").value.trim(),
        password: $("#login-password").value
      });
      showDashboard(data);
    } catch (error) {
      authNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("#register-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button[type=submit]");
    button.disabled = true;
    const email = $("#register-email").value.trim();
    const password = $("#register-password").value;

    try {
      const data = await authRequest("/api/auth/register", {email, password});
      $("#login-email").value = email;
      showAuth("login", data.message || "Account created. You can now sign in.");
    } catch (error) {
      authNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("#forgot-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const data = await authRequest("/api/auth/forgot-password", {
        email: $("#forgot-email").value.trim()
      });
      authNotice(data.message || "If an account exists, reset instructions will be sent.");
    } catch (error) {
      authNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("#reset-form").addEventListener("submit", async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const data = await authRequest("/api/auth/reset-password", {
        token: $("#reset-token").value.trim(),
        new_password: $("#reset-password").value
      });
      showAuth("login", data.message || "Password updated. Please sign in.");
      $("#reset-form").reset();
    } catch (error) {
      authNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("#github-connect").addEventListener("click", () => {
    window.location.assign("/auth/github/login");
  });

  $("#logout-button").addEventListener("click", async () => {
    try {
      await authRequest("/api/auth/logout", {});
      latest = null;
      showAuth("login", "You have signed out.");
    } catch (error) {
      toast(error.message || "Sign out failed.");
    }
  });


  async function health() {
    try {
      const r = await fetch("/api/health", {cache:"no-store"});
      if (!r.ok) throw new Error();
      const d = await r.json();
      $("#api-status").textContent = "Connected";
      $("#health-message").textContent = `${d.service || "CloudSentinel"} API is responding · version ${d.version || "unknown"}`;
    } catch {
      $("#api-status").textContent = "Unavailable";
      $("#health-message").textContent = "Unable to reach the API health endpoint.";
    }
  }


  function updateAnalytics(scans) {
    const findings = scans.flatMap(scan =>
      Array.isArray(scan.findings)
        ? scan.findings.map(finding => ({...finding, __report: scan}))
        : []
    );

    const setText = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    };

    const countBy = (items, keyFn) => {
      const counts = {};
      items.forEach(item => {
        const key = keyFn(item);
        counts[key] = (counts[key] || 0) + 1;
      });
      return counts;
    };

    const renderBars = (containerId, entries, options = {}) => {
      const el = document.getElementById(containerId);
      if (!el) return;

      if (!entries.length) {
        el.innerHTML = '<p class="muted">No data available in saved reports.</p>';
        return;
      }

      const max = Math.max(...entries.map(item => item.count), 1);
      el.innerHTML = entries.map(item => {
        const width = Math.max(item.count > 0 ? 3 : 0, item.count / max * 100);
        const label = esc(item.label);
        const color = options.severity
          ? `bar-${String(item.key).toLowerCase().replace(/[^a-z]/g, "")}`
          : "bar-default";

        return `
          <div class="analytics-bar-row">
            <div class="analytics-bar-label" title="${label}">${label}</div>
            <div class="analytics-bar-track">
              <div class="analytics-bar-fill ${color}" style="width:${width}%"></div>
            </div>
            <b class="analytics-bar-count">${item.count}</b>
          </div>`;
      }).join("");
    };

    setText("analytics-findings", findings.length);

    const openCount = findings.filter(f =>
      String(f.status || "").toLowerCase() === "open"
    ).length;
    setText("analytics-open", openCount);

    const affectedTargets = new Set(
      scans.filter(scan =>
        Array.isArray(scan.findings) && scan.findings.length > 0
      ).map(scan => String(scan.target || "Unknown"))
    );
    setText("analytics-targets", affectedTargets.size);

    // These are the scanner cards currently available in index.html.
    const scannerAliases = {
      "ZIP Analyzer": ["ZIP Analyzer"],
      "Project Readiness Analyzer": ["Project Readiness Analyzer"],
      "Source Code": ["Source Code Security Scanner", "Source Code Scanner"],
      "Website URL": ["URL & Webpage Security Scanner"],
      "Trivy Security": ["Trivy Container Security Scanner"],
      "Terraform": ["Terraform Security Scanner"],
      "Checkov Infrastructure": ["Checkov Infrastructure Security Scanner"],
      "Semgrep Code Security": ["Semgrep"],
      "Bandit Python Security": ["Bandit"],
      "Gitleaks Secret Detection": ["Gitleaks"],
      "SonarQube Analysis": ["SonarQube"]
    };
    const scannerMap = new Map();
    Object.entries(scannerAliases).forEach(([name, aliases]) =>
      aliases.forEach(alias => scannerMap.set(alias.toLowerCase(), name))
    );
    const scannerCounts = {};
    scans.forEach(scan => {
      const name = scannerMap.get(String(scan.tool || "").trim().toLowerCase());
      if (name) {
        scannerCounts[name] = (scannerCounts[name] || 0) +
          (Array.isArray(scan.findings) ? scan.findings.length : 0);
      }
    });
    setText("analytics-scanners", Object.keys(scannerCounts).length);

    // Clickable summary cards: show the records behind each metric.
    const summaryPanel = document.getElementById("summary-details");
    const summaryTitle = document.getElementById("summary-details-title");
    const summaryBody = document.getElementById("summary-details-body");

    const summaryField = (label, value) => {
      if (value === undefined || value === null || value === "") return "";
      const shown = typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
      return `<div class="finding-field"><small>${esc(label)}</small><div>${esc(shown)}</div></div>`;
    };

    const showSummary = (kind) => {
      if (!summaryPanel || !summaryTitle || !summaryBody) return;
      let title = "";
      let content = "";

      if (kind === "open") {
        const matching = findings.filter(f => String(f.status || "").toLowerCase() === "open");
        title = `Open Findings — ${matching.length}`;
        content = matching.map((f, i) => {
          const report = f.__report || {};
          return `<article class="finding summary-record">
            <b>${i + 1}. ${esc(f.title || "Finding")}</b>
            ${summaryField("Severity", f.severity || "Unclassified")}
            ${summaryField("Scanner", f.scanner || report.tool)}
            ${summaryField("Target", report.target)}
            ${summaryField("File / location", f.file_path || f.location)}
            ${summaryField("Line", f.line)}
            ${summaryField("CWE / CVE", [f.cwe, f.cve].filter(Boolean).join(" / "))}
            ${summaryField("Description", f.detail)}
            ${summaryField("Recommendation", f.recommendation || f.remediation)}
          </article>`;
        }).join("") || '<p class="muted">There are no findings explicitly marked Open.</p>';
      } else if (kind === "targets") {
        const matching = scans.filter(s => Array.isArray(s.findings) && s.findings.length);
        title = `Affected Targets — ${affectedTargets.size}`;
        content = matching.map((s, i) => `<article class="finding summary-record">
          <b>${i + 1}. ${esc(s.target || "Unspecified target")}</b>
          ${summaryField("Scanner", s.tool)}
          ${summaryField("Scan date", dateText(s.created_at))}
          ${summaryField("Risk", s.summary?.risk)}
          ${summaryField("Finding count", s.summary?.finding_count ?? s.findings.length)}
          ${summaryField("Scan ID", s.scan_id)}
        </article>`).join("") || '<p class="muted">No saved targets currently have findings.</p>';
      } else if (kind === "scanners") {
        title = `Scanners Used — ${Object.keys(scannerCounts).length}`;
        content = Object.entries(scannerCounts).map(([name, count]) => {
          const reports = scans.filter(s =>
            scannerMap.get(String(s.tool || "").trim().toLowerCase()) === name
          );
          return `<article class="finding summary-record">
            <b>${esc(name)}</b>
            ${summaryField("Finding count", count)}
            ${summaryField("Scan reports", reports.length)}
            ${summaryField("Targets", [...new Set(reports.map(s => s.target || "Unspecified target"))].join(", "))}
          </article>`;
        }).join("") || '<p class="muted">No recognised dashboard scanners have saved reports yet.</p>';
      }

      summaryTitle.textContent = title;
      summaryBody.innerHTML = content;
      summaryPanel.hidden = false;
      summaryPanel.scrollIntoView({behavior: "smooth", block: "nearest"});
    };

    document.querySelectorAll("[data-summary]").forEach(card => {
      if (card.dataset.clickBound) return;
      card.dataset.clickBound = "true";
      card.addEventListener("click", () => showSummary(card.dataset.summary));
      card.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showSummary(card.dataset.summary);
        }
      });
    });

    const summaryClose = document.getElementById("summary-details-close");
    if (summaryClose && !summaryClose.dataset.clickBound) {
      summaryClose.dataset.clickBound = "true";
      summaryClose.addEventListener("click", () => { summaryPanel.hidden = true; });
    }


    const severityOrder = ["critical", "high", "medium", "low", "info", "unclassified"];
    const severityLabels = {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
      info: "Informational",
      unclassified: "Unclassified"
    };

    const severityCounts = countBy(findings, f => {
      const value = String(f.severity || "unclassified").toLowerCase();
      if (value === "informational") return "info";
      return severityOrder.includes(value) ? value : "unclassified";
    });

    renderBars("severity-chart",
      severityOrder.map(key => ({
        key,
        label: severityLabels[key],
        count: severityCounts[key] || 0
      }))
    , {severity: true});

    renderBars("scanner-chart",
      Object.entries(scannerCounts)
        .map(([label, count]) => ({label, count}))
        .sort((a, b) => b.count - a.count)
    );

    const cweFindings = findings.filter(f => f.cwe && String(f.cwe).trim());
    const cweCounts = countBy(cweFindings, f => String(f.cwe).trim());
    const cweChart = document.getElementById("cwe-chart");

    if (cweChart) {
      const topCwes = Object.entries(cweCounts)
        .map(([label, count]) => ({label, count}))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);

      cweChart.innerHTML = topCwes.length ? topCwes.map(item => {
        const width = Math.max(3, item.count / Math.max(...topCwes.map(x => x.count)) * 100);
        const label = esc(item.label);
        return `<button type="button" class="analytics-bar-row cwe-bar-button"
          data-cwe="${label}" title="Show ${label} findings">
          <span class="analytics-bar-label">${label}</span>
          <span class="analytics-bar-track"><span class="analytics-bar-fill" style="width:${width}%"></span></span>
          <b class="analytics-bar-count">${item.count}</b>
        </button>`;
      }).join("") : '<p class="muted">No CWE identifiers are present in the saved findings.</p>';
    }

    const details = document.getElementById("cwe-details");
    const detailsTitle = document.getElementById("cwe-details-title");
    const detailsBody = document.getElementById("cwe-details-body");

    if (cweChart && details && !cweChart.dataset.clickBound) {
      cweChart.dataset.clickBound = "true";
      cweChart.addEventListener("click", event => {
        const button = event.target.closest("button[data-cwe]");
        if (!button) return;

        const selected = button.dataset.cwe;
        const matching = cweFindings.filter(f => String(f.cwe).trim() === selected);
        detailsTitle.textContent = `${selected} — ${matching.length} finding(s)`;

        const value = v => {
          if (v === undefined || v === null || v === "") return "";
          return typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
        };
        const field = (label, v) => {
          const text = value(v);
          return text ? `<div class="finding-field"><small>${esc(label)}</small><div>${esc(text)}</div></div>` : "";
        };
        const refs = list => {
          if (!Array.isArray(list) || !list.length) return "";
          return `<div class="finding-field"><small>References</small><ul>${list.map(ref => {
            const url = typeof ref === "string" ? ref : ref?.url;
            const label = typeof ref === "string" ? ref : (ref?.title || ref?.url || "Reference");
            return url && /^https?:\/\//i.test(url)
              ? `<li><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a></li>`
              : `<li>${esc(label)}</li>`;
          }).join("")}</ul></div>`;
        };

        detailsBody.innerHTML = matching.map((f, i) => {
          const report = f.__report || {};
          const loc = f.location && typeof f.location === "object" ? f.location : {};
          const location = [
            loc.file_path || f.file_path,
            loc.line ?? f.line,
            loc.line_end ?? f.line_end,
            loc.column ?? f.column
          ].filter(v => v !== undefined && v !== null && v !== "").join(" · ");

          return `<article class="finding cwe-finding-detail">
            <div class="finding-head">
              <b>${i + 1}. ${esc(f.title || "Finding")}</b>
              <span class="sev sev-${esc(String(f.severity || "unknown").toLowerCase())}">${esc(f.severity || "unknown")}</span>
            </div>
            ${field("Scanner", f.scanner || report.tool)}
            ${field("Target", report.target)}
            ${field("Scan date", report.created_at)}
            ${field("Description", f.detail)}
            ${field("Location (file / line / column)", location)}
            ${field("URL / affected component", f.url || f.component || loc.url || loc.element)}
            ${field("CWE", f.cwe)}
            ${field("CVE", f.cve)}
            ${field("Confidence", f.confidence)}
            ${field("Status", f.status)}
            ${field("Evidence", f.evidence)}
            ${field("Root cause", f.root_cause)}
            ${field("Security / business impact", f.impact)}
            ${field("Recommendation", f.recommendation)}
            ${field("Remediation", f.remediation)}
            ${field("Suggested fixed code", f.fixed_code)}
            ${refs(f.references)}
          </article>`;
        }).join("");

        details.hidden = false;
        details.scrollIntoView({behavior: "smooth", block: "nearest"});
      });
    }

    const closeButton = document.getElementById("cwe-details-close");
    if (closeButton && !closeButton.dataset.clickBound) {
      closeButton.dataset.clickBound = "true";
      closeButton.addEventListener("click", () => { details.hidden = true; });
    }

    const dailyCounts = {};
    scans.forEach(scan => {
      if (!scan.created_at) return;
      const date = new Date(scan.created_at);
      if (Number.isNaN(date.getTime())) return;
      const key = date.toISOString().slice(0, 10);
      dailyCounts[key] = (dailyCounts[key] || 0) +
        (Array.isArray(scan.findings) ? scan.findings.length : 0);
    });

    const trendEntries = Object.entries(dailyCounts)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-7)
      .map(([date, count]) => ({
        label: new Date(date + "T00:00:00").toLocaleDateString(
          undefined, {month: "short", day: "numeric"}
        ),
        count
      }));

    renderBars("trend-chart", trendEntries);
  }

  async function history() {
    try {
      const r = await fetch("/api/scans", {cache:"no-store"});
      if (!r.ok) throw new Error(`History request failed (${r.status})`);
      const d = await r.json();
      const scans = Array.isArray(d.scans) ? d.scans : [];
      updateAnalytics(scans);
      $("#stat-total").textContent = scans.length;
      $("#stat-high").textContent = scans.filter(x => /high|critical/i.test(x.summary?.risk || "")).length;
      $("#history-list").innerHTML = scans.length ? scans.map((x, index) => `
        <article class="history-card">
          <div class="history-card-top">
            <span class="history-card-number">SCAN ${scans.length - index}</span>
            <span class="history-risk">${riskBadge(x.summary?.risk)}</span>
          </div>
          <h3>${esc(x.target || "Unknown target")}</h3>
          <p class="history-scanner">${esc(x.tool || "Scanner")}</p>
          <div class="history-card-stats">
            <div><small>FINDINGS</small><strong>${esc(x.summary?.finding_count ?? x.findings?.length ?? 0)}</strong></div>
            <div><small>DATE</small><strong>${dateText(x.created_at)}</strong></div>
          </div>
          <div class="history-card-findings">
            ${Array.isArray(x.findings) && x.findings.length
              ? x.findings.map(f => `<div class="history-finding">
                  <span class="sev sev-${esc(String(f.severity || "unclassified").toLowerCase())}">${esc(f.severity || "Unclassified")}</span>
                  <b>${esc(f.title || "Finding")}</b>
                  ${f.file_path ? `<small>${esc(f.file_path)}${f.line ? ":" + esc(f.line) : ""}</small>` : ""}
                </div>`).join("")
              : '<span class="muted">No findings recorded for this scan.</span>'}
          </div>
          <details class="history-card-details">
            <summary>View scan details</summary>
            <p><b>Scan ID:</b> ${esc(x.scan_id || "—")}</p>
            <p><b>Target:</b> ${esc(x.target || "—")}</p>
            <p><b>Scanner:</b> ${esc(x.tool || "—")}</p>
            <p><b>Status:</b> ${esc(x.status || "Saved report")}</p>
          </details>
        </article>`).join("") :
        '<p class="empty">No scans yet. Run a scan to create your first report.</p>';
    } catch (e) {
      $("#history-list").innerHTML = '<tr><td colspan="6" class="empty">Scan history is unavailable.</td></tr>';
      toast(e.message);
    }
  }

  function render(report) {
    latest = report;
    $("#results").classList.remove("hidden");
    $("#result-title").textContent = `${report.tool || "Scan"} — ${report.target || "Result"}`;
    $("#result-meta").textContent = `Scan ID: ${report.scan_id || "—"} · ${dateText(report.created_at)}`;

    $("#result-summary").innerHTML = `
      <div class="summary-item"><small>Risk</small><b>${riskBadge(report.summary?.risk)}</b></div>
      <div class="summary-item"><small>Findings</small><b>${esc(report.summary?.finding_count ?? report.findings?.length ?? 0)}</b></div>
      <div class="summary-item"><small>Scanner</small><b>${esc(report.tool || "—")}</b></div>`;

    const findings = Array.isArray(report.findings) ? report.findings : [];

    const field = (label, value) => {
      if (value === undefined || value === null || value === "") return "";
      const display = Array.isArray(value) ? value.join(", ") : value;
      return `<div class="finding-field"><small>${esc(label)}</small><div>${esc(display)}</div></div>`;
    };

    const references = value => {
      if (!Array.isArray(value) || !value.length) return "";
      return `<div class="finding-field"><small>References</small><ul>${value.map(ref => {
        const url = typeof ref === "string" ? ref : ref?.url;
        const label = typeof ref === "string" ? ref : (ref?.title || ref?.url || "Reference");
        if (!url || !/^https?:\/\//i.test(url)) return `<li>${esc(label)}</li>`;
        return `<li><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a></li>`;
      }).join("")}</ul></div>`;
    };

    $("#result-body").innerHTML = findings.length ? findings.map(f => {
      const loc = f.location && typeof f.location === "object" ? f.location : {};
      const filePath = loc.file_path || f.file_path;
      const line = loc.line ?? f.line;
      const lineEnd = loc.line_end ?? f.line_end;
      const column = loc.column ?? f.column;
      const locationText = [
        filePath,
        line !== undefined && line !== null ? `Line ${line}${lineEnd && lineEnd !== line ? `–${lineEnd}` : ""}` : "",
        column !== undefined && column !== null ? `Column ${column}` : ""
      ].filter(Boolean).join(" · ");

      return `
        <article class="finding">
          <div class="finding-head">
            <b>${esc(f.title || "Finding")}</b>
            <span class="sev sev-${esc(String(f.severity || "unknown").toLowerCase())}">${esc(f.severity || "unknown")}</span>
          </div>
          ${field("Description", f.detail)}
          ${field("Location", locationText)}
          ${field("Scanner", f.scanner || report.tool)}
          ${field("CWE", f.cwe)}
          ${field("CVE", f.cve)}
          ${field("Confidence", f.confidence)}
          ${field("Evidence", f.evidence)}
          ${field("Root cause", f.root_cause)}
          ${field("Security / business impact", f.impact)}
          ${field("Remediation", f.remediation || f.recommendation)}
          ${field("Suggested fixed code", f.fixed_code)}
          ${references(f.references)}
        </article>`;
    }).join("") :
      '<div class="finding"><p>No individual findings were returned by this scanner. This does not guarantee that the target is free of security vulnerabilities.</p></div>';

    $("#result-json").textContent = JSON.stringify(report, null, 2);
    $("#results").scrollIntoView({behavior:"smooth", block:"start"});
  }

  const endpoints = {project:"/api/scan/project",zip:"/api/scan/zip",code:"/api/scan/code",terraform:"/api/scan/terraform",checkov:"/api/scan/checkov",url:"/api/scan/url",image:"/api/scan/image",semgrep:"/api/scan/advanced/semgrep",bandit:"/api/scan/advanced/bandit",gitleaks:"/api/scan/advanced/gitleaks",sonarqube:"/api/scan/sonarqube"};
  document.querySelectorAll("form[data-kind]").forEach(form => form.addEventListener("submit", async e => {
    e.preventDefault();
    const kind = form.dataset.kind, button = form.querySelector("button"), original = button.innerHTML;
    button.disabled = true; button.textContent = "Scanning…";
    try {
      let response;
      if (["project","zip","code","terraform","checkov","semgrep","bandit","gitleaks","sonarqube"].includes(kind)) {
        response = await fetch(endpoints[kind], {method:"POST", body:new FormData(form)});
      } else {
        const key = kind === "url" ? "url" : "image";
        response = await fetch(endpoints[kind], {method:"POST", headers:{"Content-Type":"application/json","Accept":"application/json"}, body:JSON.stringify({[key]:form.elements[key].value.trim()})});
      }
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data) || `HTTP ${response.status}`);
      render(data); await history(); toast("Scan completed and report saved.");
      if (["project","zip","code","terraform","checkov","semgrep","bandit","gitleaks","sonarqube"].includes(kind)) form.reset();
    } catch (err) { toast(err.message || "Scan failed"); }
    finally { button.disabled = false; button.innerHTML = original; }
  }));

  $("#refresh").addEventListener("click", async () => { await history(); await health(); toast("Dashboard refreshed."); });
  $("#copy").addEventListener("click", async () => {
    if (!latest) return;
    try { await navigator.clipboard.writeText(JSON.stringify(latest,null,2)); toast("JSON copied."); }
    catch { toast("Clipboard access unavailable in this browser."); }
  });
  $("#download").addEventListener("click", () => {
    if (!latest) return;
    const blob = new Blob([JSON.stringify(latest,null,2)], {type:"application/json"});
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = `cloudsentinel-${latest.scan_id || "report"}.json`; a.click(); URL.revokeObjectURL(url);
  });
  $("#gitleaks-repository").addEventListener("change", event => {
    const option = event.currentTarget.selectedOptions[0];
    $("#gitleaks-branch").value = option?.dataset.defaultBranch || "main";
  });

  $("#github-gitleaks-scan").addEventListener("click", async event => {
    const button = event.currentTarget;
    const status = $("#github-gitleaks-status");
    const selected = $("#gitleaks-repository").value;
    const branch = $("#gitleaks-branch").value.trim();

    if (!selected || !selected.includes("/")) {
      status.textContent = "Please select a GitHub repository.";
      return;
    }

    if (!branch) {
      status.textContent = "Please enter a branch name.";
      return;
    }

    const [owner, repo] = selected.split("/");
    const original = button.innerHTML;
    button.disabled = true;
    button.textContent = "Scanning GitHub repository...";
    status.textContent = `Gitleaks is scanning ${selected} (${branch})...`;

    try {
      const response = await fetch("/api/scan/github/gitleaks", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({owner, repo, branch})
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : `GitHub scan failed (HTTP ${response.status}).`
        );
      }

      render(data);
      await history();
      status.textContent = `Scan completed for ${selected} (${branch}).`;
      toast("GitHub Gitleaks scan completed and report saved.");
    } catch (error) {
      status.textContent = error.message || "GitHub scan failed.";
      toast(status.textContent);
    } finally {
      button.disabled = false;
      button.innerHTML = original;
    }
  });

  authBoot();
  setInterval(() => {
    if (!$("#dashboard-shell").hidden) health();
  }, 60000);
})();