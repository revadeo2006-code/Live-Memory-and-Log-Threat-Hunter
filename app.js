const state = { user: null, processes: [], incidents: [], connections: [], investigations: [], reports: [], users: [], adminAlerts: [], safeCount: 0, hasHunt: false };
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

async function api(url, options = {}) { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw Error(data.error || "Request failed"); if (url === "/api/investigations" && data.investigations) state.investigations = data.investigations; if (url === "/api/reports" && data.reports) state.reports = data.reports; if (url === "/api/users" && data.users) state.users = data.users; if (url === "/api/alerts" && data.alerts) state.adminAlerts = data.alerts; return data; }
function orderedIncidents() { return [...state.incidents].sort((a, b) => b.risk_score - a.risk_score); }
function setStatus(label, error = false) { $("liveStatus").textContent = label; $("liveStatus").className = `status ${error ? "error" : "online"}`; }

function showPage(page) {
  const mainSections = [...document.querySelectorAll("main.content > section")];
  mainSections.forEach((section) => section.classList.add("hidden"));
  const overview = state.user?.role === "admin" ? $("adminOverview") : $("overviewDetails");
  const visible = page === "dashboard" ? [$("dashboard"), overview] : [$(page)];
  if (page === "hunts") visible.push(...mainSections.slice(-2));
  visible.filter(Boolean).forEach((section) => section.classList.remove("hidden"));
  document.querySelectorAll(".nav-link[data-page]").forEach((link) => link.classList.toggle("active", link.dataset.page === page));
  const labels = { dashboard: state.user?.role === "admin" ? "Administrator overview" : "Analyst overview", hunts: "Threat hunts", alerts: "Priority alerts", adminAlerts: "Alert oversight", rules: "Rule library", investigations: "Investigations", reports: "Reports", users: "User management" };
  document.querySelector(".topbar h1").textContent = labels[page] || "SentinelOps";
  window.location.hash = page;
}

function configureWorkspace() {
  const admin = state.user.role === "admin";
  $("workspaceLabel").textContent = admin ? "ADMINISTRATION WORKSPACE" : "ANALYST WORKSPACE";
  $("sidebarStatus").innerHTML = admin ? '<span class="live-dot"></span> Manage access and cases' : '<span class="live-dot"></span> Hunt on demand';
  document.querySelectorAll(".analyst-only").forEach((link) => link.classList.toggle("hidden", admin));
  $("refreshBtn").classList.toggle("hidden", admin);
  $("overviewDetails").classList.toggle("hidden", admin);
  if (admin && !$("adminOverview")) {
    const overview = document.createElement("section");
    overview.id = "adminOverview";
    overview.className = "two-col";
    overview.innerHTML = `<section class="panel"><div class="panel-head"><div><h2>Administrator responsibilities</h2><p>Manage access and provide oversight for the investigation workflow.</p></div></div><div class="records"><article class="record"><div><strong>User management</strong><p>Create administrator and analyst accounts. Review active accounts before granting access.</p></div></article><article class="record"><div><strong>Investigation oversight</strong><p>Review every case, its owner, status, false-positive reason, and resolution note.</p></div></article><article class="record"><div><strong>Report administration</strong><p>Review saved alert reports and CSV export history for project documentation.</p></div></article></div></section><section class="panel"><div class="panel-head"><div><h2>Administrator quick guide</h2><p>This account supervises the system; it does not run live hunts.</p></div></div><div class="health"><div><span>1. Manage users</span><i>Add only required accounts and assign the correct role.</i></div><div><span>2. Monitor cases</span><i>Ensure alerts move from Open to Investigating, Resolved, or False Positive.</i></div><div><span>3. Review reports</span><i>Use exports as evidence for the project report and viva demonstration.</i></div></div></section>`;
    document.querySelector("main.content").appendChild(overview);
  }
  if (admin && !$("adminAlerts")) {
    const nav = document.createElement("a");
    nav.className = "nav-link";
    nav.dataset.page = "adminAlerts";
    nav.href = "#adminAlerts";
    nav.textContent = "Alert oversight";
    nav.onclick = (event) => { event.preventDefault(); showPage("adminAlerts"); };
    $("usersNav").insertAdjacentElement("beforebegin", nav);
    const alertPage = document.createElement("section");
    alertPage.id = "adminAlerts";
    alertPage.className = "panel";
    alertPage.innerHTML = '<div class="panel-head"><div><h2>Alert oversight</h2><p>Review persisted alerts and open an investigation when administrator action is needed.</p></div><button id="reloadAlerts">Refresh alerts</button></div><div id="adminAlertsList" class="records"></div>';
    document.querySelector("main.content").appendChild(alertPage);
    $("reloadAlerts").onclick = () => loadAdminAlerts();
  }
  if (admin) loadAdminAlerts();
}

function render() {
  const all = orderedIncidents(); const filter = $("severityFilter").value; const visible = filter === "all" ? all : all.filter((item) => item.severity === filter);
  if (state.user?.role === "admin") {
    const open = state.investigations.filter((item) => ["Open", "Investigating"].includes(item.status));
    $("metricOneLabel").textContent = "Managed investigations"; $("incidentCount").textContent = state.investigations.length; $("metricOneDetail").textContent = "All recorded cases";
    $("metricTwoLabel").textContent = "Open / investigating"; $("highRiskCount").textContent = open.length; $("metricTwoDetail").textContent = "Require case oversight";
    $("metricThreeLabel").textContent = "Active users"; $("processCount").textContent = state.users.filter((item) => item.active).length; $("hostName").textContent = "Administrator-managed accounts";
    $("metricFourLabel").textContent = "Report exports"; $("safeCount").textContent = state.reports.length; $("safeDetail").textContent = "Saved reporting history";
    $("overviewChartTitle").textContent = "Administration guidance"; $("overviewChartText").textContent = "Use Investigations, Reports, and User management to supervise SentinelOps.";
  } else {
    $("metricOneLabel").textContent = "Open alerts"; $("incidentCount").textContent = all.length; $("metricOneDetail").textContent = "Correlated detection signals";
    $("metricTwoLabel").textContent = "Critical / High"; $("highRiskCount").textContent = all.filter((item) => ["critical", "high"].includes(item.severity)).length; $("metricTwoDetail").textContent = "Needs immediate review";
    $("metricThreeLabel").textContent = "Monitored processes"; $("processCount").textContent = state.processes.length;
    $("metricFourLabel").textContent = "Normal processes"; $("safeCount").textContent = state.safeCount; $("safeDetail").textContent = state.hasHunt ? "No risky rule match found" : "No hunt run yet";
    $("overviewChartTitle").textContent = "Risk distribution"; $("overviewChartText").textContent = "Results from the last manual hunt";
  }
  $("alertSummary").textContent = state.hasHunt ? `${visible.length} of ${all.length} correlated signals shown` : "Run a threat hunt to see results.";
  $("alertsList").innerHTML = !state.hasHunt ? '<div class="empty-state">No automatic scan is running. Select Run hunt when you want to inspect the host.</div>' : visible.length ? visible.slice(0, 30).map((item, index) => `<article class="alert ${esc(item.severity)}" data-alert="${index}"><div><span class="badge">${esc(item.severity)} / ${item.risk_score}</span><strong> ${esc(item.title)}</strong><p>${esc(item.explanation)}</p></div><div class="alert-actions"><button class="investigate" data-investigate="${index}">Investigate</button><button data-alert-report="${index}">Create report</button></div></article>`).join("") : '<div class="empty-state">No threat rules matched. The reviewed processes appear safe based on the current rule set.</div>';
  document.querySelectorAll("[data-alert]").forEach((element) => element.onclick = (event) => { if (!event.target.dataset.investigate) showAlert(visible[Number(element.dataset.alert)]); });
  document.querySelectorAll("[data-investigate]").forEach((element) => element.onclick = (event) => { event.stopPropagation(); openInvestigation(visible[Number(element.dataset.investigate)]); });
  document.querySelectorAll("[data-alert-report]").forEach((element) => element.onclick = (event) => { event.stopPropagation(); createAlertReport(visible[Number(element.dataset.alertReport)]); });
  document.querySelectorAll("[data-alert-report]").forEach((element) => {
    element.textContent = "Individual alert report";
    if (!element.parentElement.querySelector(".threat-report")) {
      const threatButton = document.createElement("button");
      threatButton.className = "threat-report";
      threatButton.textContent = "Individual threat report";
      threatButton.onclick = (event) => { event.stopPropagation(); createAlertReport(visible[Number(element.dataset.alertReport)], "Individual Threat"); };
      element.insertAdjacentElement("afterend", threatButton);
    }
  });
  const query = $("processFilter").value.toLowerCase();
  $("processRows").innerHTML = state.processes.filter((item) => `${item.name} ${item.pid} ${item.cmdline}`.toLowerCase().includes(query)).map((item) => `<tr><td><span class="badge">${esc(item.verdict || "normal")}</span><br>${item.risk}/100</td><td><strong>${esc(item.parent_name || "unknown")} → ${esc(item.name)}</strong><div class="cmd">PID ${item.pid} / PPID ${item.ppid} / ${esc(item.username)}</div></td><td>${item.cpu_percent}% / ${item.memory_mb} MB<br><small>${item.remote_count} remote connection(s)</small></td><td>${item.baseline?.samples || 0} samples<br><small>CPU ${Number(item.baseline?.cpu_avg || 0).toFixed(1)}% / ${Number(item.baseline?.memory_avg || 0).toFixed(1)} MB</small></td><td class="cmd">${esc(item.cmdline || item.exe)}<br><small>${esc(item.exe)}</small></td></tr>`).join("");
  $("processTree").innerHTML = state.processes.slice(0, 30).map((item) => `<article class="record"><div><strong>${esc(item.parent_name || "unknown")} → ${esc(item.name)}</strong><p>PID ${item.ppid || "?"} → ${item.pid} / ${esc(item.username)} / risk ${item.risk}/100</p></div></article>`).join("") || '<div class="empty-state">Run a hunt to view process relationships.</div>';
  $("connectionList").innerHTML = state.connections.slice(0, 30).map((item) => `<article class="record"><div><strong>${esc(item.process)} (PID ${item.pid ?? "unknown"})</strong><p>${esc(item.local)} → ${esc(item.remote)} / ${esc(item.status)}</p></div></article>`).join("") || '<div class="empty-state">No accessible remote connections were found.</div>';
  drawChart(all);
}

function drawChart(items) { const canvas = $("riskChart"); const ctx = canvas.getContext("2d"); const labels = ["critical", "high", "medium", "low"]; const colors = ["#fb657d", "#ff8c66", "#f4c65b", "#4f8cff"]; const counts = labels.map((label) => items.filter((item) => item.severity === label).length); const max = Math.max(1, ...counts); ctx.clearRect(0, 0, canvas.width, canvas.height); labels.forEach((label, index) => { const height = 130 * counts[index] / max; const x = 50 + index * 145; ctx.fillStyle = "#1d2b42"; ctx.fillRect(x, 35, 88, 135); ctx.fillStyle = colors[index]; ctx.fillRect(x, 170 - height, 88, height || 3); ctx.fillStyle = "#eaf0fa"; ctx.font = "bold 21px Arial"; ctx.fillText(counts[index], x + 36, 160 - height); ctx.fillStyle = "#95a3b8"; ctx.font = "12px Arial"; ctx.fillText(label.toUpperCase(), x, 195); }); }

async function runHunt() { setStatus("Hunting"); $("huntResult").textContent = "Collecting live process, memory, and connection evidence..."; try { const [status, snapshot] = await Promise.all([api("/api/status"), api("/api/snapshot")]); state.processes = snapshot.processes || []; state.incidents = snapshot.incidents || []; state.connections = snapshot.connections || []; state.safeCount = snapshot.safe_count || 0; state.hasHunt = true; $("hostName").textContent = status.host; $("platformName").textContent = status.platform; $("memoryPercent").textContent = `${status.memory.percent}%`; $("memoryDetail").textContent = `${status.memory.used_gb} GB of ${status.memory.total_gb} GB`; $("diskPercent").textContent = `${status.disk.percent}%`; $("diskDetail").textContent = `${status.disk.used_gb} GB of ${status.disk.total_gb} GB`; $("huntResult").textContent = `Hunt completed: ${state.processes.length} processes reviewed, ${state.incidents.length} threat signals, and ${state.safeCount} safe processes in the displayed result set.`; render(); setStatus("Hunt complete"); } catch (error) { $("huntResult").textContent = error.message; setStatus("Hunt failed", true); } }
function showAlert(item) { $("dialogTitle").textContent = `${item.title} (${item.severity} ${item.risk_score}/100)`; $("dialogBody").innerHTML = `<p><strong>What happened / why it matters</strong><br>${esc(item.explanation)}</p><p><strong>Recommended action</strong><br>${esc(item.recommended_action)}</p><p><strong>Evidence found</strong><br>${(item.evidence || []).map((evidence) => esc(`${evidence.tactic}: ${evidence.title} — ${evidence.detail}`)).join("<br><br>")}</p>`; $("alertDialog").showModal(); }
async function openInvestigation(item) { const notes = prompt("Optional investigation note:"); if (notes === null) return; try { await api("/api/investigations", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_title: item.title, severity: item.severity, alert_id: item.alert_id, notes }) }); await loadInvestigations(); } catch (error) { alert(error.message); } }
async function loadInvestigations() { const data = await api("/api/investigations"); $("investigationsList").innerHTML = data.investigations.length ? data.investigations.map((item) => `<article class="record"><div><strong>${esc(item.alert_title)}</strong> <span class="badge">${esc(item.severity)} / ${esc(item.status)}</span><p>${esc(item.analyst)} / ${new Date(item.created_at).toLocaleString()}${item.notes ? ` / ${esc(item.notes)}` : ""}${item.resolution_note ? ` / Reason: ${esc(item.resolution_note)}` : ""}</p></div><select data-id="${item.id}"><option ${item.status === "Open" ? "selected" : ""}>Open</option><option ${item.status === "Investigating" ? "selected" : ""}>Investigating</option><option ${item.status === "Resolved" ? "selected" : ""}>Resolved</option><option ${item.status === "False Positive" ? "selected" : ""}>False Positive</option></select></article>`).join("") : '<div class="empty-state">No investigations have been opened.</div>'; document.querySelectorAll("#investigationsList select").forEach((select) => select.onchange = async () => { const resolution_note = select.value === "False Positive" ? prompt("Why is this activity legitimate?") : ""; if (resolution_note === null) return loadInvestigations(); try { await api(`/api/investigations/${select.dataset.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: select.value, resolution_note }) }); await loadInvestigations(); } catch (error) { alert(error.message); await loadInvestigations(); } }); }
async function loadReports() { const data = await api("/api/reports"); $("reportsList").innerHTML = data.reports.length ? data.reports.map((item) => `<article class="record"><div><strong>${esc(item.title)}</strong><p>${item.alert_count} alerts / ${esc(item.created_by)} / ${new Date(item.created_at).toLocaleString()}</p></div></article>`).join("") : '<div class="empty-state">Export an alert report to create the first record.</div>'; }
async function createAlertReport(item, reportType = "Individual Alert") { try { await api("/api/alert-reports", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_title: item.title, severity: item.severity, risk_score: item.risk_score, summary: item.explanation, recommended_action: item.recommended_action, report_type: reportType }) }); await loadAlertReports(); alert(`${reportType} report created and saved.`); } catch (error) { alert(error.message); } }
async function loadAlertReports() { const data = await api("/api/alert-reports"); $("alertReportsList").innerHTML = data.reports.length ? data.reports.map((item) => `<article class="record"><div><strong>${esc(item.alert_title)}</strong> <span class="badge">${esc(item.severity)} / ${item.risk_score}</span><p>${esc(item.created_by)} / ${new Date(item.created_at).toLocaleString()}</p><p>${esc(item.recommended_action)}</p></div></article>`).join("") : '<div class="empty-state">Use Create report on any detected alert to save its report here.</div>'; }
async function loadRules() { const data = await api("/api/rules"); $("ruleCount").textContent = `${data.rules.length} rules`; $("rulesList").innerHTML = data.rules.map((rule) => `<article class="record"><div><strong>${esc(rule.rule_id)} - ${esc(rule.name)}</strong> <span class="badge">${esc(rule.severity)}</span><p>${esc(rule.tactic)} / ${esc(rule.confidence)} confidence</p><p>${esc(rule.description)}</p></div></article>`).join(""); }
async function exportReport() { const data = await api("/api/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ incidents: orderedIncidents() }) }); const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([data.csv], { type: "text/csv" })); link.download = "sentinelops-threat-report.csv"; link.click(); await loadReports(); }
async function scanLogs() { const isFile = $("logMode").value === "file"; const url = isFile ? `/api/logs/file?path=${encodeURIComponent($("logPath").value)}` : `/api/logs/windows?channel=${encodeURIComponent($("eventChannel").value)}`; $("logStatus").textContent = "Scanning..."; try { const data = await api(url); state.incidents = [...state.incidents, ...(data.incidents || [])]; state.hasHunt = true; $("logStatus").textContent = `${data.source}: ${data.incidents.length} correlated signals.`; $("logEvents").innerHTML = (data.rows || []).filter((row) => row.risk).slice(0, 20).map((row) => `<article class="record"><div><strong>Event ${esc(row.event_id || "-")} — ${esc(row.event_type)}</strong><p>${esc(row.timestamp)} / ${esc(row.event_source)} / severity indicator: ${row.risk}</p><p>Why it matters: ${esc(row.why_it_matters)}</p></div></article>`).join("") || '<div class="empty-state">No important log events matched the contextual rules.</div>'; render(); } catch (error) { $("logStatus").textContent = error.message; } }
async function loadUsers() { if (state.user.role !== "admin") return; const data = await api("/api/users"); $("usersList").innerHTML = data.users.map((item) => `<article class="record"><div><strong>${esc(item.name)}</strong> <span class="badge">${esc(item.role)}</span><p>${esc(item.email)} / ${item.active ? "Active" : "Inactive"}</p></div>${item.role === "analyst" ? `<button class="investigate" data-delete-user="${item.id}">Delete analyst</button>` : ""}</article>`).join(""); document.querySelectorAll("[data-delete-user]").forEach((button) => button.onclick = async () => { try { await api(`/api/users/${button.dataset.deleteUser}`, { method: "DELETE" }); await loadUsers(); } catch (error) { $("userMessage").textContent = error.message; } }); }
async function loadAdminAlerts() { if (state.user.role !== "admin") return; await api("/api/alerts"); $("adminAlertsList").innerHTML = state.adminAlerts.length ? state.adminAlerts.map((item) => `<article class="record"><div><strong>${esc(item.title)}</strong> <span class="badge">${esc(item.severity)} / ${esc(item.status)}</span><p>Risk ${item.risk_score}/100 / ${esc(item.source)} / ${new Date(item.timestamp).toLocaleString()}</p><p>${esc(item.recommended_action)}</p></div><button class="investigate" data-admin-alert="${item.id}">Investigate alert</button></article>`).join("") : '<div class="empty-state">No stored alerts are available yet. An analyst must run a hunt first.</div>'; document.querySelectorAll("[data-admin-alert]").forEach((button) => button.onclick = async () => { const item = state.adminAlerts.find((alert) => alert.id === Number(button.dataset.adminAlert)); if (item) await openInvestigation({ alert_id: item.id, title: item.title, severity: item.severity }); }); }
async function start() { try { const data = await api("/api/auth/me"); state.user = data.user; $("loginView").classList.add("hidden"); $("appView").classList.remove("hidden"); $("currentUser").textContent = `${state.user.name} / ${state.user.role}`; if (state.user.role === "admin") { $("usersNav").classList.remove("hidden"); await loadUsers(); } await Promise.all([loadInvestigations(), loadReports(), loadAlertReports(), loadRules()]); configureWorkspace(); render(); showPage("dashboard"); } catch {} }
document.querySelectorAll(".role-option").forEach((button) => button.onclick = () => { document.querySelectorAll(".role-option").forEach((item) => item.classList.remove("selected")); button.classList.add("selected"); $("selectedRole").value = button.dataset.role; $("loginError").textContent = ""; });
$("loginForm").onsubmit = async (event) => { event.preventDefault(); try { await api("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: $("email").value, password: $("password").value, role: $("selectedRole").value }) }); location.reload(); } catch (error) { $("loginError").textContent = error.message; } };
$("logoutBtn").onclick = async () => { await api("/api/auth/logout", { method: "POST" }); location.reload(); }; $("refreshBtn").onclick = runHunt; $("huntBtn").onclick = runHunt; $("severityFilter").onchange = render; $("processFilter").oninput = render; $("scanBtn").onclick = scanLogs; $("exportBtn").onclick = () => exportReport().catch((error) => alert(error.message)); $("logMode").onchange = () => { const fileMode = $("logMode").value === "file"; $("logPath").classList.toggle("hidden", !fileMode); $("eventChannel").classList.toggle("hidden", fileMode); }; $("closeDialog").onclick = () => $("alertDialog").close(); $("userForm").onsubmit = async (event) => { event.preventDefault(); try { await api("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("newName").value, email: $("newEmail").value, password: $("newPassword").value, role: $("newRole").value }) }); $("userMessage").textContent = "User added successfully."; event.target.reset(); loadUsers(); } catch (error) { $("userMessage").textContent = error.message; } };
document.querySelectorAll(".nav-link[data-page]").forEach((link) => link.onclick = (event) => { event.preventDefault(); showPage(link.dataset.page); });
const newPassword = $("newPassword");
$("exportBtn").textContent = "Combined report (CSV)";
newPassword.placeholder = "Password";
const passwordToggle = document.createElement("button");
passwordToggle.type = "button";
passwordToggle.className = "password-toggle";
passwordToggle.textContent = "👁";
passwordToggle.title = "Show password";
passwordToggle.setAttribute("aria-label", "Show password");
passwordToggle.onclick = () => {
  const visible = newPassword.type === "text";
  newPassword.type = visible ? "password" : "text";
  passwordToggle.textContent = visible ? "👁" : "◉";
  passwordToggle.title = visible ? "Show password" : "Hide password";
  passwordToggle.setAttribute("aria-label", passwordToggle.title);
};
newPassword.insertAdjacentElement("afterend", passwordToggle);

async function enhancedInvestigations() {
  const data = await api("/api/investigations");
  const admin = state.user.role === "admin";
  $("investigationsList").innerHTML = data.investigations.length ? data.investigations.map((item) => {
    const canEdit = admin || item.analyst_id === null || item.analyst_id === state.user.id;
    return `<article class="record" data-case="${item.id}"><div><strong>${esc(item.alert_title)}</strong> <span class="badge">${esc(item.severity)} / ${esc(item.status)}</span><p>Assigned analyst: ${esc(item.analyst)} / ${new Date(item.created_at).toLocaleString()}</p><label class="muted">Analyst note for administrator<textarea data-analyst-note ${canEdit && !admin ? "" : "readonly"}>${esc(item.analyst_note || item.notes || "")}</textarea></label><label class="muted">Administrator response<textarea data-admin-note ${admin ? "" : "readonly"}>${esc(item.admin_note || "")}</textarea></label>${item.resolution_note ? `<p>Resolution / false-positive reason: ${esc(item.resolution_note)}</p>` : ""}</div><div class="alert-actions"><select data-case-status ${canEdit ? "" : "disabled"}><option ${item.status === "Open" ? "selected" : ""}>Open</option><option ${item.status === "Investigating" ? "selected" : ""}>Investigating</option><option ${item.status === "Resolved" ? "selected" : ""}>Resolved</option><option ${item.status === "False Positive" ? "selected" : ""}>False Positive</option></select>${canEdit ? '<button data-save-case>Save update</button>' : '<span class="muted">Assigned to another analyst</span>'}</div></article>`;
  }).join("") : '<div class="empty-state">No investigations have been opened.</div>';
  document.querySelectorAll("[data-save-case]").forEach((button) => button.onclick = async () => {
    const card = button.closest("[data-case]"); const status = card.querySelector("[data-case-status]").value;
    let resolution_note = "";
    if (status === "False Positive") { resolution_note = prompt("Why is this activity legitimate?") || ""; if (!resolution_note) return; }
    try {
      await api(`/api/investigations/${card.dataset.case}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, resolution_note, analyst_note: card.querySelector("[data-analyst-note]").value, admin_note: card.querySelector("[data-admin-note]").value }) });
      await enhancedInvestigations(); if (admin) await loadAdminAlerts();
    } catch (error) { alert(error.message); }
  });
}
loadInvestigations = enhancedInvestigations;
async function enhancedAlertReports() {
  const data = await api("/api/alert-reports");
  $("alertReportsList").innerHTML = data.reports.length ? data.reports.map((item) => `<article class="record"><div><strong>${esc(item.alert_title)}</strong> <span class="badge">${esc(item.report_type || "Individual Alert")}</span><p>${esc(item.severity)} / risk ${item.risk_score}/100 / ${esc(item.created_by)} / ${new Date(item.created_at).toLocaleString()}</p><p>${esc(item.recommended_action)}</p></div></article>`).join("") : '<div class="empty-state">Create an individual threat or alert report from a detected item.</div>';
}
loadAlertReports = enhancedAlertReports;
async function enhancedAdminAlerts() {
  if (state.user.role !== "admin") return;
  await api("/api/alerts");
  $("adminAlertsList").innerHTML = state.adminAlerts.length ? state.adminAlerts.map((item) => `<article class="record"><div><strong>${esc(item.title)}</strong> <span class="badge">${esc(item.severity)} / ${esc(item.status)}</span><p>Risk ${item.risk_score}/100 / ${esc(item.source)} / ${new Date(item.timestamp).toLocaleString()}</p><p>${esc(item.recommended_action)}</p></div><div class="alert-actions"><button class="investigate" data-admin-alert="${item.id}">Investigate alert</button><button data-admin-alert-report="${item.id}">Individual alert report</button><button data-admin-threat-report="${item.id}">Individual threat report</button></div></article>`).join("") : '<div class="empty-state">No stored alerts are available yet. An analyst must run a hunt first.</div>';
  document.querySelectorAll("[data-admin-alert]").forEach((button) => button.onclick = async () => { const item = state.adminAlerts.find((alert) => alert.id === Number(button.dataset.adminAlert)); if (item) await openInvestigation({ alert_id: item.id, title: item.title, severity: item.severity }); });
  document.querySelectorAll("[data-admin-alert-report]").forEach((button) => button.onclick = () => { const item = state.adminAlerts.find((alert) => alert.id === Number(button.dataset.adminAlertReport)); if (item) createAlertReport(item, "Individual Alert"); });
  document.querySelectorAll("[data-admin-threat-report]").forEach((button) => button.onclick = () => { const item = state.adminAlerts.find((alert) => alert.id === Number(button.dataset.adminThreatReport)); if (item) createAlertReport(item, "Individual Threat"); });
}
loadAdminAlerts = enhancedAdminAlerts;
start();
