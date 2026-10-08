const dashText = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = value ?? "-"; };
const dashEsc = (value) => String(value ?? "-").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));
const dashTime = (value) => value ? new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-";
const dashMetric = (value, suffix = "") => value == null ? "Data unavailable" : `${value}${suffix}`;

function setupDashboardTabs() {
  document.querySelectorAll("[data-dashboard-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.dashboardTab;
      document.querySelectorAll("[data-dashboard-tab]").forEach((item) => {
        const active = item === button;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", active ? "true" : "false");
      });
      document.querySelectorAll(".dashboard-tab-panel").forEach((panel) => {
        const active = panel.id === target;
        panel.classList.toggle("active", active);
        panel.hidden = !active;
      });
    });
  });
}

const agentDescriptions = {
  "Monitoring Agent": "CloudWatch metrics and EC2 health",
  "Threat Detection Agent": "Suspicious activity and Isolation Forest",
  "Recovery Assessment Agent": "Trust score and safety gate",
  "Recovery Point Selection Agent": "Safest eligible recovery point",
  "Recovery Execution Agent": "Authorization-controlled recovery",
  "Recovery Verification Agent": "Post-recovery health validation"
};

function renderAgents(agents) {
  const node = document.getElementById("agent_cards");
  if (!node) return;
  node.innerHTML = (agents.activities || []).map((agent) => `
    <article class="agent-card"><div class="agent-card-top"><span class="agent-status">${dashEsc(agent.status)}</span><span>${dashTime(agent.timestamp)}</span></div>
      <h3>${dashEsc(agent.agent_name)}</h3><p>${dashEsc(agentDescriptions[agent.agent_name] || "Evidence-backed workflow stage")}</p>
      <strong>${dashEsc(agent.action)}</strong><small>Confidence: ${agent.confidence == null ? "Data unavailable" : `${agent.confidence}%`}</small><em>${dashEsc(agent.decision)}</em>
    </article>`).join("");
}

function renderPipeline(stages) {
  const node = document.getElementById("decision_pipeline");
  if (!node) return;
  node.innerHTML = (stages || []).map((stage, index) => `<article class="pipeline-stage"><span class="pipeline-number">${index + 1}</span><div><small>${dashEsc(stage.state)} | ${dashTime(stage.timestamp)}</small><h3>${dashEsc(stage.stage)}</h3><p><b>INPUT</b> ${dashEsc(stage.input)}</p><p><b>DECISION</b> ${dashEsc(stage.decision)}</p><p><b>REASON</b> ${dashEsc(stage.reason)}</p></div></article>`).join("");
}

function renderTable(id, rows, columns) {
  const node = document.getElementById(id);
  if (!node) return;
  node.innerHTML = `<thead><tr>${columns.map((column) => `<th>${dashEsc(column.label)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((row) => `<tr>${columns.map((column) => `<td>${dashEsc(column.value(row))}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${columns.length}">No assessment records available.</td></tr>`}</tbody>`;
}

function renderChart(id, title, rows, field) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const width = canvas.clientWidth || 360;
  const height = canvas.clientHeight || 180;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = width * ratio; canvas.height = height * ratio;
  const context = canvas.getContext("2d"); context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height); context.fillStyle = "#91a9b2"; context.font = "12px Segoe UI"; context.fillText(title, 14, 18);
  const points = [...(rows || [])].reverse().filter((row) => row[field] != null);
  if (!points.length) { context.fillText("Data unavailable", 14, height / 2); return; }
  const values = points.map((row) => Number(row[field]) || 0); const max = Math.max(100, ...values); const pad = 24;
  context.strokeStyle = "#57f0ff"; context.lineWidth = 2; context.beginPath();
  values.forEach((value, index) => { const x = pad + (width - pad * 2) * index / Math.max(1, values.length - 1); const y = height - pad - (value / max) * (height - pad * 2); index ? context.lineTo(x, y) : context.moveTo(x, y); });
  context.stroke();
}

function renderDashboard(data) {
  const live = data.live || {};
  const agents = data.agents || {};
  const cloudwatch = live.cloudwatch || {};
  const system = live.system || {};
  const telemetry = live.telemetry || {};
  const systemSource = cloudwatch.status === "CONNECTED" ? cloudwatch : telemetry;
  const anomaly = live.anomaly || {};
  const selected = agents.selected || {};
  dashText("command_updated", `Last evidence update: ${dashTime(live.updated_at)}`);
  dashText("command_security_state", live.security_state);
  dashText("command_system_status", `${live.system_status} | Risk ${Number(live.risk_score || 0).toFixed(1)}`);
  dashText("dash_cloudwatch", cloudwatch.status || "Data unavailable");
  dashText("dash_weather", dashMetric(live.weather?.weather_risk_score, "/100"));
  dashText("dash_health", dashMetric(cloudwatch.status === "CONNECTED" ? cloudwatch.application_health : system.system_health ?? live.system_status));
  dashText("dash_cpu", dashMetric(systemSource.cpu, "%"));
  dashText("dash_memory", dashMetric(systemSource.memory ?? systemSource.ram, "%"));
  dashText("dash_disk", dashMetric(systemSource.disk, "%"));
  dashText("dash_network", dashMetric(systemSource.network_in ?? systemSource.network_activity, " bytes/s"));
  dashText("dash_anomalies", anomaly.classification === "WARMING_UP" ? "WARMING_UP" : `${live.anomaly_count ?? 0} (${anomaly.classification || "UNKNOWN"})`);
  dashText("dash_alarm", live.alarm?.active ? `${live.alarm.severity} ALARM` : "CLEAR");
  dashText("dash_backup", live.backup?.backup_id || "No recovery point");
  dashText("dash_safety_score", agents.safety_score == null ? "-" : `${agents.safety_score}/100`);
  dashText("dash_safety_label", agents.safety_label);
  dashText("dash_formula", agents.formula);
  const robust = data.robust_decision || {};
  dashText("robust_decision_label", robust.decision || "Waiting for decision");
  dashText("robust_authority", robust.authority || "-");
  dashText("robust_confidence", robust.confidence == null ? "-" : `${robust.confidence}%`);
  dashText("robust_readiness", robust.recovery_readiness?.score == null ? "-" : `${robust.recovery_readiness.score}/100`);
  dashText("robust_agent", robust.selected_recovery_agent || "None");
  dashText("robust_point", robust.selected_recovery_point || "None");
  dashText("robust_id", robust.decision_id || "-");
  dashText("robust_reason", robust.reason || "No robust decision generated.");
  const trustList = document.getElementById("robust_agents");
  if (trustList) trustList.innerHTML = Object.entries(robust.agent_trust || {}).map(([name, item]) => `<div><span>${dashEsc(name)}</span><strong>${dashEsc(item.score)} ${dashEsc(item.state)}</strong><small>${dashEsc(item.authority)}</small></div>`).join("");
  renderAgents(agents);
  renderPipeline(agents.pipeline);
  renderTable("trust_points_table", agents.recovery_points || [], [
    { label: "Recovery Point", value: row => row.recovery_point }, { label: "Timestamp", value: row => dashTime(row.timestamp) },
    { label: "Integrity", value: row => `${row.backup_integrity}%` }, { label: "Threat", value: row => row.threat_score },
    { label: "Anomaly", value: row => row.anomaly_score }, { label: "Trust", value: row => row.recovery_safety_score },
    { label: "Status", value: row => row.status }, { label: "Decision", value: row => row.decision }
  ]);
  renderTable("assessment_history_table", agents.history || [], [
    { label: "Recovery ID", value: row => row.recovery_id }, { label: "Point", value: row => row.recovery_point },
    { label: "Safety", value: row => row.recovery_safety_score }, { label: "Decision", value: row => row.agent_decision },
    { label: "Timestamp", value: row => dashTime(row.timestamp) }
  ]);
  renderChart("dash_cpu_chart", "CPU utilization", agents.telemetry_history, "cpu");
  renderChart("dash_anomaly_chart", "Anomaly score", agents.anomaly_history, "anomaly_score");
  renderChart("dash_safety_chart", "Recovery safety score", agents.safety_history, "recovery_safety_score");
  const timeline = document.getElementById("agent_timeline");
  if (timeline) timeline.innerHTML = (agents.activity_timeline || []).length ? agents.activity_timeline.map((item) => `<li><time>${dashTime(item.timestamp)}</time><strong>${dashEsc(item.agent_name)}</strong><span>${dashEsc(item.action)} | ${dashEsc(item.decision)}</span></li>`).join("") : "<li>No agent activity recorded.</li>";
}

async function refreshCommandCenter() {
  try {
    const response = await fetch("/api/dashboard/live", { cache: "no-store" });
    const data = await response.json();
    if (data.ok) renderDashboard(data);
  } catch (error) {
    dashText("command_updated", "Live command-center data unavailable");
  }
}

setupDashboardTabs();
refreshCommandCenter();
window.setInterval(refreshCommandCenter, 8000);