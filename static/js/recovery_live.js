const recoveryStages = [
  "MONITORING", "RISK_DETECTED", "COMPROMISED", "BACKUP_IN_PROGRESS", "BACKUP_COMPLETE",
  "ASSESSING_RECOVERY", "SAFE_POINT_SELECTED", "RECOVERY_AUTHORIZATION_REQUIRED",
  "RECOVERY_IN_PROGRESS", "RECOVERY_COMPLETE", "RECOVERY_FAILED"
];

const liveText = (id, value) => {
  const node = document.getElementById(id);
  if (node) node.textContent = value ?? "-";
};

const formatTime = (value) => value ? new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--:--";
const metricValue = (value, suffix = "") => value == null ? "-" : `${value}${suffix}`;

function renderLive(data) {
  const system = data.system || {};
  const cyber = data.cyber || {};
  const cloudwatch = data.cloudwatch || {};
  liveText("risk_score", Number(data.risk_score || 0).toFixed(1));
  liveText("risk_level", data.risk_level);
  liveText("security_state", data.security_state);
  liveText("ai_decision", data.ai_decision);
  liveText("system_status", data.system_status);
  liveText("system_health", `CPU ${system.cpu ?? "-"}% | RAM ${system.ram ?? "-"}% | Disk ${system.disk ?? "-"}%`);
  liveText("anomaly_count", data.anomaly_count ?? 0);
  liveText("cyber_status", `${cyber.model || "Isolation Forest"}: ${cyber.status || "NOT_RUN"}`);
  liveText("backup_status", data.backup?.status || "NONE");
  liveText("backup_id", data.backup?.backup_id || "No backup recorded");
  liveText("recovery_state", data.recovery_state);
  liveText("cpu", `${system.cpu ?? "-"}%`);
  liveText("ram", `${system.ram ?? "-"}%`);
  liveText("disk", `${system.disk ?? "-"}%`);
  liveText("network", `${system.network_activity ?? "-"} bytes/s`);
  liveText("live_updated", `Last telemetry: ${formatTime(data.updated_at)}`);
  liveText("cloudwatch_status", cloudwatch.status || "DISABLED");
  liveText("cloudwatch_timestamp", cloudwatch.latest_timestamp ? formatTime(cloudwatch.latest_timestamp) : "No CloudWatch data");
  liveText("cloudwatch_cpu", metricValue(cloudwatch.cpu, "%"));
  liveText("cloudwatch_memory", metricValue(cloudwatch.memory, "%"));
  liveText("cloudwatch_disk", metricValue(cloudwatch.disk, "%"));
  liveText("cloudwatch_network", metricValue(cloudwatch.network, " bytes/s"));
  liveText("cloudwatch_health", metricValue(cloudwatch.application_health));
  liveText("cloudwatch_alarm", cloudwatch.alarm_status || "NOT_CONFIGURED");

  const summary = document.getElementById("threat_summary");
  if (summary) summary.textContent = `${cyber.records_analyzed || 0} records analyzed, ${data.anomaly_count || 0} anomalies detected by ${cyber.model || "Isolation Forest"}.`;
  const latest = data.event;
  const eventNode = document.getElementById("latest_event");
  if (eventNode && latest) eventNode.textContent = `SECURITY EVENT DETECTED | ${latest.event_id} | ${latest.security_state} | Risk ${latest.risk_score} | Anomalies ${latest.anomaly_count}`;

  const pipeline = document.getElementById("pipeline");
  if (pipeline) pipeline.innerHTML = recoveryStages.map((stage) => `<span class="${stage === data.recovery_state ? "active" : ""}">${stage.replaceAll("_", " ")}</span>`).join("");
  const timeline = document.getElementById("event_timeline");
  if (timeline) timeline.innerHTML = (data.events || []).length
    ? data.events.map((event) => `<li><time>${formatTime(event.timestamp)}</time><strong>${event.security_state || event.event_type}</strong><span>Risk ${event.risk_score} | ${event.anomaly_count} anomalies | ${event.ai_decision || "-"}</span></li>`).join("")
    : "<li>Waiting for recorded events.</li>";
}

async function refreshLive() {
  try {
    const response = await fetch("/api/recovery/live", { cache: "no-store" });
    const data = await response.json();
    if (data.ok) renderLive(data);
  } catch (error) {
    liveText("live_updated", "Telemetry connection unavailable");
  }
}

refreshLive();
window.setInterval(refreshLive, 5000);