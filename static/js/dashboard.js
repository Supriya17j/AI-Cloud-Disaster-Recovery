const $ = (id) => document.getElementById(id);

async function act(path, body) {
  const response = await fetch(`/api/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  const data = await response.json();
  const msg = $("msg");
  if (msg) {
    msg.className = `notice compact ${data.ok === false ? "warning" : "success"}`;
    msg.textContent = data.message || "Action complete.";
  }
  refresh();
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function setText(selector, value) {
  document.querySelectorAll(selector).forEach((node) => {
    node.textContent = value ?? "-";
  });
}

function firstMatch(lines, pattern) {
  const line = (lines || []).find((item) => pattern.test(item));
  return line || "";
}

function classifyStatus(text) {
  const value = String(text || "").toLowerCase();
  if (value.includes("failed") || value.includes("exceeded") || value.includes("after") || value.includes("reject") || value.includes("blocked")) return "fail";
  if (value.includes("during") || value.includes("suspicious") || value.includes("partial") || value.includes("approval") || value.includes("risky")) return "warning";
  if (value.includes("ok") || value.includes("clean") || value.includes("before") || value.includes("successful") || value.includes("ready") || value.includes("healthy")) return "pass";
  return "warning";
}

function statusWord(status) {
  return status === "pass" ? "PASS" : status === "fail" ? "FAIL" : "WARNING";
}

function parseNumber(text, pattern) {
  const match = String(text || "").match(pattern);
  return match ? Number(match[1]) : null;
}

function table(id, rows, cols) {
  const node = $(id);
  if (!node) return;
  const head = `<thead><tr>${cols.map((col) => `<th>${esc(col)}</th>`).join("")}</tr></thead>`;
  const body = rows.length
    ? rows.map((row) => `<tr>${cols.map((col) => `<td>${esc(row[col])}</td>`).join("")}</tr>`).join("")
    : `<tr><td colspan="${cols.length}">No records yet.</td></tr>`;
  node.innerHTML = `${head}<tbody>${body}</tbody>`;
}

function drawChart(id, title, rows) {
  const canvas = $(id);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  canvas.width = Math.max(1, Math.floor(width * ratio));
  canvas.height = Math.max(1, Math.floor(height * ratio));
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const pad = 30;
  ctx.strokeStyle = "rgba(145, 169, 178, 0.18)";
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i += 1) {
    const y = pad + ((height - pad * 2) * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(width - pad, y);
    ctx.stroke();
  }

  ctx.fillStyle = "#91a9b2";
  ctx.font = "12px Segoe UI, Arial";
  ctx.fillText(title, pad, 18);

  if (!rows.length) {
    ctx.fillText("No data yet", pad, height / 2);
    return;
  }

  const values = rows.map((row) => Number(row.score) || 0);
  const max = Math.max(100, ...values);
  const min = Math.min(0, ...values);
  const span = max - min || 1;
  const points = values.map((value, index) => {
    const x = pad + ((width - pad * 2) * index) / Math.max(1, values.length - 1);
    const y = height - pad - ((value - min) / span) * (height - pad * 2);
    return [x, y];
  });

  const gradient = ctx.createLinearGradient(0, pad, 0, height - pad);
  gradient.addColorStop(0, "rgba(87, 240, 255, 0.34)");
  gradient.addColorStop(1, "rgba(87, 240, 255, 0)");

  ctx.beginPath();
  points.forEach(([x, y], index) => index ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
  ctx.lineTo(points[points.length - 1][0], height - pad);
  ctx.lineTo(points[0][0], height - pad);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.beginPath();
  points.forEach(([x, y], index) => index ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
  ctx.strokeStyle = "#57f0ff";
  ctx.lineWidth = 2.5;
  ctx.stroke();

  points.forEach(([x, y]) => {
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = "#74f59a";
    ctx.fill();
  });
}

function renderGate(gate) {
  const node = $("gate");
  if (!node) return;
  if (!gate || !gate.decision) {
    node.innerHTML = "Run an assessment.";
    return;
  }
  node.innerHTML = `
    <h4 class="decision-title">${esc(gate.decision)}</h4>
    <p class="gate-meta">Recommended: <strong>${esc(gate.recommended || "none")}</strong> | Readiness: <strong>${esc(gate.readiness)}</strong></p>
    <ul class="reason-list">${(gate.reasons || []).map((reason) => `<li>${esc(reason)}</li>`).join("")}</ul>
  `;
}

function statusFromState(state) {
  const disaster = state.cards["Disaster Status"];
  const anomaly = state.latest_risk?.anomaly || "-";
  if (disaster && disaster !== "None") return "Attention required";
  if (state.gate?.decision === "SAFE TO RECOVER") return "Ready";
  if (anomaly === "anomalous") return "Anomaly under review";
  return "Operational";
}

function renderCommon(state) {
  Object.entries(state.cards || {}).forEach(([key, value]) => {
    setText(`[data-card="${key}"]`, value);
  });

  const metric = state.latest_metric || {};
  ["cpu", "ram", "disk"].forEach((key) => setText(`[data-metric="${key}"]`, metric[key] != null ? `${metric[key]}%` : "-"));
  ["failed_logins", "suspicious"].forEach((key) => setText(`[data-metric="${key}"]`, metric[key] ?? "-"));

  const risk = state.latest_risk || {};
  ["anomaly", "decision"].forEach((key) => setText(`[data-risk="${key}"]`, risk[key] || "-"));
  const live = state.live || {};
  const anomaly = live.anomaly || {};
  setText('[data-field="anomaly_score"]', anomaly.anomaly_score == null ? "WARMING_UP" : `${anomaly.anomaly_score}/100`);
  setText('[data-field="baseline_size"]', anomaly.baseline_size ?? "-" );
  setText('[data-field="anomaly_explanation"]', anomaly.explanation || "Waiting for a valid model result.");

  const event = state.latest_event || {};
  ["type", "ts"].forEach((key) => setText(`[data-event="${key}"]`, event[key] || "-"));
  setText('[data-event="type"]', anomaly.classification || event.type || "WARMING_UP");
  setText('[data-event="ts"]', anomaly.timestamp || event.ts || "Data unavailable");

  const external = (state.events || []).find((item) => item.category === "external");
  setText('[data-field="external_event"]', external ? external.type : "-");
  setText('[data-field="threat_status"]', risk.anomaly ? `${risk.anomaly} / ${state.cards["Disaster Status"]}` : "-");
  setText('[data-field="overall_status"]', statusFromState(state));
  setText('[data-field="detection_status"]', anomaly.classification || "WARMING_UP");
  setText('[data-field="detection_confidence"]', anomaly.confidence == null ? "Data unavailable" : `${anomaly.confidence}%`);
  setText('[data-field="dependency_status"]', state.cards["Disaster Status"]?.includes("dependency") ? "Blocked" : "Ready");
  setText('[data-field="environment_status"]', state.cards["Disaster Status"]?.includes("environment") ? "Blocked" : "Ready");
  setText('[data-field="validation_status"]', state.recoveries?.[0]?.status || "-");
  setText('[data-field="final_recovery_status"]', state.recoveries?.[0]?.status || state.cards["Recovery Decision"] || "-");
  setText('[data-field="rto_target"]', state.targets?.rto_s != null ? `${state.targets.rto_s}s` : "-");
  setText('[data-field="rpo_target"]', state.targets?.rpo_min != null ? `${state.targets.rpo_min} min` : "-");

  renderGate(state.gate);
}

function renderLists(state) {
  const reasonsNode = $("risk_reasons");
  if (reasonsNode) {
    const reasons = state.risk_reasons || [];
    reasonsNode.innerHTML = reasons.length
      ? reasons.map((reason) => `<li>${esc(reason)}</li>`).join("")
      : "<li>No risk analysis has been recorded yet.</li>";
  }

  const indicatorsNode = $("detected_indicators");
  if (indicatorsNode) {
    const indicators = [];
    if (state.latest_risk?.anomaly) indicators.push(`Metric behavior: ${state.latest_risk.anomaly}`);
    if (state.live?.anomaly?.feature_deviations?.length) {
      state.live.anomaly.feature_deviations.forEach((item) => indicators.push(`${item.feature}: current ${item.current}, baseline ${item.baseline} (${item.level} deviation)`));
    }
    if (state.latest_event?.type) indicators.push(`Latest event: ${state.latest_event.type} (${state.latest_event.severity})`);
    (state.risk_reasons || []).slice(0, 4).forEach((reason) => indicators.push(reason));
    indicatorsNode.innerHTML = indicators.length
      ? indicators.map((item) => `<li>${esc(item)}</li>`).join("")
      : "<li>No detection evidence has been recorded yet.</li>";
  }

  const validationNode = $("validation_checks");
  if (validationNode) {
    const latest = state.recoveries?.[0];
    const assessment = state.latest_assessment;
    validationNode.innerHTML = [
      `Dependency validation: ${state.cards["Disaster Status"]?.includes("dependency") ? "blocked" : "ready"}`,
      `Integrity validation: ${assessment?.hard_failure === "REJECT RECOVERY POINT" ? "failed" : assessment ? "passed or not blocked" : "pending"}`,
      `Recovery validation result: ${latest?.status || "pending recovery execution"}`
    ].map((item) => `<li>${esc(item)}</li>`).join("");
  }
}

function renderTables(state) {
  table("t_asm", (state.assessment || []).map((item) => ({
    backup: item.backup_id,
    readiness: item.readiness,
    class: item.classification,
    hard_failure: item.hard_failure || "-",
    evidence: item.details.slice(0, 3).join(" | ")
  })), ["backup", "readiness", "class", "hard_failure", "evidence"]);

  table("t_points", (state.recovery_points || []).map((item) => ({
    backup: item.backup_id,
    timestamp: item.created_at,
    integrity: item.status || "-",
    attack_timeline: "Run assessment",
    suspicious: item.suspicious,
    risk_score: item.risk_score,
    storage: item.storage || "-"
  })), ["backup", "timestamp", "integrity", "attack_timeline", "suspicious", "risk_score", "storage"]);

  table("t_b", state.backups || [], ["backup_id", "created_at", "risk_score", "storage", "status"]);
  table("t_r", state.recoveries || [], ["ts", "backup_id", "rto_s", "rpo_min", "status"]);
  table("t_e", state.events || [], ["ts", "category", "type", "severity", "detail"]);
}

function renderRecoveryResults(state) {
  if (!document.body.matches('[data-page="results"]')) return;

  const gate = state.gate || {};
  const authoritative = state.decision || {};
  const selected = state.selected_assessment || {};
  const backup = state.selected_backup || {};
  const details = selected.details || [];
  const latestRecovery = state.recoveries?.[0] || {};
  const score = Number(authoritative.safety_score ?? gate.readiness ?? selected.readiness ?? 0) || 0;
  const decision = authoritative.gate_decision || gate.decision || "NO SAFE RECOVERY POINT";
  const disasters = state.active_disasters || [];

  setText("#result_status_title", decision);
  setText('[data-result="status_badge"]', decision);
  setText('[data-result="assessment_ts"]', selected.ts || "-");
  setText('[data-result="disaster_type"]', disasters.length ? disasters.map((item) => item.type).join(", ") : state.cards["Disaster Status"]);
  setText('[data-result="assessment_id"]', selected.id ? `ASM-${selected.id}` : "-");
  setText('[data-result="score_classification"]', selected.classification || decision);
  setText('[data-result="selected_backup_id"]', authoritative.selected_recovery_point || "-");
  setText('[data-result="selected_backup_ts"]', authoritative.selected_recovery_point ? (backup.created_at || selected.ts || "-") : "-");
  setText('[data-result="selected_suspicious"]', authoritative.selected_recovery_point ? "Review assessment evidence" : "No point selected");
  setText('[data-result="selected_rpo"]', latestRecovery.rpo_min != null ? `${latestRecovery.rpo_min} min` : "-");

  const statusBadge = document.querySelector(".status-badge-large");
  if (statusBadge) {
    statusBadge.classList.toggle("fail", /BLOCKED|NO SAFE|REJECT/.test(decision));
    statusBadge.classList.toggle("warn", /APPROVAL|EARLIER/.test(decision));
  }

  const gauge = $("readiness_gauge");
  if (gauge) gauge.style.setProperty("--score", Math.max(0, Math.min(100, score)));

  const integrity = firstMatch(details, /^Integrity:/i);
  const attack = firstMatch(details, /^Attack phase:/i);
  const rpo = firstMatch(details, /^RPO:/i);
  const rto = firstMatch(details, /^RTO:/i);
  const deps = firstMatch(details, /^Dependencies:/i);
  const env = firstMatch(details, /^Environment:/i);
  const cyber = firstMatch(details, /^Predicted condition:/i) || attack;

  setText('[data-result="selected_integrity"]', integrity ? statusWord(classifyStatus(integrity)) : "-");
  setText('[data-result="selected_attack_phase"]', attack ? attack.replace(/^Attack phase:\s*/i, "") : "-");

  renderAssessmentFactors([
    ["Backup Integrity", integrity],
    ["Attack Timeline", attack],
    ["Cyber Safety", cyber],
    ["Dependency Readiness", deps],
    ["Recovery Environment", env],
    ["RTO Compatibility", rto],
    ["RPO Compatibility", rpo]
  ]);

  const rtoTarget = Number(state.targets?.rto_s);
  const rpoTarget = Number(state.targets?.rpo_min);
  const estimatedRto = latestRecovery.rto_s != null ? Number(latestRecovery.rto_s) : parseNumber(rto, /estimated\s+([\d.]+)s/i);
  const actualRpo = latestRecovery.rpo_min != null ? Number(latestRecovery.rpo_min) : parseNumber(rpo, /backup age\s+([\d.]+)\s+min/i);

  setText('[data-result="rto_actual"]', estimatedRto != null ? `${estimatedRto}s` : "-");
  setText('[data-result="rpo_actual"]', actualRpo != null ? `${actualRpo} min` : "-");
  setText('[data-result="rto_status"]', estimatedRto != null && rtoTarget ? (estimatedRto <= rtoTarget ? "WITHIN TARGET" : "OUTSIDE TARGET") : "-");
  setText('[data-result="rpo_status"]', actualRpo != null && rpoTarget ? (actualRpo <= rpoTarget ? "WITHIN TARGET" : "OUTSIDE TARGET") : "-");
  setText('[data-result="rto_difference"]', estimatedRto != null && rtoTarget ? `${Math.round((rtoTarget - estimatedRto) * 10) / 10}s` : "-");
  setText('[data-result="rpo_difference"]', actualRpo != null && rpoTarget ? `${Math.round((rpoTarget - actualRpo) * 10) / 10} min` : "-");

  const reasonsNode = $("result_reasons");
  if (reasonsNode) {
    const reasons = gate.reasons?.length ? gate.reasons : details;
    reasonsNode.innerHTML = reasons?.length
      ? reasons.map((reason) => `<li>${esc(reason)}</li>`).join("")
      : "<li>Run a readiness assessment to generate decision reasons.</li>";
  }

  renderResultAction(decision);
  renderComparisonTable(state);
}

function renderAssessmentFactors(factors) {
  const node = $("assessment_factors");
  if (!node) return;
  node.innerHTML = factors.map(([title, detail]) => {
    const status = classifyStatus(detail);
    return `
      <article class="factor-card ${status === "warning" ? "warning" : status === "fail" ? "fail" : ""}">
        <span>${esc(title)}</span>
        <strong>${esc(statusWord(status))}</strong>
        <p>${esc(detail || "Assessment evidence is not available yet.")}</p>
      </article>
    `;
  }).join("");
}

function renderResultAction(decision) {
  const button = $("result_action_button");
  if (!button) return;
  const note = document.querySelector('[data-result="action_note"]');
  button.disabled = true;
  button.className = "blocked-action";
  if (decision === "SAFE TO RECOVER") {
    button.textContent = "START RECOVERY";
    button.disabled = false;
    button.className = "success";
    if (note) note.textContent = "Recovery can proceed because no hard safety gate is blocking the selected point.";
  } else if (decision === "RECOVER WITH HUMAN APPROVAL" || decision === "USE EARLIER RECOVERY POINT") {
    button.textContent = "REQUEST APPROVAL";
    button.disabled = false;
    button.className = "approval-action";
    if (note) note.textContent = "Operator approval is required before recovery execution.";
  } else if (decision === "NO SAFE RECOVERY POINT AVAILABLE") {
    button.textContent = "NO SAFE RECOVERY AVAILABLE";
    if (note) note.textContent = "No recovery point passed the mandatory safety checks.";
  } else {
    button.textContent = "RECOVERY BLOCKED";
    if (note) note.textContent = "Recovery is blocked by the latest decision or a hard safety check.";
  }
}

function renderComparisonTable(state) {
  const assessments = state.assessment || [];
  const rows = (state.recovery_points || []).map((point) => {
    const assessment = assessments.find((item) => item.backup_id === point.backup_id);
    const details = assessment?.details || [];
    const integrity = firstMatch(details, /^Integrity:/i);
    const attack = firstMatch(details, /^Attack phase:/i);
    const deps = firstMatch(details, /^Dependencies:/i);
      const selected = point.backup_id === state.decision?.selected_recovery_point;
    return {
      recovery_point: point.backup_id,
      timestamp: point.created_at,
      integrity: integrity ? statusWord(classifyStatus(integrity)) : point.status || "-",
      attack_window: attack ? attack.replace(/^Attack phase:\s*/i, "") : "Run assessment",
      suspicious_activity: Number(point.suspicious || 0) > 0 ? "REVIEW" : "CLEAN",
      dependency_status: deps ? statusWord(classifyStatus(deps)) : "-",
      readiness_score: assessment?.readiness ?? "-",
      decision: selected ? "SELECTED" : assessment?.hard_failure || assessment?.classification || "-"
    };
  });
  table("t_results_compare", rows, ["recovery_point", "timestamp", "integrity", "attack_window", "suspicious_activity", "dependency_status", "readiness_score", "decision"]);
}

function renderCharts(state) {
  drawChart("c1", "Risk score", state.risk_trend || []);
  drawChart("c2", "Risk at backup", state.backup_timeline || []);
  drawChart("c3", "Readiness score", state.readiness_trend || []);
}

async function refresh() {
  const state = await (await fetch("/api/state")).json();
  renderCommon(state);
  renderLists(state);
  renderTables(state);
  renderRecoveryResults(state);
  renderCharts(state);
}

window.addEventListener("resize", refresh);
refresh();
setInterval(refresh, 15000);
