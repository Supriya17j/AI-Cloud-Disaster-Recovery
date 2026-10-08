(() => {
  const selectors = {
    overall: document.querySelector('[data-risk="overall"]'),
    severity: document.querySelector('[data-risk="severity"]'),
    weatherScore: document.querySelector('[data-risk="weather_score"]'),
    cyberScore: document.querySelector('[data-risk="cyber_score"]'),
    systemScore: document.querySelector('[data-risk="system_score"]'),
    records: document.querySelector('[data-risk="records"]'),
    anomalies: document.querySelector('[data-risk="anomalies"]'),
    anomalyPercentage: document.querySelector('[data-risk="anomaly_percentage"]'),
    model: document.querySelector('[data-risk="model"]'),
    modelStatus: document.querySelector('[data-risk="model_status"]'),
    cpu: document.querySelector('[data-risk="cpu"]'),
    ram: document.querySelector('[data-risk="ram"]'),
    disk: document.querySelector('[data-risk="disk"]'),
    network: document.querySelector('[data-risk="network"]'),
    dominant: document.querySelector('[data-risk="dominant"]'),
    evidence: document.querySelector('[data-risk="evidence"]'),
    fusionTrack: document.querySelector('[data-risk="fusion_track"]'),
    fusionSummary: document.querySelector('[data-risk="fusion_summary"]'),
    processing: document.querySelector('[data-risk="processing"]'),
    weatherMetrics: document.querySelector('[data-risk="weather_metrics"]'),
    uploadForm: document.querySelector('#risk-analysis-form'),
    uploadStatus: document.querySelector('[data-risk="upload_status"]')
  };

  function formatNumber(value, digits = 2) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString(undefined, {
      maximumFractionDigits: digits,
      minimumFractionDigits: digits
    }) : "-";
  }

  function setText(element, value) {
    if (element) element.textContent = value;
  }

  function renderMetric(element, value, suffix = "") {
    setText(element, `${formatNumber(value)}${suffix}`);
  }

  function renderRisk(result) {
    const cyber = result.cyber || {};
    const weather = result.weather || {};
    const system = result.system || {};

    renderMetric(selectors.overall, result.overall_risk);
    setText(selectors.severity, result.severity || "LOW");
    renderMetric(selectors.weatherScore, result.weather_risk);
    renderMetric(selectors.cyberScore, result.cyber_risk);
    renderMetric(selectors.systemScore, result.system_risk);
    setText(document.querySelector('[data-risk="records_uploaded"]'), Number(cyber.records_uploaded || 0).toLocaleString());
    setText(selectors.records, Number(cyber.records_analyzed || 0).toLocaleString());
    setText(selectors.anomalies, Number(cyber.anomalies_detected || 0).toLocaleString());
    renderMetric(selectors.anomalyPercentage, cyber.anomaly_percentage || 0, "%");
    setText(selectors.model, result.model || "Isolation Forest");
    setText(selectors.modelStatus, result.model_status || "NOT_RUN");
    renderMetric(selectors.cpu, system.cpu, "%");
    renderMetric(selectors.ram, system.ram, "%");
    renderMetric(selectors.disk, system.disk, "%");
    renderMetric(selectors.network, system.network_activity, " bytes/s");
    setText(selectors.dominant, result.dominant_source || "NONE");
    renderMetric(selectors.processing, result.processing_time_seconds, "s");

    if (selectors.weatherMetrics) {
      const metrics = weather.weather_metrics || {};
      selectors.weatherMetrics.innerHTML = [
        ["Temperature", metrics.temperature ?? "-"],
        ["Precipitation", metrics.precipitation ?? "-"],
        ["Wind speed", metrics.wind_speed ?? "-"],
        ["Humidity", metrics.humidity ?? "-"],
        ["Pressure", metrics.pressure ?? "-"],
        ["Condition", metrics.weather_condition ?? metrics.weather_code ?? "-"]
      ].map(([label, value]) => `<div><span>${label}</span><strong>${String(value)}</strong></div>`).join("");
    }

    const weights = { weather: 0.25, cyber: 0.45, system: 0.30 };
    const sourceNames = { weather: "Weather", cyber: "Cyber", system: "System" };
    if (selectors.fusionTrack) {
      selectors.fusionTrack.innerHTML = Object.entries(weights).map(([key, weight]) => {
        const value = Number(result.risk_factors?.[key] || 0);
        const width = Math.max(0, Math.min(100, value * weight * 4));
        return `<div class="fusion-row"><span>${sourceNames[key]}</span><div class="fusion-bar"><div class="fusion-fill" style="width:${width}%"></div></div><strong>${formatNumber(value)}</strong></div>`;
      }).join("");
    }

    if (selectors.fusionSummary) {
      selectors.fusionSummary.innerHTML = `<p>Final weighted score: <strong>${formatNumber(result.overall_risk)} / 100</strong></p><p>Dominant source: <strong>${result.dominant_source || "NONE"}</strong></p><p>Severity: <strong>${result.severity || "LOW"}</strong></p>`;
    }

    if (selectors.evidence) {
      selectors.evidence.innerHTML = (result.risk_evidence || []).map((item) => `<li>${String(item)}</li>`).join("");
    }

    if (selectors.uploadStatus) {
      const uploaded = Number(cyber.records_uploaded || 0);
      const analyzed = Number(cyber.records_analyzed || 0);
      selectors.uploadStatus.textContent = uploaded > 0
        ? `Analyzed ${analyzed.toLocaleString()} of ${uploaded.toLocaleString()} uploaded records.`
        : "No CSV supplied. Weather and live system data are still evaluated.";
    }
  }

  async function analyze() {
    if (selectors.uploadForm === null) return;
    const form = selectors.uploadForm;
    const button = form.querySelector('button[type="submit"]');
    const fileInput = form.querySelector('input[type="file"]');
    if (button) button.disabled = true;
    try {
      const hasFile = fileInput && fileInput.files.length;
      const response = await fetch(hasFile ? "/api/risk-analysis" : "/api/risk-status", {
        method: hasFile ? "POST" : "GET",
        body: hasFile ? new FormData(form) : undefined
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.message || "Risk analysis failed");
      renderRisk(payload.analysis || payload.risk);
    } catch (error) {
      if (selectors.uploadStatus) selectors.uploadStatus.textContent = error.message;
    } finally {
      if (button) button.disabled = false;
    }
  }

  selectors.uploadForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    analyze();
  });

  analyze();
  window.setInterval(() => { if (!selectors.uploadForm.matches(":focus-within")) analyze(); }, 10000);
})();
