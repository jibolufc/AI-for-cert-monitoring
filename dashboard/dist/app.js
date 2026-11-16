const state = { data: null };

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = value;
}

function showSection(id) {
  document.querySelectorAll(".page-section").forEach((section) => {
    section.classList.toggle("is-visible", section.id === id);
  });
  document.querySelectorAll(".nav-item").forEach((item) => {
    const active = item.dataset.section === id;
    item.classList.toggle("is-active", active);
    active ? item.setAttribute("aria-current", "page") : item.removeAttribute("aria-current");
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderMetrics(metrics) {
  byId("metric-grid").innerHTML = metrics.map((metric) => `
    <article class="metric-card">
      <div class="metric-top"><span>${escapeHtml(metric.label)}</span><span class="metric-symbol">${escapeHtml(metric.symbol)}</span></div>
      <strong>${escapeHtml(metric.value)}</strong>
      <small>${escapeHtml(metric.note)}</small>
    </article>
  `).join("");
}

function renderTruths(truths) {
  byId("truth-list").innerHTML = truths.map((truth) => `
    <div class="truth-item">
      <span class="truth-marker ${escapeHtml(truth.tone)}"></span>
      <div><strong>${escapeHtml(truth.title)}</strong><small>${escapeHtml(truth.detail)}</small></div>
      <em>${escapeHtml(truth.state)}</em>
    </div>
  `).join("");
}

function renderActivity(activity) {
  byId("activity-list").innerHTML = activity.map((item) => `
    <li><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.time)} · ${escapeHtml(item.detail)}</span></li>
  `).join("");
}

function renderControls(controls) {
  byId("control-list").innerHTML = controls.map((control) => `
    <article class="control-card">
      <button class="control-summary" type="button" aria-expanded="false">
        <span class="control-id">${escapeHtml(control.id)}</span>
        <span class="control-name">${escapeHtml(control.name)}</span>
        <span class="control-required">${escapeHtml(control.minimumEvidence)}</span>
        <span class="control-state">${escapeHtml(control.status)}</span>
      </button>
      <div class="control-detail">${escapeHtml(control.note)}</div>
    </article>
  `).join("");
  document.querySelectorAll(".control-summary").forEach((button) => {
    button.addEventListener("click", () => {
      const card = button.closest(".control-card");
      const open = card.classList.toggle("is-open");
      button.setAttribute("aria-expanded", String(open));
    });
  });
}

function renderPqc(items) {
  byId("pqc-grid").innerHTML = items.map((item) => {
    const bars = Array.from({ length: 8 }, (_, index) => `<i class="${index < item.bars ? "is-on" : ""}"></i>`).join("");
    return `
      <article class="pqc-card">
        <div class="pqc-card-top"><span class="eyebrow">${escapeHtml(item.label)}</span><span class="pill ${escapeHtml(item.pillClass)}">${escapeHtml(item.badge)}</span></div>
        <div class="number">${escapeHtml(item.value)}</div>
        <p>${escapeHtml(item.note)}</p>
        <div class="mini-bars" aria-hidden="true">${bars}</div>
      </article>
    `;
  }).join("");
}

function renderEvidence(items) {
  byId("evidence-grid").innerHTML = items.map((item) => `
    <article class="evidence-card">
      <div class="evidence-card-head"><h3>${escapeHtml(item.title)}</h3><span class="pill ${escapeHtml(item.pillClass)}">${escapeHtml(item.level)}</span></div>
      <dl>${item.fields.map((field) => `<dt>${escapeHtml(field.label)}</dt><dd>${escapeHtml(field.value)}</dd>`).join("")}</dl>
    </article>
  `).join("");
}

function render(data) {
  state.data = data;
  setText("snapshot-date", data.snapshot.displayDate);
  setText("stack-region", data.deployment.regionLabel);
  setText("stack-name", data.deployment.stackName);
  setText("stack-state", data.deployment.stackStatus);
  setText("data-mode", data.boundaries.dataClassification);

  const demonstrated = data.controls.filter((control) => control.status === "demonstrated").length;
  const percent = Math.round((demonstrated / data.controls.length) * 100);
  setText("controls-demonstrated", demonstrated);
  setText("readiness-percent", `${percent}%`);
  byId("readiness-bar").style.width = `${percent}%`;
  byId("readiness-ring").style.setProperty("--progress", `${percent * 3.6}deg`);
  byId("readiness-ring").setAttribute("aria-label", `${demonstrated} of ${data.controls.length} controls demonstrated`);

  renderMetrics(data.metrics);
  renderTruths(data.truths);
  renderActivity(data.activity);
  renderControls(data.controls);
  renderPqc(data.pqcPosture);
  renderEvidence(data.evidence);
  setText("assurance-note", data.assuranceNote);
}

async function loadDashboard() {
  byId("load-error").hidden = true;
  try {
    const response = await fetch("data.json", { cache: "no-store" });
    if (!response.ok) throw new Error("snapshot unavailable");
    render(await response.json());
  } catch (error) {
    byId("load-error").hidden = false;
  }
}

document.querySelectorAll("[data-section]").forEach((button) => button.addEventListener("click", () => showSection(button.dataset.section)));
document.querySelectorAll("[data-jump]").forEach((button) => button.addEventListener("click", () => showSection(button.dataset.jump)));
byId("refresh-view").addEventListener("click", loadDashboard);
loadDashboard();
