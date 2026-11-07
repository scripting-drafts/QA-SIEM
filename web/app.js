(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const tokenInput = $("token");
  const errorBox = $("error");
  const alertsBody = $("alerts");
  const eventsBody = $("events");
  const updated = $("updated");
  let timer = null;

  const token = () => sessionStorage.getItem("qaSiemToken") || "";

  function showError(message) {
    errorBox.textContent = message || "";
    errorBox.classList.toggle("hidden", !message);
  }

  function cell(text, className) {
    const td = document.createElement("td");
    td.textContent = text == null ? "" : String(text);
    if (className) td.className = className;
    return td;
  }

  function severityClass(value) {
    const s = String(value || "").toLowerCase();
    return ["critical", "error", "warning", "info"].includes(s) ? `sev-${s}` : "";
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
    headers["Authorization"] = `Bearer ${token()}`;
    if (options.body) headers["Content-Type"] = "application/json";
    const res = await fetch(path, Object.assign({}, options, { headers }));
    if (res.status === 401) throw new Error("Unauthorized: check the bearer token");
    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body && body.error) message = body.error;
      } catch (_) { /* keep status */ }
      throw new Error(message);
    }
    return res.json();
  }

  function renderStats(stats) {
    $("stat-events").textContent = stats.events ?? "-";
    $("stat-open").textContent = stats.alerts_open ?? "-";
    $("stat-alerts").textContent = stats.alerts_total ?? "-";
    $("stat-hosts").textContent = stats.hosts ?? "-";
    updated.textContent = stats.last_event_ts ? `last event ${stats.last_event_ts}` : "no events yet";
  }

  function renderAlerts(rows) {
    alertsBody.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = cell("No open alerts", "muted");
      td.colSpan = 6;
      tr.appendChild(td);
      alertsBody.appendChild(tr);
      return;
    }
    for (const row of rows) {
      const tr = document.createElement("tr");
      tr.appendChild(cell(row.severity, severityClass(row.severity)));
      tr.appendChild(cell(row.rule));
      tr.appendChild(cell(row.host_id));
      tr.appendChild(cell(row.count));
      tr.appendChild(cell(row.last_seen));
      const action = document.createElement("td");
      const button = document.createElement("button");
      button.textContent = "Ack";
      button.className = "small";
      button.addEventListener("click", async () => {
        try {
          await api("/api/v1/alerts/ack", {
            method: "POST",
            body: JSON.stringify({ id: row.id }),
          });
          await refresh();
        } catch (err) {
          showError(err.message);
        }
      });
      action.appendChild(button);
      tr.appendChild(action);
      alertsBody.appendChild(tr);
    }
  }

  function renderEvents(rows) {
    eventsBody.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = cell("No events yet", "muted");
      td.colSpan = 6;
      tr.appendChild(td);
      eventsBody.appendChild(tr);
      return;
    }
    for (const row of rows) {
      const tr = document.createElement("tr");
      tr.appendChild(cell(row.ts));
      tr.appendChild(cell(row.severity, severityClass(row.severity)));
      tr.appendChild(cell(row.event_type));
      tr.appendChild(cell(row.rule));
      tr.appendChild(cell(row.host_id));
      tr.appendChild(cell(row.subject || row.detail));
      eventsBody.appendChild(tr);
    }
  }

  async function refresh() {
    if (!token()) {
      showError("Enter the bearer token to connect");
      return;
    }
    try {
      const [stats, alerts, events] = await Promise.all([
        api("/api/v1/stats"),
        api("/api/v1/alerts?status=open&limit=50"),
        api("/api/v1/events?limit=50"),
      ]);
      showError("");
      renderStats(stats);
      renderAlerts(alerts);
      renderEvents(events);
    } catch (err) {
      showError(err.message);
    }
  }

  function connect() {
    const value = tokenInput.value.trim();
    if (!value) {
      showError("Enter the bearer token");
      return;
    }
    sessionStorage.setItem("qaSiemToken", value);
    tokenInput.value = "";
    refresh();
    if (timer) clearInterval(timer);
    timer = setInterval(refresh, 10000);
  }

  $("connect").addEventListener("click", connect);
  $("refresh").addEventListener("click", refresh);
  tokenInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") connect();
  });

  if (token()) {
    refresh();
    timer = setInterval(refresh, 10000);
  }
})();
