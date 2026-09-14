"use strict";
const byId = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(`/api/v1/${path}`, {credentials: "same-origin", ...options});
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401) throw new Error("Сессия недействительна. Обновите страницу и войдите снова.");
    const detail = Array.isArray(body.detail)
      ? body.detail.map((item) => `${item.loc.join(".")}: ${item.msg}`).join("\n") : body.detail;
    throw new Error(detail || `Ошибка HTTP ${response.status}`);
  }
  return body;
}

function table(id, rows) {
  const target = byId(id);
  target.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const value of row) {
      const td = document.createElement("td");
      td.textContent = value ?? "—";
      tr.append(td);
    }
    target.append(tr);
  }
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.textContent = "Нет данных";
    tr.append(td);
    target.append(tr);
  }
}

function drawSystem(data) {
  byId("hostname").textContent = data.hostname;
  byId("observed").textContent = `Linux ${data.kernel} · Обновлено ${new Date(data.observed_at).toLocaleString("ru-RU")}`;
  const hours = Math.floor((data.uptime_seconds ?? 0) / 3600);
  byId("uptime").textContent = data.uptime_seconds === null ? "—" : `${Math.floor(hours / 24)} д ${hours % 24} ч`;
  byId("load").textContent = data.load_average.map((x) => x.toFixed(2)).join(" / ") || "—";
  const total = data.memory_total_bytes;
  const available = data.memory_available_bytes;
  byId("memory").textContent = total && available !== null ? `${Math.round((1 - available / total) * 100)}%` : "—";
  byId("memory-total").textContent = total ? `Всего ${(total / 1024 ** 3).toFixed(2)} ГиБ` : "Память недоступна";
}

function drawInterfaces(data) {
  byId("interface-count").textContent = data.filter((x) => !x.is_loopback).length;
  table("interfaces-body", data.map((x) => [x.name, x.operstate,
    x.addresses.map((a) => `${a.address}/${a.prefixlen}`).join(", ") || "—", x.mac, x.mtu]));
}

function drawServices(data) {
  const target = byId("service-list");
  target.replaceChildren();
  for (const item of data) {
    const row = document.createElement("div");
    row.className = "service";
    const name = document.createElement("span");
    name.textContent = item.name;
    const state = document.createElement("span");
    state.textContent = item.error ? "Статус недоступен" : item.load_state === "not-found"
      ? "Не установлен" : `${item.active_state} / ${item.sub_state}`;
    state.className = item.error || item.active_state === "failed" ? "error" : item.active_state === "active" ? "good" : "";
    if (item.error) state.title = item.error;
    row.append(name, state);
    target.append(row);
  }
}

function formatBytes(value) {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} Б`;

  const units = ["КиБ", "МиБ", "ГиБ", "ТиБ"];
  let size = value / 1024;
  let unit = units[0];

  for (let index = 1; index < units.length && size >= 1024; index += 1) {
    size /= 1024;
    unit = units[index];
  }

  return `${size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)} ${unit}`;
}

function formatHandshake(seconds) {
  if (seconds === null || seconds === undefined) return "нет handshake";
  if (seconds < 60) return `${Math.round(seconds)} с назад`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин назад`;
  return `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин назад`;
}

function vpnStatusClass(status) {
  if (status === "healthy") return "vpn-status healthy";
  if (status === "degraded") return "vpn-status degraded";
  if (status === "down") return "vpn-status down";
  return "vpn-status";
}

function vpnStatusLabel(status) {
  if (status === "healthy") return "HEALTHY";
  if (status === "degraded") return "DEGRADED";
  if (status === "down") return "DOWN";
  return String(status || "UNKNOWN").toUpperCase();
}

function drawVpnStatus(data) {
  byId("vpn-active").textContent = data.active_interface || "Нет";
  byId("vpn-active-tag").textContent =
    `Активный: ${data.active_interface || "нет"}`;
  byId("vpn-reason").textContent = data.reason || "—";
  byId("vpn-observed").textContent =
    `Обновлено ${new Date(data.observed_at).toLocaleString("ru-RU")}`;

  const target = byId("vpn-tunnels");
  target.replaceChildren();

  for (const tunnel of data.tunnels) {
    const card = document.createElement("article");
    card.className = `vpn-tunnel ${
      tunnel.interface === data.active_interface ? "active" : ""
    }`;

    const top = document.createElement("div");
    top.className = "vpn-tunnel-top";

    const identity = document.createElement("div");

    const name = document.createElement("strong");
    name.textContent = tunnel.name;

    const iface = document.createElement("span");
    iface.className = "vpn-interface";
    iface.textContent = tunnel.interface;

    identity.append(name, iface);

    const status = document.createElement("span");
    status.className = vpnStatusClass(tunnel.status);
    status.textContent = vpnStatusLabel(tunnel.status);

    top.append(identity, status);

    const metrics = document.createElement("dl");
    metrics.className = "vpn-tunnel-metrics";

    const values = [
      ["Handshake", formatHandshake(tunnel.handshake_age_seconds)],
      [
        "Probe",
        tunnel.probe_ok === true
          ? "OK"
          : tunnel.probe_ok === false
            ? "FAIL"
            : "—",
      ],
      [
        "Latency",
        tunnel.latency_ms === null || tunnel.latency_ms === undefined
          ? "—"
          : `${tunnel.latency_ms.toFixed(2)} ms`,
      ],
      ["RX", formatBytes(tunnel.rx_bytes)],
      ["TX", formatBytes(tunnel.tx_bytes)],
    ];

    for (const [label, value] of values) {
      const item = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");

      dt.textContent = label;
      dd.textContent = value;

      item.append(dt, dd);
      metrics.append(item);
    }

    const reason = document.createElement("p");
    reason.className = "vpn-tunnel-reason";
    reason.textContent = tunnel.reason || "—";

    card.append(top, metrics, reason);
    target.append(card);
  }

  if (!data.tunnels.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "Нет настроенных VPN-туннелей.";
    target.append(empty);
  }
}

function drawVpnEvents(events) {
  const target = byId("vpn-events");
  target.replaceChildren();

  byId("vpn-event-count").textContent =
    `${events.length} ${events.length === 1 ? "событие" : "событий"}`;

  if (!events.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "Автоматических переключений пока не зарегистрировано.";
    target.append(empty);
    return;
  }

  for (const event of events) {
    const row = document.createElement("div");
    row.className = "vpn-event";

    const time = document.createElement("time");
    time.dateTime = event.occurred_at;
    time.textContent =
      new Date(event.occurred_at).toLocaleString("ru-RU");

    const route = document.createElement("strong");
    route.textContent =
      `${event.from_interface || "—"} → ${event.to_interface || "—"}`;

    const reason = document.createElement("span");
    reason.textContent = event.reason || "—";

    row.append(time, route, reason);
    target.append(row);
  }
}

async function refresh() {
  byId("refresh").disabled = true;
  const jobs = [
    ["system", "global-message", drawSystem],
    ["network/interfaces", "network-error", drawInterfaces],
    ["network/routes", "routes-error", (data) => table("routes-body", data.map((x) => [x.destination, x.gateway, x.interface, x.table, x.metric]))],
    ["services", "services-error", drawServices],
    ["vpn/status", "vpn-error", drawVpnStatus],
    ["vpn/events?limit=10", "vpn-error", drawVpnEvents],
    ["vpn/status", "vpn-error", drawVpnStatus],
    ["vpn/events?limit=10", "vpn-error", drawVpnEvents],
  ];
  await Promise.all(jobs.map(async ([path, errorId, draw]) => {
    byId(errorId).textContent = "";
    try { draw(await api(path)); }
    catch (error) {
      byId(errorId).textContent = `Не удалось обновить данные: ${error.message}. Предыдущие данные, если есть, могут устареть.`;
      byId(errorId).className = "error";
    }
  }));
  byId("refresh").disabled = false;
}

async function loadConfig() {
  byId("load-config").disabled = true;
  byId("preview-files").replaceChildren();
  try {
    byId("config-editor").value = JSON.stringify(await api("config"), null, 2);
    byId("config-message").textContent = "Текущая конфигурация загружена. Можно изменить копию для проверки.";
    byId("config-message").className = "good";
  } catch (error) {
    byId("config-message").textContent = error.message;
    byId("config-message").className = "error";
  } finally { byId("load-config").disabled = false; }
}

async function preview() {
  byId("preview").disabled = true;
  byId("preview-files").replaceChildren();
  byId("config-message").textContent = "Проверка…";
  byId("config-message").className = "";
  try {
    const candidate = JSON.parse(byId("config-editor").value);
    const result = await api("config/preview", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(candidate),
    });
    byId("config-message").textContent = "Проверка структуры и связей модулей пройдена. Настройки не сохранены и не применены. Синтаксис утилитами networkd, dnsmasq и nft не проверялся.";
    byId("config-message").className = "good";
    for (const [name, content] of Object.entries(result.files)) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = name;
      const pre = document.createElement("pre");
      pre.textContent = content;
      details.append(summary, pre);
      byId("preview-files").append(details);
    }
    if (!Object.keys(result.files).length) byId("config-message").textContent += " Нет включённых компонентов для генерации файлов.";
  } catch (error) {
    byId("config-message").textContent = error instanceof SyntaxError ? `Некорректный JSON: ${error.message}` : error.message;
    byId("config-message").className = "error";
  } finally { byId("preview").disabled = false; }
}

byId("refresh").addEventListener("click", refresh);
byId("load-config").addEventListener("click", loadConfig);
byId("preview").addEventListener("click", preview);
byId("config-editor").addEventListener("input", () => {
  byId("preview-files").replaceChildren();
  byId("config-message").textContent = "Копия изменена. Выполните проверку заново.";
  byId("config-message").className = "";
});
refresh();
