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

function findService(services, name) {
  return (services || []).find((item) => item.name === name);
}

function serviceIsActive(service) {
  return service &&
    !service.error &&
    service.load_state === "loaded" &&
    service.active_state === "active";
}

function setComponentStatus(id, status, label) {
  const element = byId(id);
  element.className = `component-status ${status}`;
  element.textContent = label;
}

function addAttention(items, severity, title, detail) {
  items.push({severity, title, detail});
}

function drawOverview(snapshot) {
  const services = snapshot["services"];
  const interfaces = snapshot["network/interfaces"];
  const vpn = snapshot["vpn/status"];

  const attention = [];

  let firewallLevel = "unknown";
  let idsLevel = "unknown";
  let vpnLevel = "unknown";
  let networkLevel = "unknown";

  /*
   * Firewall
   *
   * This reports the systemd service state only. It intentionally does not
   * claim that the currently loaded nftables rules are semantically correct.
   */
  if (services) {
    const nftables = findService(services, "nftables.service");

    if (serviceIsActive(nftables)) {
      firewallLevel = "healthy";
      setComponentStatus("firewall-health", "healthy", "ACTIVE");
      byId("firewall-summary").textContent = "Сервис активен";
      byId("firewall-detail").textContent = "nftables.service · active";
    } else if (nftables) {
      firewallLevel = "critical";
      setComponentStatus("firewall-health", "critical", "INACTIVE");
      byId("firewall-summary").textContent = "Сервис не активен";
      byId("firewall-detail").textContent =
        `${nftables.active_state || "unknown"} / ${nftables.sub_state || "unknown"}`;

      addAttention(
        attention,
        "critical",
        "Firewall",
        `nftables.service: ${nftables.active_state || "unknown"} / ${nftables.sub_state || "unknown"}`,
      );
    }

    const suricata = findService(services, "suricata.service");
    const idsProcessor = findService(services, "secbox-ids.service");

    if (serviceIsActive(suricata) && serviceIsActive(idsProcessor)) {
      idsLevel = "healthy";
      setComponentStatus("ids-health", "healthy", "ACTIVE");
      byId("ids-summary").textContent = "IDS работает";
      byId("ids-detail").textContent = "Suricata + event processor";
    } else {
      idsLevel = "critical";
      setComponentStatus("ids-health", "critical", "INACTIVE");
      byId("ids-summary").textContent = "IDS работает не полностью";

      const failed = [suricata, idsProcessor]
        .filter((item) => !serviceIsActive(item))
        .map((item) => item?.name || "unknown");

      byId("ids-detail").textContent = failed.join(", ");

      addAttention(
        attention,
        "critical",
        "IDS",
        `Неактивные компоненты: ${failed.join(", ")}`,
      );
    }

    for (const service of services) {
      if (
        service.name === "nftables.service" ||
        service.name === "suricata.service" ||
        service.name === "secbox-ids.service"
      ) {
        continue;
      }

      if (service.error) {
        addAttention(
          attention,
          "warning",
          service.name,
          "Не удалось определить состояние systemd-сервиса",
        );
      } else if (
        service.load_state !== "not-found" &&
        service.active_state !== "active"
      ) {
        addAttention(
          attention,
          "warning",
          service.name,
          `${service.active_state || "unknown"} / ${service.sub_state || "unknown"}`,
        );
      }
    }
  }

  /*
   * VPN
   */
  if (vpn) {
    const active = vpn.tunnels.find(
      (tunnel) => tunnel.interface === vpn.active_interface
    );

    const down = vpn.tunnels.filter(
      (tunnel) => tunnel.status === "down"
    );

    const degraded = vpn.tunnels.filter(
      (tunnel) => tunnel.status === "degraded"
    );

    if (!active || active.status === "down") {
      vpnLevel = "critical";
      setComponentStatus(
        "overview-vpn-health",
        "critical",
        "DOWN",
      );
      byId("overview-vpn-summary").textContent =
        vpn.active_interface
          ? `${vpn.active_interface} недоступен`
          : "Нет активного туннеля";

      addAttention(
        attention,
        "critical",
        "VPN",
        vpn.reason || "Нет доступного активного VPN-туннеля",
      );
    } else if (active.status === "degraded" || down.length || degraded.length) {
      vpnLevel = "warning";
      setComponentStatus(
        "overview-vpn-health",
        "warning",
        "DEGRADED",
      );

      byId("overview-vpn-summary").textContent =
        `${vpn.active_interface} активен`;

      const affected = [...down, ...degraded]
        .map((tunnel) => `${tunnel.name} (${tunnel.interface})`)
        .join(", ");

      addAttention(
        attention,
        "warning",
        "VPN Pool",
        affected
          ? `Проблемы: ${affected}`
          : vpn.reason,
      );
    } else {
      vpnLevel = "healthy";
      setComponentStatus(
        "overview-vpn-health",
        "healthy",
        "HEALTHY",
      );
      byId("overview-vpn-summary").textContent =
        `${vpn.active_interface} активен`;
    }

    byId("overview-vpn-detail").textContent =
      `${vpn.tunnels.length} туннеля · active ${vpn.active_interface || "—"}`;
  }

  /*
   * Network
   */
  if (interfaces) {
    const physical = interfaces.filter(
      (item) =>
        !item.is_loopback &&
        !item.name.startsWith("wg")
    );

    /*
     * Until the runtime API exposes interface roles, an administratively
     * unused physical interface must not make the whole appliance degraded.
     */
    const relevant = physical.filter(
      (item) => String(item.operstate).toUpperCase() === "UP"
    );

    const failed = relevant.filter(
      (item) => String(item.operstate).toUpperCase() !== "UP"
    );

    if (!relevant.length) {
      networkLevel = "unknown";
      setComponentStatus("network-health", "unknown", "UNKNOWN");
      byId("network-summary").textContent = "Нет данных";
      byId("network-detail").textContent = "Интерфейсы не обнаружены";
    } else if (failed.length) {
      networkLevel = "warning";
      setComponentStatus("network-health", "warning", "DEGRADED");
      byId("network-summary").textContent =
        `${relevant.length - failed.length}/${relevant.length} UP`;
      byId("network-detail").textContent =
        `Неактивны: ${failed.map((item) => item.name).join(", ")}`;

      addAttention(
        attention,
        "warning",
        "Network",
        `Интерфейсы не UP: ${failed.map((item) => item.name).join(", ")}`,
      );
    } else {
      networkLevel = "healthy";
      setComponentStatus("network-health", "healthy", "HEALTHY");
      byId("network-summary").textContent =
        `${relevant.length}/${relevant.length} UP`;
      byId("network-detail").textContent =
        "Все обнаруженные интерфейсы активны";
    }
  }

  const levels = [
    firewallLevel,
    idsLevel,
    vpnLevel,
    networkLevel,
  ];

  const global = byId("system-health");

  if (levels.includes("critical")) {
    global.className = "health-badge critical";
    global.textContent = "● Требуется вмешательство";
  } else if (levels.includes("warning")) {
    global.className = "health-badge warning";
    global.textContent = "● Требует внимания";
  } else if (
    levels.length &&
    levels.every((level) => level === "healthy")
  ) {
    global.className = "health-badge healthy";
    global.textContent = "● Система работает штатно";
  } else {
    global.className = "health-badge unknown";
    global.textContent = "● Состояние определено не полностью";
  }

  drawAttention(attention);
}

function drawAttention(items) {
  const target = byId("attention-list");
  target.replaceChildren();

  byId("attention-count").textContent =
    items.length
      ? `${items.length} проблем`
      : "Нет проблем";

  if (!items.length) {
    const clean = document.createElement("div");
    clean.className = "attention-clean";

    const icon = document.createElement("span");
    icon.textContent = "✓";

    const text = document.createElement("div");

    const title = document.createElement("strong");
    title.textContent = "Критических проблем не обнаружено";

    const detail = document.createElement("small");
    detail.textContent =
      "Все контролируемые компоненты находятся в штатном состоянии.";

    text.append(title, detail);
    clean.append(icon, text);
    target.append(clean);
    return;
  }

  for (const item of items) {
    const row = document.createElement("div");
    row.className = `attention-item ${item.severity}`;

    const marker = document.createElement("span");
    marker.className = "attention-marker";
    marker.textContent =
      item.severity === "critical" ? "!" : "⚠";

    const content = document.createElement("div");

    const title = document.createElement("strong");
    title.textContent = item.title;

    const detail = document.createElement("span");
    detail.textContent = item.detail;

    content.append(title, detail);
    row.append(marker, content);
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
  const snapshot = {};

  await Promise.all(jobs.map(async ([path, errorId, draw]) => {
    byId(errorId).textContent = "";

    try {
      const data = await api(path);
      snapshot[path] = data;
      draw(data);
    } catch (error) {
      byId(errorId).textContent =
        `Не удалось обновить данные: ${error.message}. ` +
        "Предыдущие данные, если есть, могут устареть.";
      byId(errorId).className = "error";
    }
  }));

  drawOverview(snapshot);
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
