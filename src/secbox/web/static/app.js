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


function vpnL2DashboardStatus(status) {
  if (status === "ok") return "healthy";
  if (status === "warning") return "degraded";
  if (status === "error") return "down";
  return "unknown";
}


function vpnL2InterfaceState(value) {
  if (!value || typeof value !== "object") {
    return "недоступно";
  }

  const operstate =
    String(value.operstate || "UNKNOWN").toUpperCase();

  const admin =
    value.admin_up === true
      ? "UP"
      : value.admin_up === false
        ? "DOWN"
        : "UNKNOWN";

  return `${operstate} · admin ${admin}`;
}


function vpnL2Metric(label, value) {
  const item = document.createElement("div");
  const dt = document.createElement("dt");
  const dd = document.createElement("dd");

  dt.textContent = label;
  dd.textContent =
    value === null ||
    value === undefined ||
    value === ""
      ? "—"
      : String(value);

  item.append(dt, dd);

  return item;
}


function drawL2VpnMonitoring(component, vpnConfig) {
  const target = byId("vpn-l2-tunnels");

  if (!target) return;

  const overall = byId("vpn-l2-overall-status");
  const message = byId("vpn-l2-message");
  const error = byId("vpn-l2-error");

  error.textContent = "";

  if (!component) {
    overall.className = "vpn-status";
    overall.textContent = "UNKNOWN";
    message.textContent =
      "L2 VPN runtime недоступен.";

    target.replaceChildren();

    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent =
      "Dashboard не вернул компонент l2_vpn.";

    target.append(empty);
    return;
  }

  const cssStatus =
    vpnL2DashboardStatus(component.status);

  overall.className =
    vpnStatusClass(cssStatus);

  overall.textContent =
    vpnStatusLabel(cssStatus);

  message.textContent =
    component.message || "—";

  const runtimeTunnels =
    component.details?.tunnels || [];

  const configured =
    vpnConfig?.l2_tunnels || [];

  const configByName = new Map(
    configured.map((tunnel) => [
      tunnel.name,
      tunnel,
    ])
  );

  target.replaceChildren();

  for (const tunnel of runtimeTunnels) {
    const config =
      configByName.get(tunnel.name) || {};

    const transport = config.transport || {};
    const peer = transport.peer || {};
    const bridge = config.bridge || {};
    const encap = config.encapsulation || {};

    const card =
      document.createElement("article");

    card.className = "vpn-l2-card";

    const header =
      document.createElement("div");

    header.className = "vpn-tunnel-top";

    const identity =
      document.createElement("div");

    const name =
      document.createElement("strong");

    name.textContent =
      tunnel.name || "L2 VPN";

    const interfaces =
      document.createElement("span");

    interfaces.className = "vpn-interface";
    interfaces.textContent = [
      tunnel.transport_interface,
      tunnel.gretap_interface,
      tunnel.bridge_interface,
    ]
      .filter(Boolean)
      .join(" → ");

    identity.append(name, interfaces);

    const status =
      document.createElement("span");

    const tunnelCss =
      vpnL2DashboardStatus(tunnel.status);

    status.className =
      vpnStatusClass(tunnelCss);

    status.textContent =
      vpnStatusLabel(tunnelCss);

    header.append(identity, status);


    const metrics =
      document.createElement("dl");

    metrics.className =
      "vpn-l2-metrics";

    metrics.append(
      vpnL2Metric(
        "Handshake",
        formatHandshake(
          tunnel.handshake_age_seconds
        )
      ),
      vpnL2Metric(
        "WG transport",
        tunnel.transport_interface
      ),
      vpnL2Metric(
        "Transport address",
        transport.address
      ),
      vpnL2Metric(
        "Endpoint",
        peer.endpoint
      ),
      vpnL2Metric(
        "Bridge",
        tunnel.bridge_interface
      ),
      vpnL2Metric(
        "Bridge address",
        bridge.address
      ),
      vpnL2Metric(
        "GRETAP",
        tunnel.gretap_interface
      ),
      vpnL2Metric(
        "GRETAP local",
        encap.local
      ),
      vpnL2Metric(
        "GRETAP remote",
        encap.remote
      ),
      vpnL2Metric(
        "Effective MTU",
        encap.mtu
      ),
      vpnL2Metric(
        "Access ports",
        (tunnel.access_ports || []).join(", ")
      ),
      vpnL2Metric(
        "Bridge members",
        (tunnel.bridge_members || []).join(", ")
      )
    );


    const runtime =
      document.createElement("div");

    runtime.className =
      "vpn-l2-runtime-grid";

    const runtimeInterfaces =
      tunnel.interfaces || {};

    const runtimeRows = [
      [
        "WireGuard",
        tunnel.transport_interface,
        runtimeInterfaces.transport,
      ],
      [
        "GRETAP",
        tunnel.gretap_interface,
        runtimeInterfaces.gretap,
      ],
      [
        "Bridge",
        tunnel.bridge_interface,
        runtimeInterfaces.bridge,
      ],
    ];

    for (const port of tunnel.access_ports || []) {
      runtimeRows.push([
        "Access",
        port,
        runtimeInterfaces[`access:${port}`],
      ]);
    }

    for (const [role, iface, state] of runtimeRows) {
      const row =
        document.createElement("div");

      row.className =
        "vpn-l2-runtime-row";

      const roleNode =
        document.createElement("span");

      roleNode.textContent = role;

      const ifaceNode =
        document.createElement("strong");

      ifaceNode.textContent =
        iface || "—";

      const stateNode =
        document.createElement("span");

      stateNode.textContent =
        vpnL2InterfaceState(state);

      if (state?.master) {
        stateNode.textContent +=
          ` · master ${state.master}`;
      }

      row.append(
        roleNode,
        ifaceNode,
        stateNode
      );

      runtime.append(row);
    }


    const notes =
      document.createElement("div");

    notes.className =
      "vpn-l2-notes";

    const errors =
      tunnel.errors || [];

    const warnings =
      tunnel.warnings || [];

    if (!errors.length && !warnings.length) {
      const ok =
        document.createElement("p");

      ok.className = "vpn-l2-ok";
      ok.textContent =
        "Все компоненты overlay работают штатно.";

      notes.append(ok);
    }

    for (const value of errors) {
      const row =
        document.createElement("p");

      row.className = "error";
      row.textContent = `Ошибка: ${value}`;

      notes.append(row);
    }

    for (const value of warnings) {
      const row =
        document.createElement("p");

      row.className =
        "vpn-l2-warning";

      row.textContent =
        `Предупреждение: ${value}`;

      notes.append(row);
    }

    card.append(
      header,
      metrics,
      runtime,
      notes
    );

    target.append(card);
  }

  if (!runtimeTunnels.length) {
    const empty =
      document.createElement("p");

    empty.className = "hint";

    empty.textContent =
      "Нет включённых L2 VPN overlays.";

    target.append(empty);
  }
}


let vpnL2RefreshRunning = false;


async function refreshL2VpnMonitoring() {
  const target = byId("vpn-l2-tunnels");

  if (!target || vpnL2RefreshRunning) {
    return;
  }

  vpnL2RefreshRunning = true;

  const error = byId("vpn-l2-error");

  try {
    const [dashboard, config] =
      await Promise.all([
        api("dashboard"),
        api("vpn/config").catch(() => null),
      ]);

    drawL2VpnMonitoring(
      dashboard?.components?.l2_vpn,
      config?.vpn
    );

  } catch (exception) {
    if (error) {
      error.textContent =
        `Не удалось получить L2 VPN runtime: ${
          exception.message
        }`;
    }
  } finally {
    vpnL2RefreshRunning = false;
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

function dashboardCssStatus(status) {
  if (status === "ok") return "healthy";
  if (status === "warning") return "warning";
  if (status === "error") return "critical";
  return "unknown";
}

function dashboardStatusLabel(status) {
  if (status === "ok") return "OK";
  if (status === "warning") return "WARNING";
  if (status === "error") return "ERROR";
  return "UNKNOWN";
}

function dashboardDetail(component) {
  if (!component || !component.details) {
    return "Нет дополнительных данных";
  }

  const details = component.details;

  if (details.enabled_tunnels !== undefined) {
    const tunnels = Array.isArray(details.tunnels)
      ? details.tunnels
      : [];

    const ok = tunnels.filter(
      (item) => item.status === "ok"
    ).length;

    return (
      `туннелей ${details.enabled_tunnels}` +
      (tunnels.length
        ? ` · OK ${ok}/${tunnels.length}`
        : "")
    );
  }

  if (details.enabled !== undefined) {
    if (!details.enabled) {
      return "Отключён конфигурацией";
    }

    return (
      `DNS ${details.dns_enabled ? "ON" : "OFF"}` +
      ` · blocked ${details.blocked_domains ?? 0}` +
      ` · DoH ${details.doh_enabled ? "ON" : "OFF"}`
    );
  }

  if (details.unit) {
    return [
      details.unit,
      details.active_state,
      details.sub_state,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  if (details.active_interface !== undefined) {
    const tunnels = Array.isArray(details.tunnels)
      ? details.tunnels.length
      : 0;

    return (
      `active ${details.active_interface || "—"}` +
      ` · туннелей ${tunnels}`
    );
  }

  if (Array.isArray(details.interfaces)) {
    return `интерфейсов ${details.interfaces.length}`;
  }

  if (details.active_entries !== undefined) {
    return (
      `активных записей ${details.active_entries}` +
      ` · всего ${details.stored_entries ?? "—"}`
    );
  }

  if (details.hostname) {
    return `${details.hostname} · ${details.kernel || "Linux"}`;
  }

  if (details.path) {
    return details.path;
  }

  return "Данные получены";
}

function drawDashboardComponent(name, component) {
  const ids = {
    system: [
      "dashboard-system-health",
      "dashboard-system-summary",
      "dashboard-system-detail",
    ],
    network: [
      "network-health",
      "network-summary",
      "network-detail",
    ],
    vpn: [
      "overview-vpn-health",
      "overview-vpn-summary",
      "overview-vpn-detail",
    ],
    l2_vpn: [
      "overview-l2-vpn-health",
      "overview-l2-vpn-summary",
      "overview-l2-vpn-detail",
    ],
    dhcp: [
      "dhcp-health",
      "dhcp-summary",
      "dhcp-detail",
    ],
    firewall: [
      "firewall-health",
      "firewall-summary",
      "firewall-detail",
    ],
    ids: [
      "ids-health",
      "ids-summary",
      "ids-detail",
    ],
    suricata: [
      "suricata-health",
      "suricata-summary",
      "suricata-detail",
    ],
    blacklist: [
      "blacklist-health",
      "blacklist-summary",
      "blacklist-detail",
    ],
    content_filter: [
      "content-filter-health",
      "content-filter-summary",
      "content-filter-detail",
    ],
  };

  const target = ids[name];

  if (!target) {
    return;
  }

  const [statusId, summaryId, detailId] = target;
  const status = component?.status || "unknown";

  setComponentStatus(
    statusId,
    dashboardCssStatus(status),
    dashboardStatusLabel(status),
  );

  byId(summaryId).textContent =
    component?.message || "Состояние недоступно";

  byId(detailId).textContent =
    dashboardDetail(component);
}

function drawOverview(data) {
  const components = data?.components || {};

  for (const name of [
    "system",
    "network",
    "vpn",
    "l2_vpn",
    "dhcp",
    "firewall",
    "ids",
    "suricata",
    "blacklist",
    "content_filter",
  ]) {
    drawDashboardComponent(
      name,
      components[name],
    );
  }

  const global = byId("system-health");

  const globalCss = dashboardCssStatus(
    data?.status || "unknown",
  );

  global.className =
    `health-badge ${globalCss}`;

  if (data?.status === "ok") {
    global.textContent =
      "● Система работает штатно";
  } else if (data?.status === "error") {
    global.textContent =
      "● Требуется вмешательство";
  } else if (data?.status === "warning") {
    global.textContent =
      "● Требует внимания";
  } else {
    global.textContent =
      "● Состояние определено не полностью";
  }

  if (data?.updated_at) {
    byId("observed").textContent =
      `Dashboard обновлён ${
        new Date(
          data.updated_at
        ).toLocaleString("ru-RU")
      }`;
  }

  const titles = {
    system: "System",
    network: "Network",
    vpn: "VPN",
    l2_vpn: "L2 VPN",
    dhcp: "DHCP",
    firewall: "Firewall",
    ids: "IDS",
    suricata: "Suricata",
    blacklist: "Blackhole",
    content_filter: "Content Filter",
  };

  const attention = [];

  for (
    const [name, component]
    of Object.entries(components)
  ) {
    if (
      !component ||
      component.status === "ok"
    ) {
      continue;
    }

    addAttention(
      attention,
      component.status === "error"
        ? "critical"
        : "warning",
      titles[name] || name,
      component.message ||
        "Состояние компонента требует проверки",
    );
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
    ["dashboard", "global-message", drawOverview],
    ["system", "global-message", drawSystem],
    ["network/status", "global-message", () => {}],
    ["network/interfaces", "network-error", drawInterfaces],
    ["network/routes", "routes-error", (data) => table("routes-body", data.map((x) => [x.destination, x.gateway, x.interface, x.table, x.metric]))],
    ["services", "services-error", drawServices],
    ["vpn/status", "vpn-error", drawVpnStatus],
    ["vpn/events?limit=10", "vpn-error", drawVpnEvents],
  ];
  await Promise.all(jobs.map(async ([path, errorId, draw]) => {
    byId(errorId).textContent = "";

    try {
      const data = await api(path);
      draw(data);
    } catch (error) {
      byId(errorId).textContent =
        `Не удалось обновить данные: ${error.message}. ` +
        "Предыдущие данные, если есть, могут устареть.";
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
window.setInterval(refresh, 10000);

/* SECBOX VPN CONFIGURATION UI START */
(() => {
  "use strict";

  const API = "/api/v1/vpn/config";
  const VALIDATE_API = "/api/v1/vpn/config/validate";

  let vpnConfig = null;
let vpnPersistedConfig = null;

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function csv(value) {
    return String(value ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function field(label, name, value, type = "text", help = "") {
    return `
      <label class="vpn-config-field">
        <span>${esc(label)}</span>
        <input
          type="${esc(type)}"
          data-vpn-field="${esc(name)}"
          value="${esc(value ?? "")}"
        >
        ${help ? `<small>${esc(help)}</small>` : ""}
      </label>
    `;
  }

  function defaultTunnel(index) {
    const number = index + 1;

    return {
      name: `tunnel-${number}`,
      enabled: true,
      interface: `wg${index}`,
      address: `10.20${index}.0.2/30`,
      private_key_file: `/etc/secbox/vpn/wg${index}.key`,
      mtu: 1420,
      priority: 100 + index * 100,
      routing_table: 200 + index,
      source_networks: [],
      health_probe: null,
      peer: {
        public_key: "",
        endpoint: "",
        allowed_ips: ["0.0.0.0/0"],
        persistent_keepalive: 25,
        preshared_key_file: null,
      },
    };
  }

  function defaultL2Tunnel(index) {
    const number = index + 1;
    const octet = 210 + index;

    return {
      name: `l2-site-${number}`,
      enabled: true,
      transport: {
        interface: `wg-l2-${number}`,
        address: `10.${octet}.0.2/30`,
        private_key_file: `/etc/secbox/vpn/wg-l2-${number}.key`,
        mtu: 1420,
        listen_port: null,
        peer: {
          public_key: "",
          endpoint: "",
          allowed_ips: [`10.${octet}.0.1/32`],
          persistent_keepalive: 25,
          preshared_key_file: null,
        },
      },
      bridge: {
        interface: `br-l2-${number}`,
        address: `172.${octet}.0.2/24`,
        ports: [],
      },
      encapsulation: {
        interface: `gt-l2-${number}`,
        local: `10.${octet}.0.2`,
        remote: `10.${octet}.0.1`,
        mtu: 1376,
        ttl: 64,
      },
    };
  }

  function l3Card(tunnel, index) {
    const peer = tunnel.peer || {};

    return `
      <article class="vpn-config-tunnel" data-vpn-tunnel="${index}">
        <div class="vpn-config-tunnel-header">
          <div>
            <div class="vpn-config-type">L3 · WireGuard</div>
            <h3>${esc(tunnel.name || `Tunnel ${index + 1}`)}</h3>
            <div class="vpn-config-subtitle">
              ${esc(tunnel.interface || "new interface")}
            </div>
          </div>

          <div class="vpn-config-tunnel-actions">
            <label class="vpn-config-enabled">
              <input
                type="checkbox"
                data-vpn-field="enabled"
                ${tunnel.enabled !== false ? "checked" : ""}
              >
              Enabled
            </label>

            <button
              type="button"
              class="vpn-config-danger"
              data-vpn-remove="${index}"
            >Delete</button>
          </div>
        </div>

        <div class="vpn-config-grid">
          ${field("Name", "name", tunnel.name)}
          ${field("Interface", "interface", tunnel.interface)}
          ${field("Address", "address", tunnel.address)}
          ${field(
            "Private key path",
            "private_key_file",
            tunnel.private_key_file,
            "text",
            "Содержимое ключа через Web UI не передаётся."
          )}
          ${field("MTU", "mtu", tunnel.mtu ?? 1420, "number")}
          ${field("Priority", "priority", tunnel.priority ?? 100, "number")}
          ${field(
            "Routing table",
            "routing_table",
            tunnel.routing_table ?? 200,
            "number"
          )}
          ${field(
            "Health probe",
            "health_probe",
            tunnel.health_probe ?? ""
          )}
          ${field(
            "Source networks",
            "source_networks",
            (tunnel.source_networks || []).join(", ")
          )}
          ${field("Peer endpoint", "peer.endpoint", peer.endpoint ?? "")}
          ${field(
            "Peer public key",
            "peer.public_key",
            peer.public_key ?? ""
          )}
          ${field(
            "Allowed IPs",
            "peer.allowed_ips",
            (peer.allowed_ips || []).join(", ")
          )}
          ${field(
            "Persistent keepalive",
            "peer.persistent_keepalive",
            peer.persistent_keepalive ?? 25,
            "number"
          )}
          ${field(
            "Preshared key path",
            "peer.preshared_key_file",
            peer.preshared_key_file ?? ""
          )}
        </div>
      </article>
    `;
  }

  function l2Card(tunnel, index) {
    const transport = tunnel.transport || {};
    const peer = transport.peer || {};
    const bridge = tunnel.bridge || {};
    const encap = tunnel.encapsulation || {};

    return `
      <article
        class="vpn-config-tunnel vpn-config-l2"
        data-vpn-l2-tunnel="${index}"
      >
        <div class="vpn-config-tunnel-header">
          <div>
            <div class="vpn-config-type">L2 · Ethernet over WireGuard</div>
            <h3>${esc(tunnel.name || `L2 Tunnel ${index + 1}`)}</h3>
            <div class="vpn-config-subtitle">
              ${esc(bridge.interface || "bridge")}
              · ${esc(transport.interface || "transport")}
              · ${esc(encap.interface || "gretap")}
            </div>
          </div>

          <div class="vpn-config-tunnel-actions">
            <span class="vpn-config-mtu-badge">
              Effective MTU ${esc(encap.mtu ?? 1376)}
            </span>

            <label class="vpn-config-enabled">
              <input
                type="checkbox"
                data-vpn-l2-field="enabled"
                ${tunnel.enabled !== false ? "checked" : ""}
              >
              Enabled
            </label>

            <button
              type="button"
              class="vpn-config-danger"
              data-vpn-l2-remove="${index}"
            >Delete</button>
          </div>
        </div>

        <div class="vpn-config-group">
          <h4>Overlay</h4>
          <div class="vpn-config-grid">
            ${field("Name", "name", tunnel.name)}
          </div>
        </div>

        <div class="vpn-config-group">
          <h4>WireGuard transport</h4>
          <div class="vpn-config-grid">
            ${field(
              "Transport interface",
              "transport.interface",
              transport.interface
            )}
            ${field(
              "Transport address",
              "transport.address",
              transport.address
            )}
            ${field(
              "Private key path",
              "transport.private_key_file",
              transport.private_key_file,
              "text",
              "SecBox хранит ключ локально; Web UI показывает только путь."
            )}
            ${field(
              "Transport MTU",
              "transport.mtu",
              transport.mtu ?? 1420,
              "number"
            )}
            ${field(
              "Listen port",
              "transport.listen_port",
              transport.listen_port ?? "",
              "number"
            )}
            ${field(
              "Peer endpoint",
              "transport.peer.endpoint",
              peer.endpoint ?? ""
            )}
            ${field(
              "Peer public key",
              "transport.peer.public_key",
              peer.public_key ?? ""
            )}
            ${field(
              "Peer allowed IPs",
              "transport.peer.allowed_ips",
              (peer.allowed_ips || []).join(", ")
            )}
            ${field(
              "Persistent keepalive",
              "transport.peer.persistent_keepalive",
              peer.persistent_keepalive ?? 25,
              "number"
            )}
            ${field(
              "Preshared key path",
              "transport.peer.preshared_key_file",
              peer.preshared_key_file ?? ""
            )}
          </div>
        </div>

        <div class="vpn-config-group">
          <h4>Ethernet bridge</h4>
          <div class="vpn-config-grid">
            ${field(
              "Bridge interface",
              "bridge.interface",
              bridge.interface
            )}
            ${field(
              "Bridge address",
              "bridge.address",
              bridge.address ?? ""
            )}
            ${field(
              "L2 access ports",
              "bridge.ports",
              (bridge.ports || []).join(", "),
              "text",
              "Например: ens37. Интерфейс должен иметь роль l2."
            )}
          </div>
        </div>

        <div class="vpn-config-group">
          <h4>GRETAP encapsulation</h4>
          <div class="vpn-config-grid">
            ${field(
              "GRETAP interface",
              "encapsulation.interface",
              encap.interface
            )}
            ${field(
              "Local transport IP",
              "encapsulation.local",
              encap.local
            )}
            ${field(
              "Remote transport IP",
              "encapsulation.remote",
              encap.remote
            )}
            ${field(
              "Effective L2 MTU",
              "encapsulation.mtu",
              encap.mtu ?? 1376,
              "number",
              "Конечные устройства также должны учитывать этот MTU."
            )}
            ${field(
              "TTL",
              "encapsulation.ttl",
              encap.ttl ?? 64,
              "number"
            )}
          </div>
        </div>

        <div class="vpn-config-warning">
          <strong>MTU:</strong>
          Ethernet-кадры проходят через GRETAP поверх WireGuard.
          Для текущего профиля безопасный effective MTU равен
          <strong>${esc(encap.mtu ?? 1376)}</strong>.
          Для полностью прозрачного L2 конечные устройства должны
          использовать совместимый MTU либо underlay должен обеспечивать
          достаточный запас.
        </div>
      </article>
    `;
  }

  function ensurePanel(id, page) {
    let panel = document.getElementById(id);

    if (panel) {
      panel.dataset.secboxPage = page;
      return panel;
    }

    panel = document.createElement("section");
    panel.id = id;
    panel.className = "panel vpn-config-panel";
    panel.dataset.secboxPage = page;

    document.querySelector("main")?.appendChild(panel);

    return panel;
  }

  function ensurePanels() {
    return {
      l3: ensurePanel(
        "vpn-configuration-l3-panel",
        "manage-vpn-l3"
      ),
      l2: ensurePanel(
        "vpn-configuration-l2-panel",
        "manage-vpn-l2"
      ),
    };
  }

  function activePanel() {
    return secboxCurrentPath() === "/manage/vpn/l2"
      ? document.getElementById("vpn-configuration-l2-panel")
      : document.getElementById("vpn-configuration-l3-panel");
  }

  function message(text, type = "info") {
    const panel = activePanel();

    if (!panel) {
      return;
    }

    const node = panel.querySelector(".vpn-config-message");

    if (!node) {
      return;
    }

    node.className =
      `vpn-config-message vpn-config-message-${type}`;

    node.textContent = text;
  }

  function toolbar(mode) {
    return `
      <div
        class="vpn-config-message vpn-config-message-info"
        role="status"
        aria-live="polite"
      >Configuration loaded.</div>

      <div class="vpn-config-toolbar">
        <div class="vpn-config-security-note">
          Private keys не читаются браузером:
          UI работает только с путями к key files.
        </div>

        <div class="vpn-config-toolbar-right">
          <button
            type="button"
            data-vpn-action="reload"
            data-vpn-mode="${mode}"
            class="vpn-config-secondary"
          >Reload</button>

          <button
            type="button"
            data-vpn-action="validate"
            data-vpn-mode="${mode}"
            class="vpn-config-secondary"
          >Validate</button>

          <button
            type="button"
            data-vpn-action="apply"
            data-vpn-mode="${mode}"
            class="vpn-config-primary"
          >Apply changes</button>
        </div>
      </div>
    `;
  }

  function renderL3(panel) {
    panel.innerHTML = `
      <div class="vpn-config-heading">
        <div>
          <p class="eyebrow">Управление VPN</p>
          <h2>L3 VPN</h2>
          <p>
            Маршрутизируемые WireGuard-туннели с priority,
            routing table и health-check.
          </p>
        </div>

        <label class="vpn-config-master-enabled">
          <input
            data-vpn-master-enabled
            type="checkbox"
            ${vpnConfig.enabled ? "checked" : ""}
          >
          VPN enabled
        </label>
      </div>

      <div class="vpn-config-section-heading">
        <div>
          <h3>L3 VPN Pool</h3>
          <p>
            Пул маршрутизируемых WireGuard-туннелей,
            переключение и контроль доступности.
          </p>
        </div>

        <span class="tag">
          ${vpnConfig.tunnels.length} tunnel(s)
        </span>
      </div>

      <div id="vpn-config-tunnels">
        ${vpnConfig.tunnels.map(l3Card).join("")}
      </div>

      <button
        type="button"
        id="vpn-config-add"
        class="vpn-config-secondary"
      >+ Add L3 tunnel</button>

      ${toolbar("l3")}
    `;
  }

  function renderL2(panel) {
    panel.innerHTML = `
      <div class="vpn-config-heading">
        <div>
          <p class="eyebrow">Управление VPN</p>
          <h2>L2 VPN</h2>
          <p>
            Ethernet-over-WireGuard:
            bridge → GRETAP → WireGuard.
          </p>
        </div>

        <label class="vpn-config-master-enabled">
          <input
            data-vpn-master-enabled
            type="checkbox"
            ${vpnConfig.enabled ? "checked" : ""}
          >
          VPN enabled
        </label>
      </div>

      <div class="vpn-config-section-heading">
        <div>
          <h3>L2 VPN Overlays</h3>
          <p>
            Ethernet bridge → GRETAP → WireGuard.
            Поддерживает broadcast/ARP/DHCP и перенос 802.1Q frames.
          </p>
        </div>

        <span class="tag">
          ${vpnConfig.l2_tunnels.length} overlay(s)
        </span>
      </div>

      <div id="vpn-config-l2-tunnels">
        ${
          vpnConfig.l2_tunnels.length
            ? vpnConfig.l2_tunnels.map(l2Card).join("")
            : `<p class="hint">L2 overlays не настроены.</p>`
        }
      </div>

      <button
        type="button"
        id="vpn-config-add-l2"
        class="vpn-config-secondary"
      >+ Add L2 overlay</button>

      ${toolbar("l2")}
    `;
  }

  function render() {
    const panels = ensurePanels();

    if (!vpnConfig) {
      for (const [mode, panel] of Object.entries(panels)) {
        panel.innerHTML = `
          <div class="vpn-config-heading">
            <div>
              <p class="eyebrow">Настройки</p>
              <h2>${mode === "l2" ? "L2 VPN" : "L3 VPN"}</h2>
              <p>Загрузка текущей VPN-конфигурации…</p>
            </div>
          </div>
        `;
      }

      return;
    }

    vpnConfig.tunnels ??= [];
    vpnConfig.l2_tunnels ??= [];

    renderL3(panels.l3);
    renderL2(panels.l2);

    bind();
    secboxActivatePage();
  }

  function setPath(object, path, value) {
    const parts = path.split(".");
    let target = object;

    for (let i = 0; i < parts.length - 1; i += 1) {
      target[parts[i]] ??= {};
      target = target[parts[i]];
    }

    target[parts.at(-1)] = value;
  }

  function readInputs(card, attribute, target) {
    card
      .querySelectorAll(`[${attribute}]`)
      .forEach((input) => {
        const path = input.getAttribute(attribute);
        let value;

        if (input.type === "checkbox") {
          value = input.checked;
        } else if (input.type === "number") {
          value = input.value === "" ? null : Number(input.value);
        } else {
          value = input.value.trim();
        }

        if (
          path === "source_networks"
          || path === "peer.allowed_ips"
          || path === "transport.peer.allowed_ips"
          || path === "bridge.ports"
        ) {
          value = csv(value);
        }

        if (
          path === "health_probe"
          || path === "peer.preshared_key_file"
          || path === "transport.peer.preshared_key_file"
          || path === "transport.listen_port"
          || path === "bridge.address"
        ) {
          if (value === "") {
            value = null;
          }
        }

        setPath(target, path, value);
      });
  }

  function activeMode() {
    return secboxCurrentPath() === "/manage/vpn/l2"
      ? "l2"
      : "l3";
  }


  function panelForMode(mode) {
    return document.getElementById(
      mode === "l2"
        ? "vpn-configuration-l2-panel"
        : "vpn-configuration-l3-panel"
    );
  }


  function readForm(mode = activeMode()) {
    if (!vpnConfig) {
      throw new Error(
        "VPN configuration is not loaded"
      );
    }

    /*
     * Start from the last configuration actually loaded
     * from SecBox.
     *
     * This guarantees:
     *
     * Apply L3 -> keeps persisted L2 untouched.
     * Apply L2 -> keeps persisted L3 untouched.
     */
    const baseline =
      vpnPersistedConfig || vpnConfig;

    const next = structuredClone(baseline);
    const panel = panelForMode(mode);

    if (!panel) {
      throw new Error(
        `VPN ${mode.toUpperCase()} editor is unavailable`
      );
    }

    const master =
      panel.querySelector(
        "[data-vpn-master-enabled]"
      );

    if (master) {
      next.enabled = master.checked;
    }

    if (mode === "l3") {
      const tunnels = structuredClone(
        vpnConfig.tunnels || []
      );

      panel
        .querySelectorAll("[data-vpn-tunnel]")
        .forEach((card) => {
          const index =
            Number(card.dataset.vpnTunnel);

          if (!tunnels[index]) {
            throw new Error(
              `Invalid L3 tunnel index ${index}`
            );
          }

          readInputs(
            card,
            "data-vpn-field",
            tunnels[index]
          );
        });

      next.tunnels = tunnels;

    } else {
      const tunnels = structuredClone(
        vpnConfig.l2_tunnels || []
      );

      panel
        .querySelectorAll(
          "[data-vpn-l2-tunnel]"
        )
        .forEach((card) => {
          const index =
            Number(card.dataset.vpnL2Tunnel);

          if (!tunnels[index]) {
            throw new Error(
              `Invalid L2 tunnel index ${index}`
            );
          }

          /*
           * Enabled has a dedicated L2 attribute.
           */
          readInputs(
            card,
            "data-vpn-l2-field",
            tunnels[index]
          );

          /*
           * Ordinary L2 fields use data-vpn-field so the
           * common field() renderer remains reusable.
           */
          readInputs(
            card,
            "data-vpn-field",
            tunnels[index]
          );
        });

      next.l2_tunnels = tunnels;
    }

    return next;
  }


  async function configApi(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
    });

    let body = null;

    try {
      body = await response.json();
    } catch {
      body = null;
    }

    if (!response.ok) {
      let detail =
        body?.detail
        || body?.error
        || `HTTP ${response.status}`;

      if (Array.isArray(detail)) {
        detail = detail
          .map((item) => {
            const location =
              Array.isArray(item.loc)
                ? item.loc.join(".")
                : "config";
            return `${location}: ${item.msg || "invalid value"}`;
          })
          .join("; ");
      }

      throw new Error(
        typeof detail === "string"
          ? detail
          : JSON.stringify(detail)
      );
    }

    return body;
  }

  async function load() {
    console.log("[SecBox VPN] load() started");

    const controller = new AbortController();

    const timeout = window.setTimeout(
      () => controller.abort(),
      10000
    );

    try {
      message("Loading configuration...");

      console.log(
        "[SecBox VPN] requesting",
        API
      );

      const body = await configApi(API, {
        signal: controller.signal,
      });

      console.log(
        "[SecBox VPN] response received",
        body
      );

      if (!body || !body.vpn) {
        throw new Error(
          "VPN API returned no vpn object"
        );
      }

      vpnConfig = body.vpn;

      vpnConfig.tunnels ??= [];
      vpnConfig.l2_tunnels ??= [];

      /*
       * Immutable baseline for editor isolation.
       * Hidden unsaved editor state must never leak into
       * Apply of the other VPN type.
       */
      vpnPersistedConfig =
        structuredClone(vpnConfig);

      console.log(
        "[SecBox VPN] config loaded",
        {
          l3: vpnConfig.tunnels.length,
          l2: vpnConfig.l2_tunnels.length,
        }
      );

      render();

      message(
        "Configuration loaded.",
        "success"
      );

    } catch (error) {
      console.error(
        "[SecBox VPN] load failed",
        error
      );

      const panel =
        activePanel()
        || ensurePanels().l3;

      const text =
        error?.name === "AbortError"
          ? "VPN API request timed out after 10 seconds"
          : (
              error?.message
              || String(error)
            );

      panel.innerHTML = `
        <div class="vpn-config-heading">
          <div>
            <p class="eyebrow">Ошибка</p>
            <h2>VPN Configuration</h2>
            <p>
              Configuration could not be loaded.
            </p>
          </div>
        </div>

        <div
          class="vpn-config-message vpn-config-message-error"
        >
          ${esc(text)}
        </div>

        <button
          type="button"
          id="vpn-config-retry"
          class="vpn-config-secondary"
        >
          Retry
        </button>
      `;

      document
        .getElementById("vpn-config-retry")
        ?.addEventListener(
          "click",
          load
        );

    } finally {
      window.clearTimeout(timeout);
    }
  }

  async function validate() {
    const button =
      activePanel()?.querySelector('[data-vpn-action="validate"]');

    try {
      const mode =
        button?.dataset.vpnMode || activeMode();

      const candidate = readForm(mode);

      if (button) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.textContent = "Validating...";
      }

      message(
        "Проверяем VPN-конфигурацию...",
        "info"
      );

      await configApi(VALIDATE_API, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          vpn: candidate,
        }),
      });

      message(
        "✓ Конфигурация корректна. Изменения НЕ применялись.",
        "success"
      );
    } catch (error) {
      message(
        `✕ Ошибка проверки: ${error.message}`,
        "error"
      );
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent =
          button.dataset.originalText || "Validate";
      }
    }
  }

  async function apply() {
    const button =
      activePanel()?.querySelector('[data-vpn-action="apply"]');

    try {
      const mode =
        button?.dataset.vpnMode || activeMode();

      const candidate = readForm(mode);

      if (!window.confirm(
        "Apply VPN configuration? Active network paths may change."
      )) {
        return;
      }

      button.disabled = true;
      message("Applying VPN configuration...");

      const body = await configApi(API, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          vpn: candidate,
        }),
      });

      /*
       * The server accepted this complete candidate.
       * Make it the new baseline immediately; load() below
       * will then refresh it from the authoritative config.
       */
      vpnPersistedConfig =
        structuredClone(candidate);

      vpnConfig =
        structuredClone(candidate);

      const l2Result =
        body.applied_l2_tunnels === undefined
          ? ""
          : ` · L2 overlays: ${body.applied_l2_tunnels}`;

      message(
        `Applied successfully. Active L3 tunnel: ${
          body.active_name || "none"
        } (${body.active_interface || "none"})${l2Result}.`,
        "success"
      );

      setTimeout(() => {
        load();
        refresh();
      }, 1000);
    } catch (error) {
      message(
        `Apply failed: ${error.message}`,
        "error"
      );
    } finally {
      if (button) {
        button.disabled = false;
      }
    }
  }

  function bind() {
    document
      .getElementById("vpn-config-add")
      ?.addEventListener("click", () => {
        vpnConfig = readForm("l3");
        vpnConfig.tunnels ??= [];

        vpnConfig.tunnels.push(
          defaultTunnel(vpnConfig.tunnels.length)
        );

        render();

        message(
          "New L3 tunnel added locally. Validate before applying."
        );
      });

    document
      .getElementById("vpn-config-add-l2")
      ?.addEventListener("click", () => {
        vpnConfig = readForm("l2");
        vpnConfig.l2_tunnels ??= [];

        vpnConfig.l2_tunnels.push(
          defaultL2Tunnel(vpnConfig.l2_tunnels.length)
        );

        render();

        message(
          "New L2 overlay added locally. Validate before applying."
        );
      });

    document
      .querySelectorAll("[data-vpn-remove]")
      .forEach((button) => {
        button.addEventListener("click", () => {
          const index = Number(button.dataset.vpnRemove);
          const current = readForm("l3");

          current.tunnels.splice(index, 1);
          vpnConfig = current;

          render();

          message(
            "L3 tunnel removed locally. Apply to commit the change."
          );
        });
      });

    document
      .querySelectorAll("[data-vpn-l2-remove]")
      .forEach((button) => {
        button.addEventListener("click", () => {
          const index = Number(button.dataset.vpnL2Remove);
          const current = readForm("l2");

          current.l2_tunnels.splice(index, 1);
          vpnConfig = current;

          render();

          message(
            "L2 overlay removed locally. Apply to commit the change."
          );
        });
      });

    document
      .querySelectorAll('[data-vpn-action="reload"]')
      .forEach((button) => {
        button.addEventListener("click", load);
      });

    document
      .querySelectorAll('[data-vpn-action="validate"]')
      .forEach((button) => {
        button.addEventListener("click", validate);
      });

    document
      .querySelectorAll('[data-vpn-action="apply"]')
      .forEach((button) => {
        button.addEventListener("click", apply);
      });

    document
      .querySelectorAll("[data-vpn-master-enabled]")
      .forEach((checkbox) => {
        checkbox.addEventListener("change", () => {
          vpnConfig.enabled = checkbox.checked;

          document
            .querySelectorAll("[data-vpn-master-enabled]")
            .forEach((other) => {
              other.checked = checkbox.checked;
            });
        });
      });
  }


  function boot() {
    ensurePanels();
    render();
    load();
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      boot
    );
  } else {
    window.setTimeout(boot, 0);
  }
})();
 /* SECBOX VPN CONFIGURATION UI END */


// ============================================================
// Network + DHCP configuration
// ============================================================

let networkDhcpState = null;


function networkConfigMessage(message, type = "info", target = null) {
    const element = document.getElementById(
        target ||
        (secboxCurrentPath() === "/manage/network/dhcp"
            ? "dhcp-config-message"
            : "network-interface-message")
    );

    if (!element) {
        return;
    }

    element.textContent = message;
    element.hidden = !message;

    element.classList.remove(
        "success",
        "error",
        "info"
    );

    element.classList.add(type);
}


function networkEscape(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}


function networkInterfaceCard(iface, index) {
    const isMgmt = iface.role === "mgmt";
    const isL2 = iface.role === "l2";

    const warning = isMgmt
        ? "MGMT — изменение адреса может разорвать Web-сессию."
        : (
            isL2
                ? "L2 — интерфейс может использоваться L2 VPN."
                : ""
        );

    return `
      <div class="network-card" data-network-index="${index}">
        <div class="network-card-title">
          <div>
            <strong>${networkEscape(iface.name)}</strong>
            <span class="network-role-badge">
              ${networkEscape(iface.role)}
            </span>
          </div>

          ${
              warning
                  ? `<span class="network-card-warning">
                       ${networkEscape(warning)}
                     </span>`
                  : ""
          }
        </div>

        <div class="network-form-grid">
          <label>
            <span>Роль</span>
            <select
              class="network-role"
              ${isMgmt || isL2 ? "disabled" : ""}
            >
              ${["wan", "lan", "mgmt", "l2"].map(role => `
                <option
                  value="${role}"
                  ${role === iface.role ? "selected" : ""}
                >
                  ${role.toUpperCase()}
                </option>
              `).join("")}
            </select>
          </label>

          <label>
            <span>IPv4</span>
            <select class="network-ipv4-method">
              ${["dhcp", "static", "disabled"].map(method => `
                <option
                  value="${method}"
                  ${method === iface.ipv4_method ? "selected" : ""}
                >
                  ${method}
                </option>
              `).join("")}
            </select>
          </label>

          <label>
            <span>IPv4 адрес / prefix</span>
            <input
              class="network-ipv4-address"
              type="text"
              placeholder="192.168.50.1/24"
              value="${
                  iface.ipv4_method === "static"
                      ? networkEscape(iface.ipv4_address || "")
                      : ""
              }"
              ${
                  iface.ipv4_method !== "static"
                      ? "disabled"
                      : ""
              }
            >
          </label>

          <label>
            <span>Routing table</span>
            <input
              class="network-routing-table"
              type="number"
              min="1"
              max="4294967295"
              placeholder="не задана"
              value="${
                  iface.routing_table === null ||
                  iface.routing_table === undefined
                      ? ""
                      : networkEscape(iface.routing_table)
              }"
            >
          </label>
        </div>
      </div>
    `;
}


function dhcpScopeCard(scope, index) {
    return `
      <div class="dhcp-card" data-dhcp-index="${index}">
        <div class="network-card-title">
          <strong>
            DHCP ${index + 1}
          </strong>

          <button
            type="button"
            class="danger-link dhcp-remove"
          >
            Удалить
          </button>
        </div>

        <div class="network-form-grid">
          <label class="checkbox-field">
            <input
              class="dhcp-enabled"
              type="checkbox"
              ${scope.enabled ? "checked" : ""}
            >
            <span>Включён</span>
          </label>

          <label>
            <span>Интерфейс</span>
            <input
              class="dhcp-interface"
              type="text"
              placeholder="ens36 или br-l2vpn"
              value="${networkEscape(scope.interface || "")}"
            >
          </label>

          <label>
            <span>Сеть</span>
            <input
              class="dhcp-network"
              type="text"
              placeholder="192.168.50.0/24"
              value="${networkEscape(scope.network || "")}"
            >
          </label>

          <label>
            <span>Начало диапазона</span>
            <input
              class="dhcp-range-start"
              type="text"
              placeholder="192.168.50.100"
              value="${networkEscape(scope.range_start || "")}"
            >
          </label>

          <label>
            <span>Конец диапазона</span>
            <input
              class="dhcp-range-end"
              type="text"
              placeholder="192.168.50.200"
              value="${networkEscape(scope.range_end || "")}"
            >
          </label>

          <label>
            <span>Gateway</span>
            <input
              class="dhcp-gateway"
              type="text"
              placeholder="192.168.50.1"
              value="${networkEscape(scope.gateway || "")}"
            >
          </label>

          <label>
            <span>DNS</span>
            <input
              class="dhcp-dns"
              type="text"
              placeholder="192.168.50.1, 1.1.1.1"
              value="${networkEscape(
                  (scope.dns_servers || []).join(", ")
              )}"
            >
          </label>

          <label>
            <span>Lease time</span>
            <input
              class="dhcp-lease-time"
              type="text"
              placeholder="1h"
              value="${networkEscape(scope.lease_time || "1h")}"
            >
          </label>
        </div>
      </div>
    `;
}


function renderNetworkDhcpConfig() {
    if (!networkDhcpState) {
        return;
    }

    const interfaceList =
        document.getElementById("network-interface-list");

    const dhcpList =
        document.getElementById("dhcp-scope-list");

    if (interfaceList) {
        interfaceList.innerHTML =
            networkDhcpState.network.interfaces
                .map(networkInterfaceCard)
                .join("");
    }

    if (dhcpList) {
        dhcpList.innerHTML =
            networkDhcpState.dhcp
                .map(dhcpScopeCard)
                .join("");
    }

    bindNetworkEditorEvents();
}

function bindNetworkEditorEvents() {
    document
        .querySelectorAll(".network-ipv4-method")
        .forEach(select => {
            select.addEventListener("change", event => {
                const card = event.target.closest(
                    ".network-card"
                );

                const address = card.querySelector(
                    ".network-ipv4-address"
                );

                const staticMode =
                    event.target.value === "static";

                address.disabled = !staticMode;

                if (!staticMode) {
                    address.value = "";
                }
            });
        });

    document
        .querySelectorAll(".dhcp-remove")
        .forEach(button => {
            button.addEventListener("click", event => {
                const card = event.target.closest(
                    ".dhcp-card"
                );

                const index = Number(
                    card.dataset.dhcpIndex
                );

                networkDhcpState.dhcp.splice(
                    index,
                    1
                );

                renderNetworkDhcpConfig();
            });
        });
}


function readNetworkDhcpForm() {
    if (!networkDhcpState) {
        throw new Error("Конфигурация сети ещё не загружена");
    }

    let interfaces = structuredClone(
        networkDhcpState.network.interfaces
    );

    const interfaceCards = Array.from(
        document.querySelectorAll(".network-card")
    );

    if (interfaceCards.length) {
        interfaces = interfaceCards.map(card => {
            const original =
                networkDhcpState.network.interfaces[
                    Number(card.dataset.networkIndex)
                ];

            const roleElement =
                card.querySelector(".network-role");

            const method =
                card.querySelector(".network-ipv4-method").value;

            const address =
                card.querySelector(".network-ipv4-address")
                    .value.trim();

            const routingRaw =
                card.querySelector(".network-routing-table")
                    .value.trim();

            return {
                name: original.name,

                role: roleElement.disabled
                    ? original.role
                    : roleElement.value,

                ipv4_method: method,

                ipv4_address:
                    method === "static"
                        ? address
                        : null,

                routing_table:
                    routingRaw === ""
                        ? null
                        : Number(routingRaw),
            };
        });
    }

    let dhcp = structuredClone(networkDhcpState.dhcp);

    const dhcpCards = Array.from(
        document.querySelectorAll(".dhcp-card")
    );

    if (dhcpCards.length) {
        dhcp = dhcpCards.map(card => {
            const dns =
                card.querySelector(".dhcp-dns")
                    .value
                    .split(",")
                    .map(value => value.trim())
                    .filter(Boolean);

            return {
                enabled:
                    card.querySelector(".dhcp-enabled").checked,

                interface:
                    card.querySelector(".dhcp-interface")
                        .value.trim(),

                network:
                    card.querySelector(".dhcp-network")
                        .value.trim(),

                range_start:
                    card.querySelector(".dhcp-range-start")
                        .value.trim(),

                range_end:
                    card.querySelector(".dhcp-range-end")
                        .value.trim(),

                gateway:
                    card.querySelector(".dhcp-gateway")
                        .value.trim(),

                dns_servers: dns,

                lease_time:
                    card.querySelector(".dhcp-lease-time")
                        .value.trim(),
            };
        });
    }

    return {
        network: {
            interfaces,
            routing_policy: [
                ...(networkDhcpState.network.routing_policy || [])
            ],
        },
        dhcp,
    };
}

async function networkApiRequest(
    path,
    options = {}
) {
    const response = await fetch(
        path,
        {
            ...options,
            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {}),
            },
        }
    );

    let body = null;

    try {
        body = await response.json();
    } catch (_) {
        body = null;
    }

    if (!response.ok) {
        let detail =
            body?.detail ||
            `HTTP ${response.status}`;

        if (Array.isArray(detail)) {
            detail = detail
                .map(item =>
                    item.msg ||
                    JSON.stringify(item)
                )
                .join("; ");
        }

        throw new Error(detail);
    }

    return body;
}


async function loadNetworkDhcpConfig() {
    networkConfigMessage(
        "Загрузка конфигурации...",
        "info"
    );

    try {
        const data = await networkApiRequest(
            "/api/v1/network/config"
        );

        networkDhcpState =
            structuredClone(data);

        renderNetworkDhcpConfig();

        networkConfigMessage(
            "Конфигурация загружена.",
            "success"
        );

    } catch (error) {
        networkConfigMessage(
            `Ошибка загрузки: ${error.message}`,
            "error"
        );
    }
}


async function validateNetworkDhcpConfig() {
    try {
        const payload = readNetworkDhcpForm();

        networkConfigMessage(
            "Проверка конфигурации...",
            "info"
        );

        await networkApiRequest(
            "/api/v1/network/config/validate",
            {
                method: "POST",
                body: JSON.stringify(payload),
            }
        );

        networkConfigMessage(
            "✓ Конфигурация корректна. Изменения НЕ применялись.",
            "success"
        );

    } catch (error) {
        networkConfigMessage(
            `Ошибка проверки: ${error.message}`,
            "error"
        );
    }
}


async function applyNetworkDhcpConfig() {
    let payload;

    try {
        payload = readNetworkDhcpForm();
    } catch (error) {
        networkConfigMessage(
            error.message,
            "error"
        );
        return;
    }

    const mgmt = payload.network.interfaces.find(
        iface => iface.role === "mgmt"
    );

    const warning =
        "Применить сетевую конфигурацию?\n\n" +
        "MGMT: " +
        (
            mgmt
                ? `${mgmt.name} / ${
                    mgmt.ipv4_address ||
                    mgmt.ipv4_method
                }`
                : "не найден"
        ) +
        "\n\nИзменение MGMT может разорвать доступ к Web UI.";

    if (!window.confirm(warning)) {
        return;
    }

    networkConfigMessage(
        "Применение Network + DHCP...",
        "info"
    );

    try {
        const result = await networkApiRequest(
            "/api/v1/network/config",
            {
                method: "PUT",
                body: JSON.stringify(payload),
            }
        );

        networkConfigMessage(
            "✓ Network + DHCP успешно применены. " +
            `Интерфейсов: ${result.interfaces}, ` +
            `DHCP: ${result.enabled_dhcp_scopes}/${result.dhcp_scopes}.`,
            "success"
        );

        await loadNetworkDhcpConfig();

    } catch (error) {
        networkConfigMessage(
            `Ошибка применения: ${error.message}`,
            "error"
        );
    }
}


function addDhcpScope() {
    if (!networkDhcpState) {
        return;
    }

    networkDhcpState.dhcp.push({
        enabled: false,
        interface: "",
        network: "192.168.60.0/24",
        range_start: "192.168.60.100",
        range_end: "192.168.60.200",
        gateway: "192.168.60.1",
        dns_servers: [],
        lease_time: "1h",
    });

    renderNetworkDhcpConfig();
}


function initializeNetworkDhcpEditor() {
    const interfacePage =
        document.getElementById("network-interfaces-page");

    const dhcpPage =
        document.getElementById("network-dhcp-page");

    if (!interfacePage && !dhcpPage) {
        return;
    }

    document
        .getElementById("network-config-reload")
        ?.addEventListener(
            "click",
            loadNetworkDhcpConfig
        );

    document
        .getElementById("dhcp-config-reload")
        ?.addEventListener(
            "click",
            loadNetworkDhcpConfig
        );

    document
        .getElementById("network-interface-validate")
        ?.addEventListener(
            "click",
            validateNetworkDhcpConfig
        );

    document
        .getElementById("network-interface-apply")
        ?.addEventListener(
            "click",
            applyNetworkDhcpConfig
        );

    document
        .getElementById("dhcp-config-validate")
        ?.addEventListener(
            "click",
            validateNetworkDhcpConfig
        );

    document
        .getElementById("dhcp-config-apply")
        ?.addEventListener(
            "click",
            applyNetworkDhcpConfig
        );

    document
        .getElementById("dhcp-add-scope")
        ?.addEventListener(
            "click",
            addDhcpScope
        );

    loadNetworkDhcpConfig();
}

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initializeNetworkDhcpEditor
    );
} else {
  window.setTimeout(
    initializeNetworkDhcpEditor,
    0
  );
}



// ============================================================
// SecBox Navigation v2
// ============================================================

const SECBOX_ROUTES = {
  "/": {
    page: "overview",
    title: "Обзор",
    section: "Мониторинг",
    subtitle: "Состояние системы",
  },

  "/monitoring/network": {
    page: "monitor-network",
    title: "Сеть",
    section: "Мониторинг",
    subtitle: "Интерфейсы и маршрутизация",
  },

  "/monitoring/vpn/l3": {
    page: "monitor-vpn-l3",
    title: "L3 VPN",
    section: "Мониторинг / VPN",
    subtitle: "Состояние маршрутизируемых WireGuard-туннелей",
  },

  "/monitoring/vpn/l2": {
    page: "monitor-vpn-l2",
    title: "L2 VPN",
    section: "Мониторинг / VPN",
    subtitle: "WireGuard transport, GRETAP и Ethernet bridge",
  },

  "/monitoring/firewall": {
    page: "monitor-firewall",
    title: "Firewall",
    section: "Мониторинг",
    subtitle: "Состояние сетевой фильтрации",
  },

  "/monitoring/ids": {
    page: "monitor-ids",
    title: "IDS / IPS",
    section: "Мониторинг",
    subtitle: "Состояние системы обнаружения угроз",
  },

  "/monitoring/blackhole": {
    page: "monitor-blackhole",
    title: "Blackhole",
    section: "Мониторинг",
    subtitle: "Динамические блокировки",
  },

  "/monitoring/content-filter": {
    page: "monitor-content-filter",
    title: "Content Filter",
    section: "Мониторинг",
    subtitle: "Состояние контентной фильтрации",
  },

  "/monitoring/services": {
    page: "monitor-services",
    title: "Службы",
    section: "Мониторинг",
    subtitle: "Состояние системных служб",
  },

  "/monitoring/system": {
    page: "monitor-system",
    title: "Система",
    section: "Мониторинг",
    subtitle: "Состояние SecBox",
  },

  "/manage/network/interfaces": {
    page: "manage-network",
    title: "Интерфейсы",
    section: "Управление / Сеть",
    subtitle: "Конфигурация сетевых интерфейсов",
  },

  "/manage/network/dhcp": {
    page: "manage-network",
    title: "DHCP / DNS",
    section: "Управление / Сеть",
    subtitle: "Адресация клиентских сетей",
  },

  "/manage/vpn/l3": {
    page: "manage-vpn",
    title: "L3 VPN",
    section: "Управление / VPN",
    subtitle: "Маршрутизируемые VPN-туннели",
  },

  "/manage/vpn/l2": {
    page: "manage-vpn",
    title: "L2 VPN",
    section: "Управление / VPN",
    subtitle: "Ethernet over WireGuard",
  },

  "/manage/firewall": {
    page: "manage-firewall",
    title: "Firewall",
    section: "Управление",
    subtitle: "Политики, правила и NAT",
  },

  "/manage/ids": {
    page: "manage-ids",
    title: "IDS / IPS",
    section: "Управление",
    subtitle: "Сигнатуры и режимы защиты",
  },

  "/manage/blackhole": {
    page: "manage-blackhole",
    title: "Blackhole",
    section: "Управление",
    subtitle: "Управление динамическими блокировками",
  },

  "/manage/content-filter": {
    page: "manage-content-filter",
    title: "Content Filter",
    section: "Управление",
    subtitle: "Политики контентной фильтрации",
  },

  "/manage/services": {
    page: "manage-services",
    title: "Службы",
    section: "Управление",
    subtitle: "Управление службами SecBox",
  },

  "/manage/system": {
    page: "manage-system",
    title: "Система",
    section: "Управление",
    subtitle: "Системные настройки SecBox",
  },
};


// Backward-compatible routes.
const SECBOX_ROUTE_ALIASES = {
  "/monitoring/vpn": "/monitoring/vpn/l3",
  "/network": "/monitoring/network",
  "/dhcp": "/manage/network/dhcp",
  "/vpn": "/monitoring/vpn/l3",
  "/firewall": "/monitoring/firewall",
  "/ids": "/monitoring/ids",
  "/blackhole": "/monitoring/blackhole",
  "/content-filter": "/monitoring/content-filter",
  "/system": "/monitoring/system",
};


function secboxCurrentPath() {
  let path = window.location.pathname.replace(/\/+$/, "");

  if (!path) {
    path = "/";
  }

  return SECBOX_ROUTE_ALIASES[path] || path;
}


function secboxRoute() {
  return SECBOX_ROUTES[secboxCurrentPath()] || SECBOX_ROUTES["/"];
}


function secboxCreatePlaceholder(page, title, description) {
  const section = document.createElement("section");

  section.className = "panel secbox-placeholder";
  section.dataset.secboxPage = page;

  section.innerHTML = `
    <div class="section-heading">
      <div>
        <p class="eyebrow">SecBox module</p>
        <h2>${title}</h2>
      </div>
      <span class="tag">В разработке</span>
    </div>

    <p class="placeholder-description">${description}</p>

    <div class="placeholder-grid">
      <article>
        <strong>Рабочая область подготовлена</strong>
        <span>
          Раздел отделён от остальных функций SecBox.
        </span>
      </article>

      <article>
        <strong>API подключается отдельно</strong>
        <span>
          Модуль можно развивать независимо от Overview.
        </span>
      </article>
    </div>
  `;

  return section;
}



function cfLines(value) {
  return String(value || "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}


async function cfRequest(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
  });

  let data = null;

  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    const detail = data?.detail || `HTTP ${response.status}`;
    throw new Error(detail);
  }

  return data;
}


function secboxCreateContentFilterPages() {
  const main = document.getElementById("app-main");

  if (!main) return;

  if (!main.querySelector('[data-secbox-page="monitor-content-filter"]')) {
    const monitor = document.createElement("section");

    monitor.className = "panel cf-page";
    monitor.dataset.secboxPage = "monitor-content-filter";

    monitor.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Контентная фильтрация</p>
          <h2>Content Filter</h2>
        </div>
        <button id="cf-monitor-refresh" type="button">Обновить</button>
      </div>

      <p id="cf-monitor-message" class="hint">Загрузка состояния…</p>

      <div class="cf-status-grid">
        <article>
          <span>Состояние</span>
          <strong id="cf-monitor-status">—</strong>
        </article>
        <article>
          <span>DNS</span>
          <strong id="cf-monitor-dns">—</strong>
        </article>
        <article>
          <span>Заблокировано доменов</span>
          <strong id="cf-monitor-blocked">—</strong>
        </article>
        <article>
          <span>Managed DoH адресов</span>
          <strong id="cf-monitor-doh-count">—</strong>
        </article>
      </div>

      <div class="cf-details">
        <div><span>Listen interface</span><strong id="cf-monitor-iface">—</strong></div>
        <div><span>Listen address</span><strong id="cf-monitor-address">—</strong></div>
        <div><span>DoT blocking</span><strong id="cf-monitor-dot">—</strong></div>
        <div><span>DoQ blocking</span><strong id="cf-monitor-doq">—</strong></div>
        <div><span>DoH blocking</span><strong id="cf-monitor-doh">—</strong></div>
        <div><span>Managed feed</span><strong id="cf-monitor-feed">—</strong></div>
        <div><span>Последнее обновление</span><strong id="cf-monitor-updated">—</strong></div>
      </div>
    `;

    main.append(monitor);
  }

  if (!main.querySelector('[data-secbox-page="manage-content-filter"]')) {
    const manage = document.createElement("section");

    manage.className = "panel cf-page";
    manage.dataset.secboxPage = "manage-content-filter";

    manage.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Управление</p>
          <h2>Content Filter</h2>
        </div>
        <span id="cf-config-state" class="tag">Загрузка…</span>
      </div>

      <form id="cf-form">
        <div class="cf-form-grid">
          <label class="cf-check">
            <input id="cf-enabled" type="checkbox">
            <span>Content Filter включён</span>
          </label>

          <label class="cf-check">
            <input id="cf-dns-enabled" type="checkbox">
            <span>DNS filtering включён</span>
          </label>

          <label>
            <span>LAN interface</span>
            <input id="cf-listen-interface" type="text" required>
          </label>

          <label>
            <span>Listen IPv4</span>
            <input id="cf-listen-address" type="text" required>
          </label>

          <label class="cf-wide">
            <span>Upstream DNS</span>
            <textarea id="cf-upstreams" rows="3"
              placeholder="1.1.1.1&#10;8.8.8.8"></textarea>
          </label>

          <label class="cf-wide">
            <span>Заблокированные домены</span>
            <textarea id="cf-blocked" rows="7"
              placeholder="example.com&#10;ads.example.net"></textarea>
          </label>
        </div>

        <h3 class="cf-subtitle">Encrypted DNS</h3>

        <div class="cf-form-grid">
          <label class="cf-check">
            <input id="cf-block-dot" type="checkbox">
            <span>Блокировать DNS-over-TLS</span>
          </label>

          <label class="cf-check">
            <input id="cf-block-doq" type="checkbox">
            <span>Блокировать DNS-over-QUIC</span>
          </label>

          <label class="cf-check">
            <input id="cf-doh-enabled" type="checkbox">
            <span>Блокировать DNS-over-HTTPS</span>
          </label>

          <label class="cf-check">
            <input id="cf-logging" type="checkbox">
            <span>Logging включён</span>
          </label>

          <label class="cf-wide">
            <span>Статические DoH resolver IPv4</span>
            <textarea id="cf-doh-resolvers" rows="3"></textarea>
          </label>
        </div>

        <h3 class="cf-subtitle">Managed DoH Feed</h3>

        <div class="cf-form-grid">
          <label class="cf-check cf-wide">
            <input id="cf-feed-enabled" type="checkbox">
            <span>Использовать managed DoH feed</span>
          </label>

          <label class="cf-wide">
            <span>Feed URL</span>
            <input id="cf-feed-url" type="url">
          </label>

          <label>
            <span>Timeout, сек</span>
            <input id="cf-feed-timeout" type="number" min="1" max="60">
          </label>

          <label>
            <span>Max size, bytes</span>
            <input id="cf-feed-bytes" type="number" min="1024" max="10485760">
          </label>

          <label>
            <span>Min addresses</span>
            <input id="cf-feed-min" type="number" min="1">
          </label>

          <label>
            <span>Max addresses</span>
            <input id="cf-feed-max" type="number" min="1">
          </label>
        </div>

        <p class="hint">
          Сейчас поддерживается политика default_action=allow.
          Allowed domains пока не поддерживаются backend.
        </p>

        <p id="cf-form-message" class="hint"></p>

        <div class="cf-actions">
          <button id="cf-reload" type="button">Перечитать</button>
          <button id="cf-validate" type="button">Проверить</button>
          <button id="cf-apply" type="submit">Применить</button>
        </div>
      </form>
    `;

    main.append(manage);
  }
}


async function cfLoadMonitoring() {
  const status = document.getElementById("cf-monitor-status");
  if (!status) return;

  const message = document.getElementById("cf-monitor-message");

  try {
    const dashboard = await cfRequest("/api/v1/dashboard");
    const component = dashboard.components?.content_filter;
    const d = component?.details || {};

    status.textContent = String(component?.status || "unknown").toUpperCase();
    message.textContent = component?.message || "Нет данных";

    document.getElementById("cf-monitor-dns").textContent =
      d.dns_enabled ? "ON" : "OFF";

    document.getElementById("cf-monitor-blocked").textContent =
      d.blocked_domains ?? 0;

    document.getElementById("cf-monitor-doh-count").textContent =
      d.managed_doh_addresses ?? "—";

    document.getElementById("cf-monitor-iface").textContent =
      d.listen_interface || "—";

    document.getElementById("cf-monitor-address").textContent =
      d.listen_address || "—";

    document.getElementById("cf-monitor-dot").textContent =
      d.block_dot ? "BLOCK" : "ALLOW";

    document.getElementById("cf-monitor-doq").textContent =
      d.block_doq ? "BLOCK" : "ALLOW";

    document.getElementById("cf-monitor-doh").textContent =
      d.doh_enabled ? "BLOCK" : "ALLOW";

    document.getElementById("cf-monitor-feed").textContent =
      d.managed_doh_feed ? "ON" : "OFF";

    document.getElementById("cf-monitor-updated").textContent =
      d.managed_doh_updated_at || "—";

  } catch (error) {
    status.textContent = "ERROR";
    message.textContent = error.message;
  }
}


function cfBuildPayload() {
  return {
    enabled: document.getElementById("cf-enabled").checked,

    dns: {
      enabled: document.getElementById("cf-dns-enabled").checked,
      listen_interface:
        document.getElementById("cf-listen-interface").value.trim(),
      listen_address:
        document.getElementById("cf-listen-address").value.trim(),
      upstream_servers:
        cfLines(document.getElementById("cf-upstreams").value),
    },

    policy: {
      default_action: "allow",
      blocked_domains:
        cfLines(document.getElementById("cf-blocked").value),
      allowed_domains: [],
    },

    encrypted_dns: {
      block_dot:
        document.getElementById("cf-block-dot").checked,
      block_doq:
        document.getElementById("cf-block-doq").checked,

      doh: {
        enabled:
          document.getElementById("cf-doh-enabled").checked,

        resolver_addresses:
          cfLines(
            document.getElementById("cf-doh-resolvers").value
          ),

        managed_feed_enabled:
          document.getElementById("cf-feed-enabled").checked,

        managed_feed_url:
          document.getElementById("cf-feed-url").value.trim() || null,

        managed_feed_timeout_seconds:
          Number(document.getElementById("cf-feed-timeout").value),

        managed_feed_max_bytes:
          Number(document.getElementById("cf-feed-bytes").value),

        managed_feed_min_addresses:
          Number(document.getElementById("cf-feed-min").value),

        managed_feed_max_addresses:
          Number(document.getElementById("cf-feed-max").value),
      },
    },

    logging: {
      enabled:
        document.getElementById("cf-logging").checked,
    },
  };
}


function cfFillForm(cf) {
  document.getElementById("cf-enabled").checked = cf.enabled;
  document.getElementById("cf-dns-enabled").checked = cf.dns.enabled;

  document.getElementById("cf-listen-interface").value =
    cf.dns.listen_interface;

  document.getElementById("cf-listen-address").value =
    cf.dns.listen_address;

  document.getElementById("cf-upstreams").value =
    (cf.dns.upstream_servers || []).join("\n");

  document.getElementById("cf-blocked").value =
    (cf.policy.blocked_domains || []).join("\n");

  document.getElementById("cf-block-dot").checked =
    cf.encrypted_dns.block_dot;

  document.getElementById("cf-block-doq").checked =
    cf.encrypted_dns.block_doq;

  const doh = cf.encrypted_dns.doh;

  document.getElementById("cf-doh-enabled").checked =
    doh.enabled;

  document.getElementById("cf-doh-resolvers").value =
    (doh.resolver_addresses || []).join("\n");

  document.getElementById("cf-feed-enabled").checked =
    doh.managed_feed_enabled;

  document.getElementById("cf-feed-url").value =
    doh.managed_feed_url || "";

  document.getElementById("cf-feed-timeout").value =
    doh.managed_feed_timeout_seconds;

  document.getElementById("cf-feed-bytes").value =
    doh.managed_feed_max_bytes;

  document.getElementById("cf-feed-min").value =
    doh.managed_feed_min_addresses;

  document.getElementById("cf-feed-max").value =
    doh.managed_feed_max_addresses;

  document.getElementById("cf-logging").checked =
    cf.logging.enabled;
}


async function cfLoadConfig() {
  const state = document.getElementById("cf-config-state");
  if (!state) return;

  state.textContent = "Загрузка…";

  try {
    const data = await cfRequest(
      "/api/v1/content-filter/config"
    );

    cfFillForm(data.content_filter);
    state.textContent = "Загружено";

  } catch (error) {
    state.textContent = "Ошибка";
    document.getElementById("cf-form-message").textContent =
      error.message;
  }
}


async function cfValidateConfig() {
  const message = document.getElementById("cf-form-message");

  message.textContent = "Проверка…";

  try {
    await cfRequest(
      "/api/v1/content-filter/config/validate",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(cfBuildPayload()),
      }
    );

    message.textContent = "Конфигурация корректна.";
    return true;

  } catch (error) {
    message.textContent = `Ошибка: ${error.message}`;
    return false;
  }
}


async function cfApplyConfig(event) {
  event.preventDefault();

  const message = document.getElementById("cf-form-message");

  if (!(await cfValidateConfig())) return;

  message.textContent = "Применение…";

  try {
    const result = await cfRequest(
      "/api/v1/content-filter/config/apply",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(cfBuildPayload()),
      }
    );

    message.textContent =
      `Применено. Заблокированных доменов: ${result.blocked_domains}.`;

    await cfLoadMonitoring();

  } catch (error) {
    message.textContent = `Ошибка применения: ${error.message}`;
  }
}


function cfBindUi() {
  const form = document.getElementById("cf-form");

  if (!form || form.dataset.bound === "true") return;

  form.dataset.bound = "true";

  form.addEventListener("submit", cfApplyConfig);

  document.getElementById("cf-reload")
    ?.addEventListener("click", cfLoadConfig);

  document.getElementById("cf-validate")
    ?.addEventListener("click", cfValidateConfig);

  document.getElementById("cf-monitor-refresh")
    ?.addEventListener("click", cfLoadMonitoring);

  cfLoadConfig();
  cfLoadMonitoring();
}



let idsCurrentConfig = null;


function idsEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


async function idsRequest(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
  });

  let data = null;

  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.detail || `HTTP ${response.status}`
    );
  }

  return data;
}


function idsCreatePages() {
  const main = document.getElementById("app-main");

  if (!main) return;

  if (!main.querySelector(
    '[data-secbox-page="monitor-ids"]'
  )) {
    const monitor = document.createElement("section");

    monitor.className = "panel ids-page";
    monitor.dataset.secboxPage = "monitor-ids";

    monitor.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Обнаружение угроз</p>
          <h2>IDS / IPS</h2>
        </div>
        <button id="ids-monitor-refresh"
                type="button">
          Обновить
        </button>
      </div>

      <div id="ids-monitor-message"></div>

      <div class="ids-status-grid">
        <article class="ids-stat">
          <span>SecBox IDS</span>
          <strong id="ids-runtime-processor">—</strong>
          <small id="ids-runtime-configured">—</small>
        </article>

        <article class="ids-stat">
          <span>Suricata</span>
          <strong id="ids-runtime-suricata">—</strong>
          <small id="ids-runtime-rule-state">—</small>
        </article>

        <article class="ids-stat">
          <span>Alerts</span>
          <strong id="ids-runtime-alerts">—</strong>
          <small id="ids-runtime-suppressed">—</small>
        </article>

        <article class="ids-stat">
          <span>Capture drops</span>
          <strong id="ids-runtime-drops">—</strong>
          <small id="ids-runtime-packets">—</small>
        </article>
      </div>

      <div class="ids-detail-grid">
        <article>
          <h3>Правила</h3>
          <dl class="ids-kv">
            <div>
              <dt>Loaded</dt>
              <dd id="ids-rules-loaded">—</dd>
            </div>
            <div>
              <dt>Failed</dt>
              <dd id="ids-rules-failed">—</dd>
            </div>
            <div>
              <dt>Skipped</dt>
              <dd id="ids-rules-skipped">—</dd>
            </div>
            <div>
              <dt>Last reload</dt>
              <dd id="ids-rules-reload">—</dd>
            </div>
          </dl>
        </article>

        <article>
          <h3>Последнее окно EVE</h3>
          <dl class="ids-kv">
            <div>
              <dt>Размер EVE</dt>
              <dd id="ids-eve-size">—</dd>
            </div>
            <div>
              <dt>Проверено</dt>
              <dd id="ids-eve-window">—</dd>
            </div>
            <div>
              <dt>Alerts в окне</dt>
              <dd id="ids-eve-alerts">—</dd>
            </div>
            <div>
              <dt>Severity</dt>
              <dd id="ids-severity">—</dd>
            </div>
          </dl>
        </article>
      </div>

      <div class="ids-section">
        <h3>Наиболее частые сигнатуры</h3>
        <div id="ids-top-signatures"
             class="ids-signatures"></div>
      </div>

      <div class="ids-section">
        <h3>Последние события</h3>
        <div class="table-wrap">
          <table class="ids-table">
            <thead>
              <tr>
                <th>Время</th>
                <th>Sev</th>
                <th>SID</th>
                <th>Источник</th>
                <th>Назначение</th>
                <th>Сигнатура</th>
              </tr>
            </thead>
            <tbody id="ids-alerts-body"></tbody>
          </table>
        </div>
      </div>
    `;

    main.append(monitor);
  }

  if (!main.querySelector(
    '[data-secbox-page="manage-ids"]'
  )) {
    const manage = document.createElement("section");

    manage.className = "panel ids-page";
    manage.dataset.secboxPage = "manage-ids";

    manage.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Управление</p>
          <h2>IDS / IPS</h2>
        </div>
        <span id="ids-config-state"
              class="tag">
          Загрузка…
        </span>
      </div>

      <div id="ids-config-message"></div>

      <form id="ids-form">
        <div class="ids-form-grid">

          <label class="ids-check ids-wide">
            <input id="ids-enabled"
                   type="checkbox">
            <span>
              SecBox IDS processor включён
            </span>
          </label>

          <label>
            <span>NAT correlation window, ms</span>
            <input id="ids-nat-window"
                   type="number"
                   min="1"
                   max="5000"
                   required>
          </label>

          <label>
            <span>Aggregation window, sec</span>
            <input id="ids-aggregation-window"
                   type="number"
                   min="1"
                   max="3600"
                   required>
          </label>

          <label>
            <span>Минимум событий для ALERT</span>
            <input id="ids-min-alert-count"
                   type="number"
                   min="1"
                   required>
          </label>

          <label>
            <span>Минимум событий для BLOCK</span>
            <input id="ids-min-block-count"
                   type="number"
                   min="1"
                   required>
          </label>

          <label>
            <span>Макс. severity для ALERT</span>
            <select id="ids-max-alert-severity">
              <option value="1">1 — высокая</option>
              <option value="2">2 — средняя</option>
              <option value="3">3 — низкая</option>
            </select>
          </label>

          <label>
            <span>Макс. severity для BLOCK</span>
            <select id="ids-max-block-severity">
              <option value="1">1 — высокая</option>
              <option value="2">2 — средняя</option>
              <option value="3">3 — низкая</option>
            </select>
          </label>

          <label class="ids-check ids-wide">
            <input id="ids-auto-blackhole"
                   type="checkbox">
            <span>
              Автоматический Dynamic Blackhole
            </span>
          </label>

          <label>
            <span>Blackhole timeout</span>
            <input id="ids-blackhole-timeout"
                   type="text"
                   maxlength="32"
                   placeholder="15m"
                   required>
          </label>

          <label>
            <span>EVE log</span>
            <input id="ids-eve-path"
                   type="text"
                   readonly>
          </label>

        </div>

        <div class="ids-warning">
          Автоблокировка применяется только к
          повторным входящим WAN-событиям,
          прошедшим policy thresholds.
          Адреса SecBox и protected networks
          не блокируются.
        </div>

        <div class="ids-actions">
          <button id="ids-reload"
                  type="button">
            Перечитать
          </button>

          <button id="ids-validate"
                  type="button">
            Проверить
          </button>

          <button id="ids-apply"
                  type="submit">
            Применить
          </button>
        </div>
      </form>
    `;

    main.append(manage);
  }
}


function idsFormatBytes(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  if (number < 1024) {
    return `${number} B`;
  }

  if (number < 1024 * 1024) {
    return `${(number / 1024).toFixed(1)} KiB`;
  }

  return `${(
    number / 1024 / 1024
  ).toFixed(1)} MiB`;
}


async function idsLoadMonitoring() {
  const message = document.getElementById(
    "ids-monitor-message"
  );

  if (!message) return;

  message.textContent = "Обновление…";
  message.className = "";

  try {
    const data = await idsRequest(
      "/api/v1/ids/runtime"
    );

    const runtime = data.runtime || {};
    const services = runtime.services || {};
    const stats = runtime.stats || {};

    const processor = services.ids || {};
    const suricata = services.suricata || {};

    document.getElementById(
      "ids-runtime-processor"
    ).textContent =
      `${processor.active_state || "unknown"} / ` +
      `${processor.sub_state || "unknown"}`;

    document.getElementById(
      "ids-runtime-configured"
    ).textContent =
      runtime.configured_enabled
        ? "Настроен как enabled"
        : "Настроен как disabled";

    document.getElementById(
      "ids-runtime-suricata"
    ).textContent =
      `${suricata.active_state || "unknown"} / ` +
      `${suricata.sub_state || "unknown"}`;

    document.getElementById(
      "ids-runtime-rule-state"
    ).textContent =
      stats.rules_failed === 0
        ? "Ruleset загружен без ошибок"
        : `${stats.rules_failed ?? "—"} ошибок ruleset`;

    document.getElementById(
      "ids-runtime-alerts"
    ).textContent =
      stats.alerts ?? "—";

    document.getElementById(
      "ids-runtime-suppressed"
    ).textContent =
      `Suppressed: ${stats.alerts_suppressed ?? "—"}`;

    document.getElementById(
      "ids-runtime-drops"
    ).textContent =
      stats.kernel_drops ?? "—";

    document.getElementById(
      "ids-runtime-packets"
    ).textContent =
      `Packets: ${stats.kernel_packets ?? "—"} · ` +
      `${stats.kernel_drop_percent ?? "—"}%`;

    document.getElementById(
      "ids-rules-loaded"
    ).textContent =
      stats.rules_loaded ?? "—";

    document.getElementById(
      "ids-rules-failed"
    ).textContent =
      stats.rules_failed ?? "—";

    document.getElementById(
      "ids-rules-skipped"
    ).textContent =
      stats.rules_skipped ?? "—";

    document.getElementById(
      "ids-rules-reload"
    ).textContent =
      stats.last_rule_reload || "—";

    document.getElementById(
      "ids-eve-size"
    ).textContent =
      idsFormatBytes(
        runtime.eve_size_bytes
      );

    document.getElementById(
      "ids-eve-window"
    ).textContent =
      idsFormatBytes(
        runtime.sample_window_bytes
      );

    document.getElementById(
      "ids-eve-alerts"
    ).textContent =
      runtime.sampled_alert_count ?? "—";

    const severities =
      runtime.severity_counts || {};

    document.getElementById(
      "ids-severity"
    ).textContent =
      `1: ${severities["1"] || 0} · ` +
      `2: ${severities["2"] || 0} · ` +
      `3: ${severities["3"] || 0}`;

    const signatures =
      document.getElementById(
        "ids-top-signatures"
      );

    signatures.innerHTML = "";

    for (
      const item
      of runtime.top_signatures || []
    ) {
      const node =
        document.createElement("div");

      node.className =
        "ids-signature-row";

      node.innerHTML =
        `<span>${idsEscape(item.signature)}</span>` +
        `<strong>${Number(item.count) || 0}</strong>`;

      signatures.append(node);
    }

    if (!signatures.children.length) {
      signatures.textContent =
        "В выбранном окне alerts отсутствуют.";
    }

    const body =
      document.getElementById(
        "ids-alerts-body"
      );

    body.innerHTML = "";

    for (
      const alert
      of runtime.recent_alerts || []
    ) {
      const row =
        document.createElement("tr");

      const source =
        `${alert.source_ip || "—"}` +
        `${alert.source_port != null
          ? `:${alert.source_port}`
          : ""}`;

      const destination =
        `${alert.destination_ip || "—"}` +
        `${alert.destination_port != null
          ? `:${alert.destination_port}`
          : ""}`;

      row.innerHTML = `
        <td>${idsEscape(alert.timestamp || "—")}</td>
        <td>${idsEscape(alert.severity ?? "—")}</td>
        <td>${idsEscape(alert.signature_id ?? "—")}</td>
        <td>${idsEscape(source)}</td>
        <td>${idsEscape(destination)}</td>
        <td>${idsEscape(alert.signature || "—")}</td>
      `;

      body.append(row);
    }

    if (!body.children.length) {
      const row =
        document.createElement("tr");

      row.innerHTML =
        '<td colspan="6">Alerts отсутствуют.</td>';

      body.append(row);
    }

    message.textContent =
      "Runtime актуален.";

    message.className = "good";

  } catch (error) {
    message.textContent =
      `Ошибка IDS runtime: ${error.message}`;

    message.className = "error";
  }
}


function idsBuildCandidate() {
  if (!idsCurrentConfig) {
    throw new Error(
      "IDS configuration is not loaded"
    );
  }

  return {
    ...idsCurrentConfig,

    enabled:
      document.getElementById(
        "ids-enabled"
      ).checked,

    nat_correlation_window_ms:
      Number(
        document.getElementById(
          "ids-nat-window"
        ).value
      ),

    aggregation_window_seconds:
      Number(
        document.getElementById(
          "ids-aggregation-window"
        ).value
      ),

    policy: {
      minimum_alert_count:
        Number(
          document.getElementById(
            "ids-min-alert-count"
          ).value
        ),

      minimum_block_count:
        Number(
          document.getElementById(
            "ids-min-block-count"
          ).value
        ),

      maximum_alert_severity:
        Number(
          document.getElementById(
            "ids-max-alert-severity"
          ).value
        ),

      maximum_block_severity:
        Number(
          document.getElementById(
            "ids-max-block-severity"
          ).value
        ),
    },

    automatic_blackhole: {
      enabled:
        document.getElementById(
          "ids-auto-blackhole"
        ).checked,

      timeout:
        document.getElementById(
          "ids-blackhole-timeout"
        ).value.trim(),
    },
  };
}


async function idsLoadConfig() {
  const message =
    document.getElementById(
      "ids-config-message"
    );

  const state =
    document.getElementById(
      "ids-config-state"
    );

  if (!message || !state) return;

  state.textContent = "Загрузка…";

  try {
    const data = await idsRequest(
      "/api/v1/ids/config"
    );

    idsCurrentConfig = data.ids;

    document.getElementById(
      "ids-enabled"
    ).checked =
      Boolean(data.ids.enabled);

    document.getElementById(
      "ids-nat-window"
    ).value =
      data.ids.nat_correlation_window_ms;

    document.getElementById(
      "ids-aggregation-window"
    ).value =
      data.ids.aggregation_window_seconds;

    document.getElementById(
      "ids-min-alert-count"
    ).value =
      data.ids.policy.minimum_alert_count;

    document.getElementById(
      "ids-min-block-count"
    ).value =
      data.ids.policy.minimum_block_count;

    document.getElementById(
      "ids-max-alert-severity"
    ).value =
      data.ids.policy.maximum_alert_severity;

    document.getElementById(
      "ids-max-block-severity"
    ).value =
      data.ids.policy.maximum_block_severity;

    document.getElementById(
      "ids-auto-blackhole"
    ).checked =
      Boolean(
        data.ids
          .automatic_blackhole
          .enabled
      );

    document.getElementById(
      "ids-blackhole-timeout"
    ).value =
      data.ids
        .automatic_blackhole
        .timeout;

    document.getElementById(
      "ids-eve-path"
    ).value =
      data.ids.eve_path;

    state.textContent = "Загружено";

    message.textContent =
      "Текущая конфигурация IDS загружена.";

    message.className = "good";

  } catch (error) {
    state.textContent = "Ошибка";

    message.textContent =
      error.message;

    message.className = "error";
  }
}


async function idsValidateConfig() {
  const message =
    document.getElementById(
      "ids-config-message"
    );

  try {
    const candidate =
      idsBuildCandidate();

    await idsRequest(
      "/api/v1/ids/config/validate",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          candidate
        ),
      }
    );

    message.textContent =
      "Конфигурация IDS корректна.";

    message.className = "good";

  } catch (error) {
    message.textContent =
      `Ошибка проверки: ${error.message}`;

    message.className = "error";
  }
}


async function idsApplyConfig(event) {
  event.preventDefault();

  const message =
    document.getElementById(
      "ids-config-message"
    );

  const button =
    document.getElementById(
      "ids-apply"
    );

  button.disabled = true;

  try {
    const candidate =
      idsBuildCandidate();

    await idsRequest(
      "/api/v1/ids/config/apply",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          candidate
        ),
      }
    );

    idsCurrentConfig =
      candidate;

    message.textContent =
      "IDS configuration применена.";

    message.className = "good";

    await Promise.all([
      idsLoadConfig(),
      idsLoadMonitoring(),
    ]);

  } catch (error) {
    message.textContent =
      `Ошибка применения: ${error.message}`;

    message.className = "error";

  } finally {
    button.disabled = false;
  }
}


function idsBindUi() {
  const form =
    document.getElementById(
      "ids-form"
    );

  if (!form) return;

  form.addEventListener(
    "submit",
    idsApplyConfig
  );

  document.getElementById(
    "ids-reload"
  )?.addEventListener(
    "click",
    idsLoadConfig
  );

  document.getElementById(
    "ids-validate"
  )?.addEventListener(
    "click",
    idsValidateConfig
  );

  document.getElementById(
    "ids-monitor-refresh"
  )?.addEventListener(
    "click",
    idsLoadMonitoring
  );

  idsLoadConfig();
  idsLoadMonitoring();
}



// ============================================================
// Dynamic Blackhole UI
// ============================================================

let bhPollTimer = null;


function bhEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}


async function bhRequest(
  url,
  options = {}
) {
  const response = await fetch(
    url,
    {
      credentials: "same-origin",
      ...options,
    }
  );

  let data = null;

  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.detail ||
      `HTTP ${response.status}`
    );
  }

  return data;
}


function bhFormatDuration(seconds) {
  const value = Number(seconds);

  if (!Number.isFinite(value)) {
    return "—";
  }

  if (value <= 0) {
    return "expired";
  }

  const hours = Math.floor(
    value / 3600
  );

  const minutes = Math.floor(
    (value % 3600) / 60
  );

  const secs = Math.floor(
    value % 60
  );

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }

  return `${secs}s`;
}


function bhCreatePages() {
  const main =
    document.getElementById(
      "app-main"
    );

  if (!main) {
    return;
  }

  if (!main.querySelector(
    '[data-secbox-page="monitor-blackhole"]'
  )) {
    const page =
      document.createElement(
        "section"
      );

    page.className =
      "panel bh-page";

    page.dataset.secboxPage =
      "monitor-blackhole";

    page.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            Dynamic Blackhole
          </p>
          <h2>Мониторинг блокировок</h2>
        </div>

        <button
          id="bh-monitor-refresh"
          type="button"
        >
          Обновить
        </button>
      </div>

      <p
        id="bh-monitor-message"
        class="hint"
      >
        Загрузка…
      </p>

      <div class="bh-status-grid">
        <article>
          <span>Состояние</span>
          <strong id="bh-enabled">—</strong>
        </article>

        <article>
          <span>nft runtime</span>
          <strong id="bh-runtime-count">—</strong>
        </article>

        <article>
          <span>Persistent</span>
          <strong id="bh-persistent-count">—</strong>
        </article>

        <article>
          <span>Consistency</span>
          <strong id="bh-consistency">—</strong>
        </article>
      </div>

      <div class="bh-section">
        <h3>Protected networks</h3>
        <div
          id="bh-protected"
          class="bh-protected"
        ></div>
      </div>

      <div class="bh-section">
        <h3>Активные блокировки</h3>

        <div class="table-wrap">
          <table class="bh-table">
            <thead>
              <tr>
                <th>IPv4</th>
                <th>Источник</th>
                <th>Причина</th>
                <th>Создано</th>
                <th>Истекает</th>
                <th>TTL</th>
                <th>nft</th>
              </tr>
            </thead>

            <tbody
              id="bh-monitor-body"
            ></tbody>
          </table>
        </div>
      </div>
    `;

    main.append(page);
  }

  if (!main.querySelector(
    '[data-secbox-page="manage-blackhole"]'
  )) {
    const page =
      document.createElement(
        "section"
      );

    page.className =
      "panel bh-page";

    page.dataset.secboxPage =
      "manage-blackhole";

    page.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            Dynamic Blackhole
          </p>
          <h2>Управление блокировками</h2>
        </div>

        <button
          id="bh-manage-refresh"
          type="button"
        >
          Перечитать
        </button>
      </div>

      <p
        id="bh-manage-message"
        class="hint"
      ></p>

      <form id="bh-add-form">
        <div class="bh-form-grid">
          <label>
            <span>IPv4 address</span>
            <input
              id="bh-address"
              type="text"
              placeholder="203.0.113.10"
              required
            >
          </label>

          <label>
            <span>Timeout</span>
            <input
              id="bh-timeout"
              type="text"
              placeholder="1h"
              required
            >
          </label>

          <label class="bh-wide">
            <span>Причина</span>
            <input
              id="bh-reason"
              type="text"
              maxlength="160"
              value="manual"
              required
            >
          </label>
        </div>

        <div class="bh-actions">
          <button
            type="submit"
            id="bh-add"
          >
            Добавить блокировку
          </button>

          <button
            type="button"
            id="bh-reconcile"
            class="secondary"
          >
            Reconcile
          </button>
        </div>
      </form>

      <div class="bh-warning">
        Локальные адреса SecBox и protected networks
        проверяются повторно root action helper'ом.
        Web-процесс не изменяет nftables напрямую.
      </div>

      <div class="bh-section">
        <h3>Текущие записи</h3>

        <div class="table-wrap">
          <table class="bh-table">
            <thead>
              <tr>
                <th>IPv4</th>
                <th>Источник</th>
                <th>Причина</th>
                <th>TTL</th>
                <th>nft</th>
                <th></th>
              </tr>
            </thead>

            <tbody
              id="bh-manage-body"
            ></tbody>
          </table>
        </div>
      </div>
    `;

    main.append(page);
  }
}


function bhCell(
  row,
  value
) {
  const cell =
    document.createElement(
      "td"
    );

  cell.textContent =
    String(
      value ?? "—"
    );

  row.append(cell);

  return cell;
}


function bhRenderRuntime(runtime) {
  const enabled =
    document.getElementById(
      "bh-enabled"
    );

  if (enabled) {
    enabled.textContent =
      runtime.enabled
        ? "Enabled"
        : "Disabled";
  }

  const runtimeCount =
    document.getElementById(
      "bh-runtime-count"
    );

  if (runtimeCount) {
    runtimeCount.textContent =
      runtime.runtime_count ?? "—";
  }

  const persistentCount =
    document.getElementById(
      "bh-persistent-count"
    );

  if (persistentCount) {
    persistentCount.textContent =
      runtime.persistent_count ?? "—";
  }

  const consistency =
    document.getElementById(
      "bh-consistency"
    );

  if (consistency) {
    consistency.textContent =
      runtime.consistent
        ? "OK"
        : "Mismatch";

    consistency.className =
      runtime.consistent
        ? "good"
        : "error";
  }

  const protectedBox =
    document.getElementById(
      "bh-protected"
    );

  if (protectedBox) {
    protectedBox.replaceChildren();

    for (
      const network
      of runtime.protected_networks || []
    ) {
      const tag =
        document.createElement(
          "code"
        );

      tag.textContent =
        network;

      protectedBox.append(
        tag
      );
    }

    if (
      !protectedBox.children.length
    ) {
      protectedBox.textContent =
        "Не настроены";
    }
  }

  const timeout =
    document.getElementById(
      "bh-timeout"
    );

  if (
    timeout &&
    !timeout.dataset.userChanged
  ) {
    timeout.value =
      runtime.default_timeout || "1h";
  }

  bhRenderMonitorTable(
    runtime.entries || []
  );

  bhRenderManageTable(
    runtime.entries || []
  );
}


function bhRenderMonitorTable(entries) {
  const body =
    document.getElementById(
      "bh-monitor-body"
    );

  if (!body) {
    return;
  }

  body.replaceChildren();

  for (const entry of entries) {
    const row =
      document.createElement(
        "tr"
      );

    bhCell(
      row,
      entry.address
    );

    bhCell(
      row,
      entry.source
    );

    bhCell(
      row,
      entry.reason
    );

    bhCell(
      row,
      entry.created_at
    );

    bhCell(
      row,
      entry.expires_at
    );

    bhCell(
      row,
      bhFormatDuration(
        entry.remaining_seconds
      )
    );

    bhCell(
      row,
      entry.runtime_present
        ? "present"
        : "missing"
    );

    body.append(row);
  }

  if (!entries.length) {
    const row =
      document.createElement(
        "tr"
      );

    const cell =
      document.createElement(
        "td"
      );

    cell.colSpan = 7;

    cell.textContent =
      "Активных блокировок нет.";

    row.append(cell);
    body.append(row);
  }
}


function bhRenderManageTable(entries) {
  const body =
    document.getElementById(
      "bh-manage-body"
    );

  if (!body) {
    return;
  }

  body.replaceChildren();

  for (const entry of entries) {
    const row =
      document.createElement(
        "tr"
      );

    bhCell(
      row,
      entry.address
    );

    bhCell(
      row,
      entry.source
    );

    bhCell(
      row,
      entry.reason
    );

    bhCell(
      row,
      bhFormatDuration(
        entry.remaining_seconds
      )
    );

    bhCell(
      row,
      entry.runtime_present
        ? "present"
        : "missing"
    );

    const actionCell =
      document.createElement(
        "td"
      );

    const button =
      document.createElement(
        "button"
      );

    button.type =
      "button";

    button.className =
      "secondary";

    button.textContent =
      "Удалить";

    button.addEventListener(
      "click",
      async () => {
        await bhDelete(
          entry.address
        );
      }
    );

    actionCell.append(
      button
    );

    row.append(
      actionCell
    );

    body.append(row);
  }

  if (!entries.length) {
    const row =
      document.createElement(
        "tr"
      );

    const cell =
      document.createElement(
        "td"
      );

    cell.colSpan = 6;

    cell.textContent =
      "Записей нет.";

    row.append(cell);
    body.append(row);
  }
}


async function bhLoadRuntime() {
  const monitorMessage =
    document.getElementById(
      "bh-monitor-message"
    );

  const manageMessage =
    document.getElementById(
      "bh-manage-message"
    );

  try {
    const data =
      await bhRequest(
        "/api/v1/blackhole/runtime"
      );

    bhRenderRuntime(
      data.runtime || {}
    );

    if (monitorMessage) {
      monitorMessage.textContent =
        "Runtime актуален.";

      monitorMessage.className =
        "good";
    }

    if (manageMessage) {
      manageMessage.textContent =
        "Состояние загружено.";

      manageMessage.className =
        "good";
    }

  } catch (error) {
    if (monitorMessage) {
      monitorMessage.textContent =
        `Ошибка: ${error.message}`;

      monitorMessage.className =
        "error";
    }

    if (manageMessage) {
      manageMessage.textContent =
        `Ошибка: ${error.message}`;

      manageMessage.className =
        "error";
    }
  }
}


async function bhAdd(event) {
  event.preventDefault();

  const message =
    document.getElementById(
      "bh-manage-message"
    );

  const button =
    document.getElementById(
      "bh-add"
    );

  button.disabled = true;

  try {
    await bhRequest(
      "/api/v1/blackhole/add",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          {
            address:
              document.getElementById(
                "bh-address"
              ).value.trim(),

            timeout:
              document.getElementById(
                "bh-timeout"
              ).value.trim(),

            reason:
              document.getElementById(
                "bh-reason"
              ).value.trim(),
          }
        ),
      }
    );

    document.getElementById(
      "bh-address"
    ).value = "";

    message.textContent =
      "Блокировка добавлена.";

    message.className =
      "good";

    await bhLoadRuntime();

  } catch (error) {
    message.textContent =
      `Ошибка добавления: ${error.message}`;

    message.className =
      "error";

  } finally {
    button.disabled = false;
  }
}


async function bhDelete(address) {
  const message =
    document.getElementById(
      "bh-manage-message"
    );

  try {
    await bhRequest(
      "/api/v1/blackhole/delete",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          {
            address,
          }
        ),
      }
    );

    if (message) {
      message.textContent =
        `Удалено: ${address}`;

      message.className =
        "good";
    }

    await bhLoadRuntime();

  } catch (error) {
    if (message) {
      message.textContent =
        `Ошибка удаления: ${error.message}`;

      message.className =
        "error";
    }
  }
}


async function bhReconcile() {
  const message =
    document.getElementById(
      "bh-manage-message"
    );

  try {
    const result =
      await bhRequest(
        "/api/v1/blackhole/reconcile",
        {
          method: "POST",
        }
      );

    if (message) {
      message.textContent =
        `Reconcile завершён: restored ${result.restored}, ` +
        `expired ${result.expired_removed}.`;

      message.className =
        "good";
    }

    await bhLoadRuntime();

  } catch (error) {
    if (message) {
      message.textContent =
        `Ошибка reconcile: ${error.message}`;

      message.className =
        "error";
    }
  }
}


function bhBindUi() {
  const monitor =
    document.querySelector(
      '[data-secbox-page="monitor-blackhole"]'
    );

  const manage =
    document.querySelector(
      '[data-secbox-page="manage-blackhole"]'
    );

  if (
    monitor &&
    monitor.dataset.bound !== "true"
  ) {
    monitor.dataset.bound =
      "true";

    document.getElementById(
      "bh-monitor-refresh"
    )?.addEventListener(
      "click",
      bhLoadRuntime
    );
  }

  if (
    manage &&
    manage.dataset.bound !== "true"
  ) {
    manage.dataset.bound =
      "true";

    document.getElementById(
      "bh-add-form"
    )?.addEventListener(
      "submit",
      bhAdd
    );

    document.getElementById(
      "bh-manage-refresh"
    )?.addEventListener(
      "click",
      bhLoadRuntime
    );

    document.getElementById(
      "bh-reconcile"
    )?.addEventListener(
      "click",
      bhReconcile
    );

    document.getElementById(
      "bh-timeout"
    )?.addEventListener(
      "input",
      (event) => {
        event.target.dataset.userChanged =
          "true";
      }
    );
  }

  if (monitor || manage) {
    bhLoadRuntime();

    if (!bhPollTimer) {
      bhPollTimer =
        window.setInterval(
          bhLoadRuntime,
          10000
        );
    }
  }
}



// ============================================================
// System Monitoring / Management
// ============================================================

let sysPollTimer = null;


function sysBytes(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  const units = [
    "B",
    "KiB",
    "MiB",
    "GiB",
    "TiB",
  ];

  let current = number;
  let index = 0;

  while (
    current >= 1024 &&
    index < units.length - 1
  ) {
    current /= 1024;
    index += 1;
  }

  return (
    `${current.toFixed(
      index === 0 ? 0 : 1
    )} ${units[index]}`
  );
}


function sysDuration(seconds) {
  let value = Math.max(
    0,
    Number(seconds) || 0
  );

  const days = Math.floor(
    value / 86400
  );

  value %= 86400;

  const hours = Math.floor(
    value / 3600
  );

  value %= 3600;

  const minutes = Math.floor(
    value / 60
  );

  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  }

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  return `${minutes}m`;
}


async function sysRequest(
  url,
  options = {}
) {
  const response = await fetch(
    url,
    {
      credentials: "same-origin",
      ...options,
    }
  );

  let data = null;

  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }

  if (!response.ok) {
    throw new Error(
      data?.detail ||
      `HTTP ${response.status}`
    );
  }

  return data;
}


function sysCreatePages() {
  const main =
    document.getElementById(
      "app-main"
    );

  if (!main) {
    return;
  }

  if (!main.querySelector(
    '[data-secbox-page="monitor-system"]'
  )) {
    const page =
      document.createElement(
        "section"
      );

    page.className =
      "panel sys-page";

    page.dataset.secboxPage =
      "monitor-system";

    page.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            SecBox host
          </p>
          <h2>Состояние системы</h2>
        </div>

        <button
          id="sys-refresh"
          type="button"
        >
          Обновить
        </button>
      </div>

      <p
        id="sys-message"
        class="hint"
      >
        Загрузка…
      </p>

      <div class="sys-metrics">
        <article>
          <span>CPU</span>
          <strong id="sys-cpu">—</strong>
          <small id="sys-load">—</small>
        </article>

        <article>
          <span>RAM</span>
          <strong id="sys-memory">—</strong>
          <small id="sys-memory-detail">—</small>
        </article>

        <article>
          <span>Root FS</span>
          <strong id="sys-disk">—</strong>
          <small id="sys-disk-detail">—</small>
        </article>

        <article>
          <span>Uptime</span>
          <strong id="sys-uptime">—</strong>
          <small id="sys-hostname">—</small>
        </article>
      </div>

      <div class="sys-details">
        <article>
          <span>SecBox</span>
          <strong id="sys-version">—</strong>
        </article>

        <article>
          <span>OS</span>
          <strong id="sys-os">—</strong>
        </article>

        <article>
          <span>Kernel</span>
          <strong id="sys-kernel">—</strong>
        </article>

        <article>
          <span>Swap</span>
          <strong id="sys-swap">—</strong>
        </article>

        <article>
          <span>Journal</span>
          <strong id="sys-journal">—</strong>
        </article>

        <article>
          <span>Reboot required</span>
          <strong id="sys-reboot-required">—</strong>
        </article>
      </div>

      <div class="sys-section">
        <div class="section-heading">
          <div>
            <h3>Температуры</h3>
          </div>
        </div>

        <div
          id="sys-temperatures"
          class="sys-temperature-list"
        ></div>
      </div>

      <div class="sys-section">
        <div class="section-heading">
          <div>
            <h3>Failed systemd units</h3>
          </div>

          <span
            id="sys-failed-count"
            class="tag"
          >
            —
          </span>
        </div>

        <div
          id="sys-failed-units"
          class="sys-failed-list"
        ></div>
      </div>
    `;

    main.append(
      page
    );
  }

  if (!main.querySelector(
    '[data-secbox-system-management="true"]'
  )) {
    const page =
      document.createElement(
        "section"
      );

    page.className =
      "panel sys-page sys-danger-zone";

    page.dataset.secboxPage =
      "manage-system";

    page.dataset.secboxSystemManagement =
      "true";

    page.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">
            Управление системой
          </p>
          <h2>Power control</h2>
        </div>
      </div>

      <p class="hint">
        Управление отдельными службами выполняется
        в разделе «Службы». Здесь доступны только
        операции над самим хостом SecBox.
      </p>

      <div class="sys-power-grid">
        <article>
          <strong>Перезагрузка</strong>

          <p>
            Корректно перезагрузить SecBox.
            Сетевые соединения будут прерваны.
          </p>

          <button
            id="sys-reboot"
            type="button"
          >
            Reboot
          </button>
        </article>

        <article>
          <strong>Выключение</strong>

          <p>
            Корректно выключить хост SecBox.
            Для запуска потребуется доступ
            к гипервизору или физической машине.
          </p>

          <button
            id="sys-poweroff"
            type="button"
            class="secondary"
          >
            Power off
          </button>
        </article>
      </div>

      <p
        id="sys-power-message"
        class="hint"
        role="status"
      ></p>
    `;

    main.prepend(
      page
    );
  }
}


function sysRender(runtime) {
  const cpu =
    runtime.cpu || {};

  const memory =
    runtime.memory || {};

  const swap =
    runtime.swap || {};

  const disk =
    runtime.root_filesystem || {};

  const load =
    Array.isArray(
      cpu.load_average
    )
      ? cpu.load_average.join(" / ")
      : "—";

  const cpuValue =
    cpu.used_percent == null
      ? "—"
      : `${cpu.used_percent}%`;

  document.getElementById(
    "sys-cpu"
  ).textContent =
    cpuValue;

  document.getElementById(
    "sys-load"
  ).textContent =
    `Load: ${load}`;

  document.getElementById(
    "sys-memory"
  ).textContent =
    `${memory.used_percent ?? "—"}%`;

  document.getElementById(
    "sys-memory-detail"
  ).textContent =
    `${sysBytes(memory.used_bytes)} / ` +
    `${sysBytes(memory.total_bytes)}`;

  document.getElementById(
    "sys-disk"
  ).textContent =
    `${disk.used_percent ?? "—"}%`;

  document.getElementById(
    "sys-disk-detail"
  ).textContent =
    `${sysBytes(disk.used_bytes)} / ` +
    `${sysBytes(disk.total_bytes)}`;

  document.getElementById(
    "sys-uptime"
  ).textContent =
    sysDuration(
      runtime.uptime_seconds
    );

  document.getElementById(
    "sys-hostname"
  ).textContent =
    runtime.hostname || "—";

  document.getElementById(
    "sys-version"
  ).textContent =
    runtime.secbox_version || "—";

  document.getElementById(
    "sys-os"
  ).textContent =
    runtime.os?.name || "—";

  document.getElementById(
    "sys-kernel"
  ).textContent =
    `${runtime.kernel?.release || "—"} ` +
    `${runtime.kernel?.machine || ""}`;

  document.getElementById(
    "sys-swap"
  ).textContent =
    swap.total_bytes
      ? (
          `${swap.used_percent}% · ` +
          `${sysBytes(swap.used_bytes)} / ` +
          `${sysBytes(swap.total_bytes)}`
        )
      : "Disabled";

  document.getElementById(
    "sys-journal"
  ).textContent =
    runtime.journal_bytes == null
      ? "—"
      : sysBytes(
          runtime.journal_bytes
        );

  const reboot =
    document.getElementById(
      "sys-reboot-required"
    );

  reboot.textContent =
    runtime.reboot_required
      ? "YES"
      : "NO";

  reboot.className =
    runtime.reboot_required
      ? "error"
      : "good";

  const failed =
    runtime.failed_units || [];

  document.getElementById(
    "sys-failed-count"
  ).textContent =
    String(
      runtime.failed_unit_count ?? 0
    );

  const failedBox =
    document.getElementById(
      "sys-failed-units"
    );

  failedBox.replaceChildren();

  if (!failed.length) {
    const item =
      document.createElement(
        "p"
      );

    item.className =
      "good";

    item.textContent =
      "Failed units отсутствуют.";

    failedBox.append(
      item
    );

  } else {
    for (const unit of failed) {
      const item =
        document.createElement(
          "article"
        );

      const title =
        document.createElement(
          "strong"
        );

      title.textContent =
        unit.unit || "unknown";

      const detail =
        document.createElement(
          "span"
        );

      detail.textContent =
        `${unit.active || "—"} / ` +
        `${unit.sub || "—"} · ` +
        `${unit.description || ""}`;

      item.append(
        title,
        detail
      );

      failedBox.append(
        item
      );
    }
  }

  const temperatureBox =
    document.getElementById(
      "sys-temperatures"
    );

  temperatureBox.replaceChildren();

  const temperatures =
    runtime.temperatures || [];

  if (!temperatures.length) {
    const item =
      document.createElement(
        "p"
      );

    item.className =
      "hint";

    item.textContent =
      "Датчики температуры недоступны.";

    temperatureBox.append(
      item
    );

  } else {
    for (
      const temperature
      of temperatures
    ) {
      const item =
        document.createElement(
          "article"
        );

      const name =
        document.createElement(
          "span"
        );

      name.textContent =
        temperature.label;

      const value =
        document.createElement(
          "strong"
        );

      value.textContent =
        `${temperature.celsius} °C`;

      item.append(
        name,
        value
      );

      temperatureBox.append(
        item
      );
    }
  }
}


async function sysLoadRuntime() {
  const message =
    document.getElementById(
      "sys-message"
    );

  if (!message) {
    return;
  }

  try {
    const data =
      await sysRequest(
        "/api/v1/system/runtime"
      );

    sysRender(
      data.runtime || {}
    );

    message.textContent =
      "Системная телеметрия актуальна.";

    message.className =
      "good";

  } catch (error) {
    message.textContent =
      `Ошибка: ${error.message}`;

    message.className =
      "error";
  }
}


async function sysPower(
  operation
) {
  const required =
    operation === "reboot"
      ? "REBOOT"
      : "POWEROFF";

  const label =
    operation === "reboot"
      ? "перезагрузки"
      : "выключения";

  const confirmation =
    window.prompt(
      `Для подтверждения ${label} ` +
      `введите ${required}`
    );

  if (
    confirmation === null
  ) {
    return;
  }

  const message =
    document.getElementById(
      "sys-power-message"
    );

  if (
    confirmation !== required
  ) {
    message.textContent =
      `Операция отменена: требуется ${required}.`;

    message.className =
      "error";

    return;
  }

  try {
    const result =
      await sysRequest(
        "/api/v1/system/power",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify(
            {
              operation,
              confirmation,
            }
          ),
        }
      );

    message.textContent =
      result.accepted
        ? (
            `Операция ${operation} принята. ` +
            "Соединение с Web Console скоро будет потеряно."
          )
        : "Операция не принята.";

    message.className =
      result.accepted
        ? "good"
        : "error";

  } catch (error) {
    message.textContent =
      `Ошибка: ${error.message}`;

    message.className =
      "error";
  }
}


function sysBindUi() {
  const monitor =
    document.querySelector(
      '[data-secbox-page="monitor-system"]'
    );

  const management =
    document.querySelector(
      '[data-secbox-system-management="true"]'
    );

  if (
    monitor &&
    monitor.dataset.bound !== "true"
  ) {
    monitor.dataset.bound =
      "true";

    document.getElementById(
      "sys-refresh"
    )?.addEventListener(
      "click",
      sysLoadRuntime
    );
  }

  if (
    management &&
    management.dataset.bound !== "true"
  ) {
    management.dataset.bound =
      "true";

    document.getElementById(
      "sys-reboot"
    )?.addEventListener(
      "click",
      () => sysPower(
        "reboot"
      )
    );

    document.getElementById(
      "sys-poweroff"
    )?.addEventListener(
      "click",
      () => sysPower(
        "poweroff"
      )
    );
  }

  if (monitor) {
    sysLoadRuntime();

    if (!sysPollTimer) {
      sysPollTimer =
        window.setInterval(
          sysLoadRuntime,
          10000
        );
    }
  }
}


function secboxClassifyPages() {
  const main = document.getElementById("app-main");

  if (!main) return;

  secboxCreateContentFilterPages();
  cfBindUi();

  fwCreatePages();
  fwBindUi();

  idsCreatePages();
  idsBindUi();

  bhCreatePages();
  bhBindUi();

  sysCreatePages();
  sysBindUi();

  // Overview
  [
    "header#overview",
    ".health-grid",
    ".metrics",
    "#attention-panel",
  ].forEach((selector) => {
    document.querySelectorAll(selector).forEach((node) => {
      node.dataset.secboxPage = "overview";
    });
  });

  // Runtime VPN -> Monitoring / VPN
  const vpn = document.getElementById("vpn");

  if (vpn) {
    vpn.dataset.secboxPage = "monitor-vpn";
  }



  // Services -> monitoring.
  const services = document.getElementById("services");

  if (services) {
    services.dataset.secboxPage = "monitor-services";
  }

  // Raw configuration -> management/system.
  const configuration = document.getElementById("configuration");

  if (configuration) {
    configuration.dataset.secboxPage = "manage-system";
  }

  const globalMessage = document.getElementById("global-message");

  if (globalMessage) {
    globalMessage.dataset.secboxGlobal = "true";
  }

  const placeholders = [
    [
      "monitor-network",
      "Сеть",
      "Оперативное состояние интерфейсов, адресов, маршрутов и сетевых связей SecBox."
    ],
    [
      "monitor-firewall",
      "Firewall",
      "Состояние nftables, counters, активный ruleset и события фильтрации."
    ],
    [
      "monitor-ids",
      "IDS / IPS",
      "Состояние Suricata, события безопасности и статистика обнаруженных угроз."
    ],
    [
      "monitor-blackhole",
      "Dynamic Blackhole",
      "Активные динамические блокировки, причины, TTL и статистика."
    ],
    [
      "monitor-content-filter",
      "Content Filter",
      "Состояние фильтрации, категории, блокировки и статистика."
    ],
    [
      "monitor-system",
      "Система",
      "CPU, RAM, диски, uptime, журналы и общее состояние SecBox."
    ],
    [
      "manage-dhcp",
      "DHCP / DNS",
      "Управление DHCP scopes, DNS и параметрами клиентских сетей."
    ],
    [
      "manage-vpn-l3",
      "L3 VPN",
      "Управление маршрутизируемыми WireGuard-туннелями и VPN pool."
    ],
    [
      "manage-vpn-l2",
      "L2 VPN",
      "Управление L2 overlays, bridge, access ports и Ethernet over WireGuard."
    ],
    [
      "manage-firewall",
      "Firewall",
      "Управление политиками nftables, зонами, правилами, NAT и counters."
    ],
    [
      "manage-ids",
      "IDS / IPS",
      "Управление сигнатурами, режимами IDS/IPS и реакциями на угрозы."
    ],
    [
      "manage-blackhole",
      "Dynamic Blackhole",
      "Политики автоматического blackholing и ручное управление блокировками."
    ],
    [
      "manage-content-filter",
      "Content Filter",
      "Управление категориями, доменами, исключениями и политиками фильтрации."
    ],
    [
      "manage-services",
      "Службы",
      "Запуск, остановка и перезапуск разрешённых служб SecBox."
    ],
  ];

  for (const [page, title, description] of placeholders) {
    if (!main.querySelector(`[data-secbox-page="${page}"]`)) {
      main.append(
        secboxCreatePlaceholder(page, title, description)
      );
    }
  }
}


function secboxUpdateNavigation(route) {
  document.querySelectorAll("[data-page-link]").forEach((link) => {
    let active = link.dataset.pageLink === route.page;

    // VPN Monitoring is one sidebar module with L3/L2 tabs.
    if (
      link.dataset.pageLink === "monitor-vpn" &&
      (
        secboxCurrentPath() === "/monitoring/vpn/l3" ||
        secboxCurrentPath() === "/monitoring/vpn/l2"
      )
    ) {
      active = true;
    }

    // Network is one sidebar module with two internal tabs.
    if (
      link.dataset.pageLink === "manage-network" &&
      (
        secboxCurrentPath() === "/manage/network/interfaces" ||
        secboxCurrentPath() === "/manage/network/dhcp"
      )
    ) {
      active = true;
    }

    // VPN is one sidebar module with L3/L2 internal tabs.
    if (
      link.dataset.pageLink === "manage-vpn" &&
      (
        secboxCurrentPath() === "/manage/vpn/l3" ||
        secboxCurrentPath() === "/manage/vpn/l2"
      )
    ) {
      active = true;
    }

    link.classList.toggle("active", active);

    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
}



function secboxEnsureVpnMonitoringTabs() {
  const path = secboxCurrentPath();

  if (
    path !== "/monitoring/vpn/l3" &&
    path !== "/monitoring/vpn/l2"
  ) {
    return;
  }

  if (
    document.getElementById(
      "vpn-monitoring-tabs"
    )
  ) {
    return;
  }

  const main =
    document.getElementById("app-main");

  if (!main) {
    return;
  }

  const breadcrumb =
    document.getElementById(
      "page-breadcrumb"
    );

  const tabs =
    document.createElement("nav");

  tabs.id = "vpn-monitoring-tabs";
  tabs.className = "module-tabs";
  tabs.setAttribute(
    "aria-label",
    "VPN Monitoring"
  );

  tabs.innerHTML = `
    <a
      href="/monitoring/vpn/l3"
      class="module-tab"
      data-vpn-monitor-tab="l3"
    >L3</a>

    <a
      href="/monitoring/vpn/l2"
      class="module-tab"
      data-vpn-monitor-tab="l2"
    >L2</a>
  `;

  if (breadcrumb) {
    breadcrumb.insertAdjacentElement(
      "afterend",
      tabs
    );
  } else {
    main.prepend(tabs);
  }

  tabs.querySelectorAll("a")
    .forEach((link) => {
      link.addEventListener(
        "click",
        (event) => {
          if (
            event.button !== 0 ||
            event.metaKey ||
            event.ctrlKey ||
            event.shiftKey ||
            event.altKey
          ) {
            return;
          }

          event.preventDefault();

          secboxNavigate(
            link.getAttribute("href")
          );
        }
      );
    });
}


function secboxUpdateVpnMonitoringTabs() {
  const path = secboxCurrentPath();

  const vpnPage =
    path === "/monitoring/vpn/l3" ||
    path === "/monitoring/vpn/l2";

  let tabs =
    document.getElementById(
      "vpn-monitoring-tabs"
    );

  if (!vpnPage) {
    tabs?.remove();
    return;
  }

  secboxEnsureVpnMonitoringTabs();

  tabs =
    document.getElementById(
      "vpn-monitoring-tabs"
    );

  if (!tabs) {
    return;
  }

  tabs
    .querySelectorAll(
      "[data-vpn-monitor-tab]"
    )
    .forEach((tab) => {
      const active =
        (
          path === "/monitoring/vpn/l3" &&
          tab.dataset.vpnMonitorTab === "l3"
        )
        ||
        (
          path === "/monitoring/vpn/l2" &&
          tab.dataset.vpnMonitorTab === "l2"
        );

      tab.classList.toggle(
        "active",
        active
      );

      if (active) {
        tab.setAttribute(
          "aria-current",
          "page"
        );
      } else {
        tab.removeAttribute(
          "aria-current"
        );
      }
    });
}


function secboxEnsureVpnTabs() {
  const path = secboxCurrentPath();

  if (
    path !== "/manage/vpn/l3" &&
    path !== "/manage/vpn/l2"
  ) {
    return;
  }

  // Do not create the tabs twice.
  if (document.getElementById("vpn-management-tabs")) {
    return;
  }

  const main = document.getElementById("app-main");

  if (!main) {
    return;
  }

  const breadcrumb =
    document.getElementById("page-breadcrumb");

  const tabs = document.createElement("nav");

  tabs.id = "vpn-management-tabs";
  tabs.className = "module-tabs";
  tabs.setAttribute("aria-label", "VPN");

  tabs.innerHTML = `
    <a
      href="/manage/vpn/l3"
      class="module-tab"
      data-vpn-tab="l3"
    >L3</a>

    <a
      href="/manage/vpn/l2"
      class="module-tab"
      data-vpn-tab="l2"
    >L2</a>
  `;

  if (breadcrumb) {
    breadcrumb.insertAdjacentElement("afterend", tabs);
  } else {
    main.prepend(tabs);
  }

  tabs.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      ) {
        return;
      }

      event.preventDefault();
      secboxNavigate(link.getAttribute("href"));
    });
  });
}


function secboxUpdateVpnTabs() {
  const tabs =
    document.getElementById("vpn-management-tabs");

  const path = secboxCurrentPath();

  const vpnPage =
    path === "/manage/vpn/l3" ||
    path === "/manage/vpn/l2";

  if (!vpnPage) {
    tabs?.remove();
    return;
  }

  secboxEnsureVpnTabs();

  const currentTabs =
    document.getElementById("vpn-management-tabs");

  if (!currentTabs) {
    return;
  }

  currentTabs
    .querySelectorAll("[data-vpn-tab]")
    .forEach((tab) => {
      const active =
        (path === "/manage/vpn/l3" &&
         tab.dataset.vpnTab === "l3") ||
        (path === "/manage/vpn/l2" &&
         tab.dataset.vpnTab === "l2");

      tab.classList.toggle("active", active);

      if (active) {
        tab.setAttribute("aria-current", "page");
      } else {
        tab.removeAttribute("aria-current");
      }
    });
}


function secboxActivatePage() {
  window.setTimeout(
    () => {
      const path =
        secboxCurrentPath();

      if (
        path === "/monitoring/firewall"
      ) {
        fwLoadRuntime();
      }

      if (
        path === "/manage/firewall"
      ) {
        fwLoadConfig();
      }
    },
    0
  );
  const route = secboxRoute();

  document.body.dataset.page = route.page;
  document.title = `${route.title} — SecBox`;

  secboxUpdateNavigation(route);

  if (
    route.page === "monitor-services"
    || route.page === "manage-services"
  ) {
    window.setTimeout(
      loadManagedServices,
      0
    );
  }
  secboxUpdateVpnTabs();
  secboxUpdateVpnMonitoringTabs();

  if (
    secboxCurrentPath() ===
    "/monitoring/vpn/l2"
  ) {
    refreshL2VpnMonitoring();
  }

  if (route.page === "monitor-vpn") {
    refreshL2VpnMonitoring();
  }

  document.querySelectorAll("[data-secbox-page]").forEach((node) => {
    let visible = node.dataset.secboxPage === route.page;

    const path = secboxCurrentPath();

    if (path === "/monitoring/vpn/l3") {
      visible = node.id === "vpn";
    }

    if (path === "/monitoring/vpn/l2") {
      visible =
        node.id === "vpn-l2-monitoring-page";
    }

    if (path === "/manage/network/interfaces") {
      visible = node.id === "network-interfaces-page";
    }

    if (path === "/manage/network/dhcp") {
      visible = node.id === "network-dhcp-page";
    }

    if (path === "/manage/vpn/l3") {
      visible = node.id === "vpn-configuration-l3-panel";
    }

    if (path === "/manage/vpn/l2") {
      visible = node.id === "vpn-configuration-l2-panel";
    }

    node.hidden = !visible;
  });

  const breadcrumb = document.getElementById("page-breadcrumb");

  if (breadcrumb) {
    breadcrumb.replaceChildren();

    const section = document.createElement("span");
    section.textContent = route.section;

    const separator = document.createElement("span");
    separator.className = "breadcrumb-separator";
    separator.textContent = "/";

    const title = document.createElement("strong");
    title.textContent = route.title;

    const subtitle = document.createElement("small");
    subtitle.textContent = route.subtitle;

    breadcrumb.append(section, separator, title, subtitle);
  }

  window.scrollTo({top: 0, behavior: "instant"});
}


function secboxNavigate(path) {
  if (window.location.pathname !== path) {
    history.pushState({}, "", path);
  }

  secboxActivatePage();
}


function secboxToggleNavigation() {
  document.querySelectorAll(".nav-group-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const group = button.closest(".nav-group");
      const expanded = !group.classList.contains("expanded");

      group.classList.toggle("expanded", expanded);
      button.setAttribute("aria-expanded", String(expanded));
    });
  });

  document.querySelectorAll(".nav-subgroup-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const group = button.closest(".nav-subgroup");
      const expanded = !group.classList.contains("expanded");

      group.classList.toggle("expanded", expanded);
      button.setAttribute("aria-expanded", String(expanded));
    });
  });
}


function secboxInitRouter() {
  secboxClassifyPages();
  secboxToggleNavigation();

  document.querySelectorAll("[data-page-link]").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      ) {
        return;
      }

      event.preventDefault();
      secboxNavigate(link.getAttribute("href"));
    });
  });

  window.addEventListener("popstate", secboxActivatePage);

  secboxActivatePage();
}


if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    secboxInitRouter
  );
} else {
  secboxInitRouter();
}


/* SECBOX L2 VPN MONITORING */
(() => {
  function bindL2VpnMonitoring() {
    const button =
      document.getElementById("vpn-l2-refresh");

    if (!button || button.dataset.bound === "true") {
      return;
    }

    button.dataset.bound = "true";

    button.addEventListener(
      "click",
      refreshL2VpnMonitoring
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      bindL2VpnMonitoring
    );
  } else {
    bindL2VpnMonitoring();
  }

  window.setInterval(() => {
    if (
      window.location.pathname === "/monitoring/vpn"
    ) {
      refreshL2VpnMonitoring();
    }
  }, 10000);
})();


/* SECBOX VPN L2 MONITOR BIND */
(() => {
  function bindVpnL2Monitor() {
    const button =
      document.getElementById(
        "vpn-l2-refresh"
      );

    if (
      !button ||
      button.dataset.bound === "true"
    ) {
      return;
    }

    button.dataset.bound =
      "true";

    button.addEventListener(
      "click",
      refreshL2VpnMonitoring
    );
  }

  if (
    document.readyState === "loading"
  ) {
    document.addEventListener(
      "DOMContentLoaded",
      bindVpnL2Monitor
    );
  } else {
    bindVpnL2Monitor();
  }

  window.setInterval(() => {
    if (
      secboxCurrentPath() ===
      "/monitoring/vpn/l2"
    ) {
      refreshL2VpnMonitoring();
    }
  }, 10000);
})();


/* ==========================================================
   SecBox Services Monitoring / Management
   ========================================================== */

function secboxCreateServicesPages() {
  const main = document.getElementById("app-main");

  if (!main) {
    return;
  }

  for (const page of document.querySelectorAll(
    '[data-secbox-page="monitor-services"],'
    + '[data-secbox-page="manage-services"]'
  )) {
    page.remove();
  }

  const footer = main.querySelector("footer");

  const monitor = document.createElement("section");
  monitor.id = "services-monitoring-page";
  monitor.className = "panel services-page";
  monitor.dataset.secboxPage = "monitor-services";
  monitor.hidden = true;

  monitor.innerHTML = `
    <div class="section-heading">
      <div>
        <p class="eyebrow">Мониторинг / Службы</p>
        <h2>Состояние служб</h2>
      </div>

      <button
        id="services-monitor-refresh"
        type="button"
        class="secondary"
      >Обновить</button>
    </div>

    <p class="hint">
      Runtime-состояние системных компонентов SecBox.
      Состояние systemd само по себе не подтверждает
      корректность обработки трафика.
    </p>

    <p
      id="services-monitor-error"
      class="error"
      role="status"
    ></p>

    <div
      id="services-monitor-list"
      class="managed-service-list"
    ></div>
  `;

  const manage = document.createElement("section");
  manage.id = "services-management-page";
  manage.className = "panel services-page";
  manage.dataset.secboxPage = "manage-services";
  manage.hidden = true;

  manage.innerHTML = `
    <div class="section-heading">
      <div>
        <p class="eyebrow">Управление / Службы</p>
        <h2>Управление службами</h2>
      </div>

      <button
        id="services-manage-refresh"
        type="button"
        class="secondary"
      >Обновить</button>
    </div>

    <p class="hint">
      Доступны только явно разрешённые действия.
      Критичные операции, способные отключить
      Web UI, Firewall, DNS/DHCP или оставить
      неконсистентный VPN runtime, заблокированы.
    </p>

    <p
      id="services-manage-error"
      class="error"
      role="status"
    ></p>

    <div
      id="services-manage-list"
      class="managed-service-list"
    ></div>
  `;

  if (footer) {
    main.insertBefore(monitor, footer);
    main.insertBefore(manage, footer);
  } else {
    main.append(monitor, manage);
  }
}


function serviceHealthLabel(service) {
  if (service.health === "ok") {
    return "ACTIVE";
  }

  if (service.health === "idle") {
    return "IDLE";
  }

  if (service.health === "error") {
    return "ERROR";
  }

  return "INACTIVE";
}


function serviceHealthClass(service) {
  if (service.health === "ok") {
    return "healthy";
  }

  if (service.health === "error") {
    return "down";
  }

  if (service.health === "idle") {
    return "idle";
  }

  return "degraded";
}


function serviceActionLabel(operation) {
  if (operation === "start") {
    return "Запустить";
  }

  if (operation === "stop") {
    return "Остановить";
  }

  if (operation === "restart") {
    return "Перезапустить";
  }

  return operation;
}


function drawManagedServices(
  targetId,
  services,
  management
) {
  const target = byId(targetId);

  if (!target) {
    return;
  }

  target.replaceChildren();

  for (const service of services) {
    const card =
      document.createElement("article");

    card.className =
      "managed-service-card";


    const top =
      document.createElement("div");

    top.className =
      "managed-service-top";


    const identity =
      document.createElement("div");

    const label =
      document.createElement("strong");

    label.textContent =
      service.label;

    const unit =
      document.createElement("code");

    unit.textContent =
      service.unit;

    identity.append(
      label,
      unit
    );


    const status =
      document.createElement("span");

    status.className =
      `vpn-status ${
        serviceHealthClass(service)
      }`;

    status.textContent =
      serviceHealthLabel(service);

    top.append(
      identity,
      status
    );


    const metrics =
      document.createElement("dl");

    metrics.className =
      "managed-service-metrics";

    const values = [
      [
        "Active",
        service.active_state,
      ],
      [
        "Substate",
        service.sub_state,
      ],
      [
        "Load",
        service.load_state,
      ],
      [
        "Startup",
        service.unit_file_state,
      ],
      [
        "Type",
        service.kind,
      ],
    ];

    for (const [name, value] of values) {
      const item =
        document.createElement("div");

      const dt =
        document.createElement("dt");

      const dd =
        document.createElement("dd");

      dt.textContent = name;
      dd.textContent = value || "—";

      item.append(dt, dd);
      metrics.append(item);
    }


    const note =
      document.createElement("p");

    note.className =
      "managed-service-note";

    note.textContent =
      service.note || "";


    card.append(
      top,
      metrics,
      note
    );


    if (management) {
      const actions =
        document.createElement("div");

      actions.className =
        "managed-service-actions";

      for (
        const operation
        of service.allowed_actions || []
      ) {
        const button =
          document.createElement("button");

        button.type = "button";
        button.dataset.serviceUnit =
          service.unit;

        button.dataset.serviceOperation =
          operation;

        button.textContent =
          serviceActionLabel(operation);

        if (operation !== "restart") {
          button.className =
            "secondary";
        }

        if (
          operation === "start" &&
          service.active_state === "active"
        ) {
          button.disabled = true;
        }

        if (
          operation === "stop" &&
          service.active_state !== "active"
        ) {
          button.disabled = true;
        }

        actions.append(button);
      }

      if (
        !(service.allowed_actions || []).length
      ) {
        const locked =
          document.createElement("span");

        locked.className =
          "managed-service-locked";

        locked.textContent =
          "Только мониторинг";

        actions.append(locked);
      }

      card.append(actions);
    }

    target.append(card);
  }
}


let managedServicesLoading = false;


async function loadManagedServices() {
  if (managedServicesLoading) {
    return;
  }

  const path =
    window.location.pathname;

  const monitoring =
    path === "/monitoring/services";

  const management =
    path === "/manage/services";

  if (!monitoring && !management) {
    return;
  }

  managedServicesLoading = true;

  const errorNode = byId(
    management
      ? "services-manage-error"
      : "services-monitor-error"
  );

  try {
    if (errorNode) {
      errorNode.textContent = "";
    }

    const body =
      await api("services/managed");

    drawManagedServices(
      management
        ? "services-manage-list"
        : "services-monitor-list",
      body.services || [],
      management
    );

  } catch (error) {
    if (errorNode) {
      errorNode.textContent =
        `Не удалось получить состояние служб: ${
          error.message
        }`;
    }

  } finally {
    managedServicesLoading = false;
  }
}


async function executeServiceAction(
  unit,
  operation
) {
  const warning =
    operation === "stop"
      ? (
          `Остановить ${unit}?\n\n`
          + "Связанные функции SecBox могут стать недоступны."
        )
      : (
          `${serviceActionLabel(operation)} ${unit}?`
        );

  if (!window.confirm(warning)) {
    return;
  }

  const errorNode =
    byId("services-manage-error");

  try {
    if (errorNode) {
      errorNode.textContent = "";
    }

    await api(
      "services/action",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          unit,
          operation,
        }),
      }
    );

    await loadManagedServices();

  } catch (error) {
    if (errorNode) {
      errorNode.textContent =
        `Операция не выполнена: ${
          error.message
        }`;
    }
  }
}


function bindServicesPages() {
  byId("services-monitor-refresh")
    ?.addEventListener(
      "click",
      loadManagedServices
    );

  byId("services-manage-refresh")
    ?.addEventListener(
      "click",
      loadManagedServices
    );

  byId("services-manage-list")
    ?.addEventListener(
      "click",
      (event) => {
        const button =
          event.target.closest(
            "[data-service-unit]"
          );

        if (!button) {
          return;
        }

        executeServiceAction(
          button.dataset.serviceUnit,
          button.dataset.serviceOperation
        );
      }
    );
}


secboxCreateServicesPages();
bindServicesPages();

window.setInterval(() => {
  if (
    window.location.pathname ===
      "/monitoring/services"
    ||
    window.location.pathname ===
      "/manage/services"
  ) {
    loadManagedServices();
  }
}, 10000);


/* ==========================================================
   SecBox Firewall Monitoring / Management
   ========================================================== */

let firewallConfigSnapshot = null;
let firewallBusy = false;


function fwRequest(
  path,
  options = {}
) {
  return api(
    path,
    options
  );
}


function fwCreatePages() {
  const main =
    document.getElementById(
      "app-main"
    );

  if (!main) {
    return;
  }

  if (
    !main.querySelector(
      '[data-secbox-page="monitor-firewall"]'
    )
  ) {
    const section =
      document.createElement(
        "section"
      );

    section.className =
      "panel firewall-page";

    section.dataset.secboxPage =
      "monitor-firewall";

    section.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Мониторинг / Firewall</p>
          <h2>Firewall Runtime</h2>
        </div>

        <button
          id="fw-monitor-refresh"
          type="button"
          class="secondary"
        >Обновить</button>
      </div>

      <p class="hint">
        Реальное состояние nftables, IPv4 forwarding,
        NAT и счётчиков правил.
      </p>

      <p
        id="fw-monitor-error"
        class="error"
        role="status"
      ></p>

      <div class="fw-status-grid">
        <article>
          <span>Filter table</span>
          <strong id="fw-mon-filter">—</strong>
        </article>

        <article>
          <span>IPv4 forwarding</span>
          <strong id="fw-mon-forwarding">—</strong>
        </article>

        <article>
          <span>NAT</span>
          <strong id="fw-mon-nat">—</strong>
        </article>

        <article>
          <span>Blacklist runtime</span>
          <strong id="fw-mon-blacklist">—</strong>
        </article>
      </div>

      <h3>Цепочки</h3>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Chain</th>
              <th>Policy</th>
              <th>Rules</th>
              <th>Counter packets</th>
              <th>Counter bytes</th>
            </tr>
          </thead>

          <tbody id="fw-monitor-chains"></tbody>
        </table>
      </div>

      <h3>NAT egress</h3>

      <div
        id="fw-monitor-nat-ifaces"
        class="fw-chip-list"
      ></div>
    `;

    main.append(section);
  }

  if (
    !main.querySelector(
      '[data-secbox-page="manage-firewall"]'
    )
  ) {
    const section =
      document.createElement(
        "section"
      );

    section.className =
      "panel firewall-page";

    section.dataset.secboxPage =
      "manage-firewall";

    section.innerHTML = `
      <div class="section-heading">
        <div>
          <p class="eyebrow">Управление / Firewall</p>
          <h2>Firewall Configuration</h2>
        </div>

        <span
          id="fw-config-state"
          class="tag"
        >Загрузка…</span>
      </div>

      <p class="hint">
        Конфигурация применяется транзакционно через
        privileged helper. TCP/8443 на MGMT защищён
        от удаления через Web UI.
      </p>

      <p
        id="fw-config-error"
        class="error"
        role="status"
      ></p>

      <form id="fw-form">
        <div class="fw-form-grid">

          <label class="fw-check">
            <input
              id="fw-enabled"
              type="checkbox"
              checked
              disabled
            >
            <span>Firewall включён</span>
          </label>

          <label class="fw-check">
            <input
              id="fw-ip-forward"
              type="checkbox"
            >
            <span>IPv4 forwarding</span>
          </label>

          <label class="fw-check">
            <input
              id="fw-nat"
              type="checkbox"
            >
            <span>NAT / masquerade</span>
          </label>

          <label class="fw-check">
            <input
              id="fw-lan-wan"
              type="checkbox"
            >
            <span>Разрешать LAN → uplink</span>
          </label>

          <label>
            <span>WAN interface</span>
            <select
              id="fw-wan"
              required
            ></select>
          </label>

          <label>
            <span>LAN interface</span>
            <select
              id="fw-lan"
              required
            ></select>
          </label>

          <label>
            <span>Management interface</span>
            <select
              id="fw-mgmt"
              required
            ></select>
          </label>

          <label>
            <span>Management TCP ports</span>
            <input
              id="fw-mgmt-ports"
              type="text"
              placeholder="22, 8443"
              required
            >
          </label>
        </div>

        <h3 class="fw-subtitle">Policies</h3>

        <div class="fw-form-grid">
          <label>
            <span>INPUT policy</span>
            <select id="fw-input-policy">
              <option value="drop">drop</option>
              <option value="accept">accept</option>
            </select>
          </label>

          <label>
            <span>FORWARD policy</span>
            <select id="fw-forward-policy">
              <option value="drop">drop</option>
              <option value="accept">accept</option>
            </select>
          </label>

          <label>
            <span>OUTPUT policy</span>
            <select id="fw-output-policy">
              <option value="accept">accept</option>
              <option value="drop">drop</option>
            </select>
          </label>
        </div>

        <h3 class="fw-subtitle">Base rules</h3>

        <div class="fw-form-grid">
          <label class="fw-check">
            <input
              id="fw-icmp"
              type="checkbox"
            >
            <span>Разрешать ICMP input</span>
          </label>

          <label class="fw-check">
            <input
              id="fw-dhcp"
              type="checkbox"
            >
            <span>Разрешать DHCP server traffic</span>
          </label>
        </div>

        <h3 class="fw-subtitle">Logging</h3>

        <div class="fw-form-grid">
          <label class="fw-check">
            <input
              id="fw-log-input"
              type="checkbox"
            >
            <span>Логировать INPUT drop</span>
          </label>

          <label class="fw-check">
            <input
              id="fw-log-forward"
              type="checkbox"
            >
            <span>Логировать FORWARD drop</span>
          </label>

          <label>
            <span>Log rate</span>
            <input
              id="fw-log-rate"
              type="text"
              placeholder="10/second"
            >
          </label>

          <label>
            <span>Log burst</span>
            <input
              id="fw-log-burst"
              type="number"
              min="1"
              max="10000"
            >
          </label>
        </div>

        <h3 class="fw-subtitle">Dynamic blacklist</h3>

        <div class="fw-form-grid">
          <label class="fw-check">
            <input
              id="fw-blacklist-enabled"
              type="checkbox"
            >
            <span>Dynamic blacklist</span>
          </label>

          <label>
            <span>Default timeout</span>
            <input
              id="fw-blacklist-timeout"
              type="text"
              placeholder="1h"
            >
          </label>

          <label class="fw-wide">
            <span>Protected networks</span>
            <textarea
              id="fw-protected-networks"
              rows="3"
              placeholder="192.168.100.0/24"
            ></textarea>
          </label>
        </div>

        <div class="fw-actions">
          <button
            id="fw-validate"
            type="button"
            class="secondary"
          >Проверить</button>

          <button
            id="fw-apply"
            type="submit"
          >Применить</button>

          <button
            id="fw-reload"
            type="button"
            class="secondary"
          >Перечитать</button>
        </div>
      </form>
    `;

    main.append(section);
  }
}


function fwSetOptions(
  selectId,
  interfaces,
  role,
  selected
) {
  const select =
    byId(selectId);

  if (!select) {
    return;
  }

  select.replaceChildren();

  const matches =
    (interfaces || []).filter(
      (item) =>
        item.role === role
    );

  for (const item of matches) {
    const option =
      document.createElement(
        "option"
      );

    option.value =
      item.name;

    option.textContent =
      item.name;

    option.selected =
      item.name === selected;

    select.append(option);
  }
}


function fwParseLines(value) {
  return String(value || "")
    .split(/[\n,]+/)
    .map(
      (item) => item.trim()
    )
    .filter(Boolean);
}


function fwParsePorts(value) {
  const ports =
    fwParseLines(value).map(
      (item) => Number(item)
    );

  if (
    ports.some(
      (port) =>
        !Number.isInteger(port)
        || port < 1
        || port > 65535
    )
  ) {
    throw new Error(
      "Management ports должны быть целыми числами 1..65535"
    );
  }

  return [
    ...new Set(ports),
  ].sort(
    (a, b) => a - b
  );
}


function fwCandidate() {
  const snapshot =
    firewallConfigSnapshot;

  if (!snapshot) {
    throw new Error(
      "Firewall configuration ещё не загружена"
    );
  }

  const ports =
    fwParsePorts(
      byId("fw-mgmt-ports").value
    );

  if (!ports.includes(8443)) {
    throw new Error(
      "Порт 8443 должен оставаться разрешённым на MGMT"
    );
  }

  return {
    ...snapshot,
    enabled: true,
    wan_interface:
      byId("fw-wan").value,
    lan_interface:
      byId("fw-lan").value,
    management_interface:
      byId("fw-mgmt").value,
    management_tcp_ports:
      ports,
    allow_lan_to_wan:
      byId("fw-lan-wan").checked,
    allow_icmp_input:
      byId("fw-icmp").checked,
    allow_dhcp_server:
      byId("fw-dhcp").checked,
    enable_ipv4_forwarding:
      byId("fw-ip-forward").checked,
    enable_nat:
      byId("fw-nat").checked,
    log_dropped_input:
      byId("fw-log-input").checked,
    log_dropped_forward:
      byId("fw-log-forward").checked,
    log_rate:
      byId("fw-log-rate").value.trim(),
    log_burst:
      Number(
        byId("fw-log-burst").value
      ),
    dynamic_blacklist_enabled:
      byId(
        "fw-blacklist-enabled"
      ).checked,
    dynamic_blacklist_timeout:
      byId(
        "fw-blacklist-timeout"
      ).value.trim(),
    dynamic_blacklist_protected_networks:
      fwParseLines(
        byId(
          "fw-protected-networks"
        ).value
      ),
    input_policy:
      byId(
        "fw-input-policy"
      ).value,
    forward_policy:
      byId(
        "fw-forward-policy"
      ).value,
    output_policy:
      byId(
        "fw-output-policy"
      ).value,
  };
}


function fwFillConfig(
  firewall,
  interfaces
) {
  firewallConfigSnapshot = {
    ...firewall,
  };

  fwSetOptions(
    "fw-wan",
    interfaces,
    "wan",
    firewall.wan_interface
  );

  fwSetOptions(
    "fw-lan",
    interfaces,
    "lan",
    firewall.lan_interface
  );

  fwSetOptions(
    "fw-mgmt",
    interfaces,
    "mgmt",
    firewall.management_interface
  );

  byId("fw-enabled").checked =
    firewall.enabled;

  byId("fw-ip-forward").checked =
    firewall.enable_ipv4_forwarding;

  byId("fw-nat").checked =
    firewall.enable_nat;

  byId("fw-lan-wan").checked =
    firewall.allow_lan_to_wan;

  byId("fw-icmp").checked =
    firewall.allow_icmp_input;

  byId("fw-dhcp").checked =
    firewall.allow_dhcp_server;

  byId("fw-log-input").checked =
    firewall.log_dropped_input;

  byId("fw-log-forward").checked =
    firewall.log_dropped_forward;

  byId("fw-log-rate").value =
    firewall.log_rate || "";

  byId("fw-log-burst").value =
    firewall.log_burst;

  byId(
    "fw-blacklist-enabled"
  ).checked =
    firewall.dynamic_blacklist_enabled;

  byId(
    "fw-blacklist-timeout"
  ).value =
    firewall.dynamic_blacklist_timeout
    || "";

  byId(
    "fw-protected-networks"
  ).value =
    (
      firewall
        .dynamic_blacklist_protected_networks
      || []
    ).join("\n");

  byId("fw-input-policy").value =
    firewall.input_policy;

  byId("fw-forward-policy").value =
    firewall.forward_policy;

  byId("fw-output-policy").value =
    firewall.output_policy;
}


async function fwLoadConfig() {
  const state =
    byId("fw-config-state");

  const error =
    byId("fw-config-error");

  if (!state) {
    return;
  }

  try {
    state.textContent =
      "Загрузка…";

    if (error) {
      error.textContent = "";
    }

    const data =
      await fwRequest(
        "firewall/config"
      );

    fwFillConfig(
      data.firewall,
      data.interfaces || []
    );

    state.textContent =
      "Загружено";

  } catch (err) {
    state.textContent =
      "Ошибка";

    if (error) {
      error.textContent =
        err.message;
    }
  }
}


function fwFormatBytes(value) {
  const number =
    Number(value || 0);

  if (number < 1024) {
    return `${number} B`;
  }

  if (number < 1024 ** 2) {
    return `${
      (number / 1024).toFixed(1)
    } KiB`;
  }

  return `${
    (number / 1024 ** 2).toFixed(1)
  } MiB`;
}


function fwDrawRuntime(runtime) {
  byId("fw-mon-filter").textContent =
    runtime.filter_table
      ? "ACTIVE"
      : "MISSING";

  byId(
    "fw-mon-forwarding"
  ).textContent =
    runtime.ipv4_forwarding
      ? "ON"
      : "OFF";

  byId("fw-mon-nat").textContent =
    runtime.nat_table
      ? "ACTIVE"
      : "OFF";

  byId(
    "fw-mon-blacklist"
  ).textContent =
    String(
      runtime.blacklist_entries ?? 0
    );

  const tbody =
    byId("fw-monitor-chains");

  tbody.replaceChildren();

  for (
    const name
    of ["input", "forward", "output"]
  ) {
    const chain =
      runtime.chains?.[name] || {};

    const counters =
      runtime.counters?.[name]
      || {};

    const row =
      document.createElement("tr");

    for (const value of [
      name.toUpperCase(),
      chain.policy || "—",
      runtime.rule_counts?.[name]
        ?? 0,
      counters.packets ?? 0,
      fwFormatBytes(
        counters.bytes
      ),
    ]) {
      const cell =
        document.createElement("td");

      cell.textContent =
        String(value);

      row.append(cell);
    }

    tbody.append(row);
  }

  const target =
    byId(
      "fw-monitor-nat-ifaces"
    );

  target.replaceChildren();

  const interfaces =
    runtime.masquerade_interfaces
    || [];

  if (!interfaces.length) {
    const text =
      document.createElement("span");

    text.className = "hint";
    text.textContent =
      "Masquerade interfaces отсутствуют";

    target.append(text);

    return;
  }

  for (const iface of interfaces) {
    const chip =
      document.createElement("code");

    chip.textContent =
      iface;

    target.append(chip);
  }
}


async function fwLoadRuntime() {
  const error =
    byId("fw-monitor-error");

  if (!byId("fw-monitor-chains")) {
    return;
  }

  try {
    if (error) {
      error.textContent = "";
    }

    const data =
      await fwRequest(
        "firewall/runtime"
      );

    fwDrawRuntime(
      data.runtime
    );

  } catch (err) {
    if (error) {
      error.textContent =
        `Не удалось получить Firewall runtime: ${
          err.message
        }`;
    }
  }
}


async function fwValidate() {
  const state =
    byId("fw-config-state");

  const error =
    byId("fw-config-error");

  try {
    const candidate =
      fwCandidate();

    if (error) {
      error.textContent = "";
    }

    state.textContent =
      "Проверка…";

    await fwRequest(
      "firewall/config/validate",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          candidate
        ),
      }
    );

    state.textContent =
      "Конфигурация корректна";

    return true;

  } catch (err) {
    state.textContent =
      "Ошибка";

    if (error) {
      error.textContent =
        err.message;
    }

    return false;
  }
}


async function fwApply(event) {
  event?.preventDefault();

  if (firewallBusy) {
    return;
  }

  const valid =
    await fwValidate();

  if (!valid) {
    return;
  }

  if (
    !window.confirm(
      "Применить конфигурацию Firewall?\n\n"
      + "Правила nftables будут перегенерированы."
    )
  ) {
    return;
  }

  const state =
    byId("fw-config-state");

  const error =
    byId("fw-config-error");

  firewallBusy = true;

  try {
    state.textContent =
      "Применение…";

    const candidate =
      fwCandidate();

    await fwRequest(
      "firewall/config/apply",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(
          candidate
        ),
      }
    );

    state.textContent =
      "Применено";

    await fwLoadConfig();

  } catch (err) {
    state.textContent =
      "Ошибка";

    if (error) {
      error.textContent =
        err.message;
    }

  } finally {
    firewallBusy = false;
  }
}


function fwBindUi() {
  byId("fw-monitor-refresh")
    ?.addEventListener(
      "click",
      fwLoadRuntime
    );

  byId("fw-reload")
    ?.addEventListener(
      "click",
      fwLoadConfig
    );

  byId("fw-validate")
    ?.addEventListener(
      "click",
      fwValidate
    );

  byId("fw-form")
    ?.addEventListener(
      "submit",
      fwApply
    );
}


window.setInterval(
  () => {
    if (
      secboxCurrentPath()
      === "/monitoring/firewall"
    ) {
      fwLoadRuntime();
    }
  },
  10000
);
