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
  const network = snapshot["network/status"];
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
  /*
   * Network
   *
   * Only interfaces managed by SecBox are evaluated here.
   * Interfaces with role "unused" are intentionally excluded
   * from appliance health.
   */
  if (network) {
    const managed = network.interfaces.filter(
      (item) =>
        item.role !== "unused" &&
        item.configured
    );

    const failed = managed.filter(
      (item) =>
        String(item.operstate).toUpperCase() !== "UP"
    );

    if (!managed.length) {
      networkLevel = "unknown";

      setComponentStatus(
        "network-health",
        "unknown",
        "UNKNOWN",
      );

      byId("network-summary").textContent =
        "Нет управляемых интерфейсов";

      byId("network-detail").textContent =
        "Network runtime не содержит активных ролей";
    } else if (failed.length) {
      networkLevel = "warning";

      setComponentStatus(
        "network-health",
        "warning",
        "DEGRADED",
      );

      byId("network-summary").textContent =
        `${managed.length - failed.length}/${managed.length} UP`;

      byId("network-detail").textContent =
        failed
          .map(
            (item) =>
              `${item.role.toUpperCase()} ${item.name}`
          )
          .join(", ");

      addAttention(
        attention,
        "warning",
        "Network",
        `Неактивные интерфейсы: ${
          failed
            .map(
              (item) =>
                `${item.role.toUpperCase()} (${item.name})`
            )
            .join(", ")
        }`,
      );
    } else {
      networkLevel = "healthy";

      setComponentStatus(
        "network-health",
        "healthy",
        "HEALTHY",
      );

      byId("network-summary").textContent =
        `${managed.length}/${managed.length} UP`;

      byId("network-detail").textContent =
        managed
          .map(
            (item) =>
              `${item.role.toUpperCase()} ${item.name}`
          )
          .join(" · ");
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
    ["network/status", "global-message", () => {}],
    ["network/interfaces", "network-error", drawInterfaces],
    ["network/routes", "routes-error", (data) => table("routes-body", data.map((x) => [x.destination, x.gateway, x.interface, x.table, x.metric]))],
    ["services", "services-error", drawServices],
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

/* SECBOX VPN CONFIGURATION UI START */
(() => {
  "use strict";

  const API = "/api/v1/vpn/config";
  const VALIDATE_API = "/api/v1/vpn/config/validate";

  let vpnConfig = null;

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

  function ensurePanel() {
    let panel = document.getElementById("vpn-configuration-panel");

    if (panel) {
      return panel;
    }

    panel = document.createElement("section");
    panel.id = "vpn-configuration-panel";
    panel.className = "panel vpn-config-panel";

    const vpnSection = document.getElementById("vpn");

    if (vpnSection) {
      vpnSection.insertAdjacentElement("afterend", panel);
    } else {
      document.querySelector("main")?.appendChild(panel);
    }

    return panel;
  }

  function message(text, type = "info") {
    const node = document.getElementById("vpn-config-message");

    if (!node) {
      return;
    }

    node.className =
      `vpn-config-message vpn-config-message-${type}`;
    node.textContent = text;
  }

  function render() {
    const panel = ensurePanel();

    if (!vpnConfig) {
      panel.innerHTML = `
        <div class="vpn-config-heading">
          <div>
            <p class="eyebrow">Настройки</p>
            <h2>VPN Configuration</h2>
            <p>Загрузка текущей VPN-конфигурации…</p>
          </div>
        </div>
      `;
      return;
    }

    vpnConfig.tunnels ??= [];
    vpnConfig.l2_tunnels ??= [];

    panel.innerHTML = `
      <div class="vpn-config-heading">
        <div>
          <p class="eyebrow">Управление VPN</p>
          <h2>VPN Configuration</h2>
          <p>
            Управление отказоустойчивым L3 WireGuard pool и
            Ethernet-over-WireGuard L2 overlays.
          </p>
        </div>

        <label class="vpn-config-master-enabled">
          <input
            id="vpn-config-master-enabled"
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
            Маршрутизируемые WireGuard-туннели с priority,
            routing table и health-check.
          </p>
        </div>
        <span class="tag">${vpnConfig.tunnels.length} tunnel(s)</span>
      </div>

      <div id="vpn-config-tunnels">
        ${vpnConfig.tunnels.map(l3Card).join("")}
      </div>

      <button
        type="button"
        id="vpn-config-add"
        class="vpn-config-secondary"
      >+ Add L3 tunnel</button>

      <div class="vpn-config-divider"></div>

      <div class="vpn-config-section-heading">
        <div>
          <h3>L2 VPN Overlays</h3>
          <p>
            Ethernet bridge → GRETAP → WireGuard.
            Поддерживает broadcast/ARP/DHCP и перенос 802.1Q frames.
          </p>
        </div>
        <span class="tag">${vpnConfig.l2_tunnels.length} overlay(s)</span>
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

      <div
        id="vpn-config-message"
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
            id="vpn-config-reload"
            class="vpn-config-secondary"
          >Reload</button>

          <button
            type="button"
            id="vpn-config-validate"
            class="vpn-config-secondary"
          >Validate</button>

          <button
            type="button"
            id="vpn-config-apply"
            class="vpn-config-primary"
          >Apply changes</button>
        </div>
      </div>
    `;

    bind();
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

  function readForm() {
    const next = structuredClone(vpnConfig);

    next.enabled =
      document.getElementById("vpn-config-master-enabled")
        ?.checked ?? false;

    document
      .querySelectorAll("[data-vpn-tunnel]")
      .forEach((card) => {
        const index = Number(card.dataset.vpnTunnel);
        readInputs(
          card,
          "data-vpn-field",
          next.tunnels[index]
        );
      });

    document
      .querySelectorAll("[data-vpn-l2-tunnel]")
      .forEach((card) => {
        const index = Number(card.dataset.vpnL2Tunnel);
        readInputs(
          card,
          "data-vpn-l2-field",
          next.l2_tunnels[index]
        );

        /*
         * Ordinary text/number L2 fields use data-vpn-field so field()
         * can be shared by L3 and L2 cards.
         */
        readInputs(
          card,
          "data-vpn-field",
          next.l2_tunnels[index]
        );
      });

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
    try {
      message("Loading configuration...");

      const body = await configApi(API);

      vpnConfig = body.vpn;
      vpnConfig.tunnels ??= [];
      vpnConfig.l2_tunnels ??= [];

      render();
      message("Configuration loaded.", "success");
    } catch (error) {
      const panel = ensurePanel();

      panel.innerHTML = `
        <div class="vpn-config-heading">
          <div>
            <h2>VPN Configuration</h2>
            <p>Configuration could not be loaded.</p>
          </div>
        </div>

        <div class="vpn-config-message vpn-config-message-error">
          ${esc(error.message)}
        </div>

        <button
          type="button"
          id="vpn-config-retry"
          class="vpn-config-secondary"
        >Retry</button>
      `;

      document
        .getElementById("vpn-config-retry")
        ?.addEventListener("click", load);
    }
  }

  async function validate() {
    const button =
      document.getElementById("vpn-config-validate");

    try {
      const candidate = readForm();

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
      document.getElementById("vpn-config-apply");

    try {
      const candidate = readForm();

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
        vpnConfig = readForm();
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
        vpnConfig = readForm();
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
          const current = readForm();

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
          const current = readForm();

          current.l2_tunnels.splice(index, 1);
          vpnConfig = current;

          render();

          message(
            "L2 overlay removed locally. Apply to commit the change."
          );
        });
      });

    document
      .getElementById("vpn-config-reload")
      ?.addEventListener("click", load);

    document
      .getElementById("vpn-config-validate")
      ?.addEventListener("click", validate);

    document
      .getElementById("vpn-config-apply")
      ?.addEventListener("click", apply);
  }

  function boot() {
    ensurePanel();
    render();
    load();
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      boot
    );
  } else {
    boot();
  }
})();
 /* SECBOX VPN CONFIGURATION UI END */


// ============================================================
// Network + DHCP configuration
// ============================================================

let networkDhcpState = null;


function networkConfigMessage(message, type = "info") {
    const element = document.getElementById(
        "network-config-message"
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

    const interfaceList = document.getElementById(
        "network-interface-list"
    );

    const dhcpList = document.getElementById(
        "dhcp-scope-list"
    );

    if (!interfaceList || !dhcpList) {
        return;
    }

    interfaceList.innerHTML =
        networkDhcpState.network.interfaces
            .map(networkInterfaceCard)
            .join("");

    dhcpList.innerHTML =
        networkDhcpState.dhcp
            .map(dhcpScopeCard)
            .join("");

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
        throw new Error(
            "Конфигурация сети ещё не загружена"
        );
    }

    const interfaces = Array.from(
        document.querySelectorAll(
            ".network-card"
        )
    ).map(card => {
        const original =
            networkDhcpState.network.interfaces[
                Number(card.dataset.networkIndex)
            ];

        const roleElement = card.querySelector(
            ".network-role"
        );

        const method = card.querySelector(
            ".network-ipv4-method"
        ).value;

        const address = card.querySelector(
            ".network-ipv4-address"
        ).value.trim();

        const routingRaw = card.querySelector(
            ".network-routing-table"
        ).value.trim();

        return {
            name: original.name,

            // Disabled role controls retain their original value.
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

    const dhcp = Array.from(
        document.querySelectorAll(
            ".dhcp-card"
        )
    ).map(card => {
        const dns = card.querySelector(
            ".dhcp-dns"
        ).value
            .split(",")
            .map(value => value.trim())
            .filter(Boolean);

        return {
            enabled: card.querySelector(
                ".dhcp-enabled"
            ).checked,

            interface: card.querySelector(
                ".dhcp-interface"
            ).value.trim(),

            network: card.querySelector(
                ".dhcp-network"
            ).value.trim(),

            range_start: card.querySelector(
                ".dhcp-range-start"
            ).value.trim(),

            range_end: card.querySelector(
                ".dhcp-range-end"
            ).value.trim(),

            gateway: card.querySelector(
                ".dhcp-gateway"
            ).value.trim(),

            dns_servers: dns,

            lease_time: card.querySelector(
                ".dhcp-lease-time"
            ).value.trim(),
        };
    });

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
    const root = document.getElementById(
        "network-config-editor"
    );

    if (!root) {
        return;
    }

    document
        .getElementById("network-config-reload")
        ?.addEventListener(
            "click",
            loadNetworkDhcpConfig
        );

    document
        .getElementById("network-config-validate")
        ?.addEventListener(
            "click",
            validateNetworkDhcpConfig
        );

    document
        .getElementById("network-config-apply")
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
    initializeNetworkDhcpEditor();
}
