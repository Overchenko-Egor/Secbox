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

async function refresh() {
  byId("refresh").disabled = true;
  const jobs = [
    ["system", "global-message", drawSystem],
    ["network/interfaces", "network-error", drawInterfaces],
    ["network/routes", "routes-error", (data) => table("routes-body", data.map((x) => [x.destination, x.gateway, x.interface, x.table, x.metric]))],
    ["services", "services-error", drawServices],
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
