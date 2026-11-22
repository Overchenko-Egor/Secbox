"use strict";

let deceptionLoaded = false;


async function deceptionRequest(
  path,
  options = {}
) {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;

    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_) {
      // Keep HTTP status.
    }

    throw new Error(detail);
  }

  return response.json();
}


function deceptionTime(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString("ru-RU");
}


function deceptionCell(row, value) {
  const cell = document.createElement("td");

  cell.textContent = String(
    value ?? "—"
  );

  row.append(cell);

  return cell;
}


function deceptionStatusClass(status) {
  if (status === "observing") {
    return "active";
  }

  if (status === "stopped") {
    return "muted";
  }

  if (status === "error") {
    return "danger";
  }

  return "unknown";
}


function deceptionStatusBadge(status) {
  const node =
    document.createElement("span");

  node.className =
    `secbox-status-badge ${
      deceptionStatusClass(status)
    }`;

  node.textContent =
    String(status || "unknown");

  return node;
}


function deceptionRemaining(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  let seconds = Math.max(
    0,
    Number(value) || 0
  );

  const hours = Math.floor(
    seconds / 3600
  );

  seconds %= 3600;

  const minutes = Math.floor(
    seconds / 60
  );

  seconds %= 60;

  if (hours > 0) {
    return `${hours}ч ${minutes}м`;
  }

  if (minutes > 0) {
    return `${minutes}м ${seconds}с`;
  }

  return `${seconds}с`;
}


function deceptionTrigger(item) {
  const trigger =
    item.trigger || {};

  if (!trigger.source) {
    return "—";
  }

  if (trigger.source !== "ids") {
    return String(
      trigger.source
    );
  }

  const parts = [
    "IDS",
  ];

  if (
    trigger.signature_id !== null &&
    trigger.signature_id !== undefined
  ) {
    parts.push(
      `SID ${trigger.signature_id}`
    );
  }

  if (
    trigger.severity !== null &&
    trigger.severity !== undefined
  ) {
    parts.push(
      `sev ${trigger.severity}`
    );
  }

  return parts.join(" · ");
}


window.deceptionCreatePage = function () {
  const main =
    document.getElementById("app-main");

  if (
    !main ||
    main.querySelector(
      '[data-secbox-page="monitor-deception"]'
    )
  ) {
    return;
  }

  const page =
    document.createElement("section");

  page.className =
    "secbox-page-shell";

  page.dataset.secboxPage =
    "monitor-deception";

  page.innerHTML = `
    <section class="secbox-page-card">

      <div class="secbox-page-card-header">
        <div>
          <p class="secbox-page-kicker">
            MONITORING / DECEPTION
          </p>

          <h2>
            Deception
          </h2>

          <p class="secbox-page-description">
            Изолированная инфраструктура для
            наблюдения за активностью источников,
            помещённых в quarantine.
          </p>
        </div>

        <div class="secbox-page-toolbar">
          <button id="deception-refresh"
                  type="button">
            Обновить
          </button>
        </div>
      </div>

      <div id="deception-message"
           class="secbox-page-message">
        Загрузка…
      </div>

      <section class="secbox-page-section">

        <div class="secbox-page-section-header">
          <div>
            <h3>Active Quarantine</h3>

            <p>
              Источники, трафик которых сейчас
              направляется в Deception.
            </p>
          </div>

          <span id="deception-quarantine-count"
                class="tag">
            —
          </span>
        </div>

        <div class="secbox-table-shell">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Case</th>
                <th>Trigger</th>
                <th>Status</th>
                <th>Expires</th>
                <th>Remaining</th>
                <th></th>
              </tr>
            </thead>

            <tbody id="deception-quarantine-body">
            </tbody>
          </table>
        </div>

      </section>

      <section class="secbox-page-section">

        <div class="secbox-page-section-header">
          <div>
            <h3>Cases</h3>

            <p>
              История наблюдений и текущие
              Deception-сессии.
            </p>
          </div>

          <span id="deception-case-count"
                class="tag">
            —
          </span>
        </div>

        <div class="secbox-table-shell">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Source</th>
                <th>Status</th>
                <th>Events</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>

            <tbody id="deception-case-body">
            </tbody>
          </table>
        </div>

      </section>

      <section id="deception-detail"
               class="secbox-page-section">
      </section>

    </section>
  `;

  main.append(page);

  document.getElementById(
    "deception-refresh"
  )?.addEventListener(
    "click",
    () => deceptionLoadCases(true)
  );
};


function deceptionRenderQuarantine(items) {
  const body =
    document.getElementById(
      "deception-quarantine-body"
    );

  const count =
    document.getElementById(
      "deception-quarantine-count"
    );

  if (!body) {
    return;
  }

  body.replaceChildren();

  if (count) {
    count.textContent =
      `${items.length} active`;
  }

  for (const item of items) {
    const row =
      document.createElement("tr");

    deceptionCell(
      row,
      item.source_ip
    );

    deceptionCell(
      row,
      item.case_id
    );

    deceptionCell(
      row,
      deceptionTrigger(item)
    );

    const statusCell =
      document.createElement("td");

    statusCell.append(
      deceptionStatusBadge(
        item.status
      )
    );

    row.append(
      statusCell
    );

    deceptionCell(
      row,
      deceptionTime(
        item.expires_at
      )
    );

    deceptionCell(
      row,
      deceptionRemaining(
        item.remaining_seconds
      )
    );

    const action =
      document.createElement("td");

    const button =
      document.createElement("button");

    button.type = "button";
    button.className =
      "secbox-danger-button";
    button.textContent =
      "Release";

    button.addEventListener(
      "click",
      () => deceptionRelease(
        item.case_id,
        item.source_ip,
        button
      )
    );

    const openButton =
      document.createElement("button");

    openButton.type = "button";
    openButton.className = "secondary";
    openButton.textContent = "Открыть";

    openButton.addEventListener(
      "click",
      () => deceptionLoadCase(item.case_id)
    );

    action.append(
      openButton,
      button
    );

    row.append(
      action
    );

    body.append(
      row
    );
  }

  if (!items.length) {
    const row =
      document.createElement("tr");

    const cell =
      document.createElement("td");

    cell.colSpan = 7;

    cell.innerHTML = `
      <div class="secbox-empty-state">
        <strong>
          Active quarantine пуст
        </strong>

        <span>
          Сейчас ни один источник не
          перенаправляется в Deception.
        </span>
      </div>
    `;

    row.append(
      cell
    );

    body.append(
      row
    );
  }
}


async function deceptionRelease(
  caseId,
  sourceIp,
  button
) {
  const message =
    document.getElementById(
      "deception-message"
    );

  const confirmed = window.confirm(
    `Освободить ${sourceIp} из Deception quarantine?`
  );

  if (!confirmed) {
    return;
  }

  button.disabled = true;

  try {
    const result =
      await deceptionRequest(
        `/api/v1/deception/quarantine/${
          encodeURIComponent(caseId)
        }/release`,
        {
          method: "POST",
        }
      );

    if (message) {
      message.textContent =
        result.status ===
        "already_released"
          ? `${sourceIp} уже освобождён.`
          : `${sourceIp} освобождён из quarantine.`;

      message.className =
        "secbox-page-message good";
    }

    deceptionLoaded = false;

    await deceptionLoadCases(
      true
    );

  } catch (error) {
    if (message) {
      message.textContent =
        `Ошибка release: ${error.message}`;

      message.className =
        "secbox-page-message error";
    }

    button.disabled = false;
  }
}


function deceptionRenderCases(cases) {
  const body =
    document.getElementById(
      "deception-case-body"
    );

  const count =
    document.getElementById(
      "deception-case-count"
    );

  if (!body) {
    return;
  }

  body.replaceChildren();

  if (count) {
    count.textContent =
      `${cases.length} case(s)`;
  }

  for (const item of cases) {
    const telemetry =
      item.telemetry || {};

    const row =
      document.createElement("tr");

    deceptionCell(
      row,
      item.case_id
    );

    deceptionCell(
      row,
      item.source_ip
    );

    const statusCell =
      document.createElement("td");

    statusCell.append(
      deceptionStatusBadge(
        item.status
      )
    );

    row.append(statusCell);

    deceptionCell(
      row,
      telemetry.event_count ?? 0
    );

    deceptionCell(
      row,
      deceptionTime(
        telemetry.first_seen
      )
    );

    deceptionCell(
      row,
      deceptionTime(
        telemetry.last_seen
      )
    );

    const action =
      document.createElement("td");

    const button =
      document.createElement("button");

    button.type = "button";
    button.className = "secondary";
    button.textContent = "Открыть";

    button.addEventListener(
      "click",
      () => {
        deceptionLoadCase(
          item.case_id
        );
      }
    );

    action.append(button);
    row.append(action);

    body.append(row);
  }

  if (!cases.length) {
    const row =
      document.createElement("tr");

    const cell =
      document.createElement("td");

    cell.colSpan = 7;

    cell.innerHTML = `
      <div class="secbox-empty-state">
        <strong>Cases отсутствуют</strong>
        <span>
          Deception ещё не фиксировал
          активности.
        </span>
      </div>
    `;

    row.append(cell);
    body.append(row);
  }
}


function deceptionRenderCase(item) {
  const root =
    document.getElementById(
      "deception-detail"
    );

  if (!root) {
    return;
  }

  root.replaceChildren();

  const telemetry =
    item.telemetry || {};

  const counts =
    telemetry.protocol_counts || {};

  const header =
    document.createElement("div");

  header.className =
    "secbox-page-section-header";

  const headingWrap =
    document.createElement("div");

  const heading =
    document.createElement("h3");

  heading.textContent =
    `Case ${item.case_id}`;

  const description =
    document.createElement("p");

  description.textContent =
    `${item.source_ip} · ` +
    `${telemetry.event_count ?? 0} event(s)`;

  headingWrap.append(
    heading,
    description
  );

  header.append(
    headingWrap,
    deceptionStatusBadge(
      item.status
    )
  );

  root.append(header);


  const summary =
    document.createElement("div");

  summary.className =
    "secbox-summary-grid";

  const summaryItems = [
    [
      "Source",
      item.source_ip,
    ],
    [
      "Status",
      item.status,
    ],
    [
      "Created",
      deceptionTime(
        item.created_at
      ),
    ],
    [
      "Expires",
      deceptionTime(
        item.expires_at
      ),
    ],
    [
      "Events",
      telemetry.event_count ?? 0,
    ],
    [
      "Protocols",
      Object.entries(counts)
        .map(
          ([name, value]) =>
            `${name.toUpperCase()}: ${value}`
        )
        .join(" · ") || "—",
    ],
  ];

  for (
    const [label, value]
    of summaryItems
  ) {
    const card =
      document.createElement("article");

    const labelNode =
      document.createElement("span");

    const valueNode =
      document.createElement("strong");

    labelNode.textContent = label;

    valueNode.textContent =
      String(value ?? "—");

    card.append(
      labelNode,
      valueNode
    );

    summary.append(card);
  }

  root.append(summary);


  const wrapper =
    document.createElement("div");

  wrapper.className =
    "secbox-table-shell";

  const table =
    document.createElement("table");

  table.innerHTML = `
    <thead>
      <tr>
        <th>Время</th>
        <th>Протокол</th>
        <th>Событие</th>
        <th>Детали</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const body =
    table.querySelector("tbody");

  for (
    const event
    of telemetry.events || []
  ) {
    const row =
      document.createElement("tr");

    deceptionCell(
      row,
      deceptionTime(
        event.timestamp
      )
    );

    deceptionCell(
      row,
      String(
        event.protocol || ""
      ).toUpperCase()
    );

    deceptionCell(
      row,
      event.event
    );

    const details =
      document.createElement("td");

    const code =
      document.createElement("code");

    code.textContent =
      JSON.stringify(
        event.details || {}
      );

    details.append(code);
    row.append(details);
    body.append(row);
  }

  if (!body.children.length) {
    const row =
      document.createElement("tr");

    const cell =
      document.createElement("td");

    cell.colSpan = 4;

    cell.innerHTML = `
      <div class="secbox-empty-state">
        <strong>Telemetry отсутствует</strong>
        <span>
          Для этого case события пока
          не зафиксированы.
        </span>
      </div>
    `;

    row.append(cell);
    body.append(row);
  }

  wrapper.append(table);
  root.append(wrapper);
}


async function deceptionLoadCase(
  caseId
) {
  const message =
    document.getElementById(
      "deception-message"
    );

  try {
    const item =
      await deceptionRequest(
        `/api/v1/deception/cases/${
          encodeURIComponent(caseId)
        }`
      );

    deceptionRenderCase(item);

    const detail =
      document.getElementById("deception-detail");

    if (detail) {
      detail.classList.add("deception-detail-focus");

      detail.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });

      detail.addEventListener(
        "animationend",
        () => detail.classList.remove(
          "deception-detail-focus"
        ),
        { once: true }
      );
    }

    if (message) {
      message.textContent =
        `Case ${caseId} загружен.`;

      message.className =
        "secbox-page-message good";
    }

  } catch (error) {
    if (message) {
      message.textContent =
        `Ошибка: ${error.message}`;

      message.className =
        "secbox-page-message error";
    }
  }
}


async function deceptionLoadCases(
  force = false
) {
  if (
    deceptionLoaded &&
    !force
  ) {
    return;
  }

  const message =
    document.getElementById(
      "deception-message"
    );

  try {
    const [
      data,
      quarantineData,
    ] = await Promise.all([
      deceptionRequest(
        "/api/v1/deception/cases"
      ),
      deceptionRequest(
        "/api/v1/deception/quarantine"
      ),
    ]);

    const cases =
      data.cases || [];

    const quarantine =
      quarantineData.quarantine || [];

    deceptionRenderCases(
      cases
    );

    deceptionRenderQuarantine(
      quarantine
    );

    deceptionLoaded = true;

    if (message) {
      message.textContent =
        `Cases: ${
          data.case_count ??
          cases.length
        } · Active quarantine: ${
          quarantineData.quarantine_count ??
          quarantine.length
        }`;

      message.className =
        "secbox-page-message good";
    }

    if (cases.length) {
      await deceptionLoadCase(
        cases[0].case_id
      );
    } else {
      const root =
        document.getElementById(
          "deception-detail"
        );

      root?.replaceChildren();
    }

  } catch (error) {
    if (message) {
      message.textContent =
        `Ошибка: ${error.message}`;

      message.className =
        "secbox-page-message error";
    }
  }
}


window.deceptionPageActivated =
function (page) {
  if (
    page === "monitor-deception"
  ) {
    deceptionLoadCases();
  }
};
