"use strict";

const byId = (id) =>
  document.getElementById(id);

let currentUser = null;

async function request(
  path,
  options = {}
) {
  const response = await fetch(
    path,
    {
      credentials: "same-origin",
      ...options,
    }
  );

  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (response.status === 401) {
    window.location.replace(
      `/login?next=${encodeURIComponent(
        window.location.pathname
      )}`
    );

    throw new Error(
      "Сессия завершена."
    );
  }

  if (!response.ok) {
    throw new Error(
      body?.detail
      || body?.error
      || `HTTP ${response.status}`
    );
  }

  return body;
}

function message(
  value,
  type = ""
) {
  const node = byId(
    "users-message"
  );

  node.textContent = value;
  node.className = type;
}

async function loadMe() {
  const body = await request(
    "/api/v1/auth/me"
  );

  currentUser = body.username;

  byId("current-user").textContent =
    body.username;
}

function actionButton(
  text,
  className,
  onClick
) {
  const button =
    document.createElement(
      "button"
    );

  button.type = "button";
  button.textContent = text;
  button.className = className;
  button.addEventListener(
    "click",
    onClick
  );

  return button;
}

function renderUsers(users) {
  const body =
    byId("users-body");

  body.replaceChildren();

  for (const user of users) {
    const row =
      document.createElement("tr");

    const username =
      document.createElement("td");

    username.textContent =
      user.username;

    const role =
      document.createElement("td");

    role.textContent =
      user.role;

    const status =
      document.createElement("td");

    status.textContent =
      user.enabled
        ? "Активен"
        : "Отключён";

    const actions =
      document.createElement("td");

    actions.className =
      "users-row-actions";

    actions.append(
      actionButton(
        "Сменить пароль",
        "secondary",
        () => {
          byId(
            "password-username"
          ).value = user.username;

          byId(
            "password-title"
          ).textContent =
            `Смена пароля: ${
              user.username
            }`;

          byId(
            "password-panel"
          ).hidden = false;

          byId(
            "change-password"
          ).focus();
        }
      )
    );

    if (
      user.username
      !== currentUser
    ) {
      actions.append(
        actionButton(
          "Удалить",
          "danger-button",
          async () => {
            if (
              !window.confirm(
                `Удалить пользователя "${
                  user.username
                }"?`
              )
            ) {
              return;
            }

            try {
              await request(
                `/api/v1/users/${
                  encodeURIComponent(
                    user.username
                  )
                }`,
                {
                  method: "DELETE",
                }
              );

              message(
                "Пользователь удалён.",
                "good"
              );

              await loadUsers();

            } catch (error) {
              message(
                error.message,
                "error"
              );
            }
          }
        )
      );
    }

    row.append(
      username,
      role,
      status,
      actions
    );

    body.append(row);
  }
}

async function loadUsers() {
  try {
    const body = await request(
      "/api/v1/users"
    );

    renderUsers(
      body.users || []
    );

  } catch (error) {
    message(
      error.message,
      "error"
    );
  }
}

byId(
  "create-user-form"
).addEventListener(
  "submit",
  async (event) => {
    event.preventDefault();

    const username =
      byId(
        "new-username"
      ).value.trim();

    const password =
      byId(
        "new-password"
      ).value;

    const repeat =
      byId(
        "new-password-repeat"
      ).value;

    if (password !== repeat) {
      message(
        "Пароли не совпадают.",
        "error"
      );

      return;
    }

    try {
      await request(
        "/api/v1/users",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            username,
            password,
          }),
        }
      );

      event.target.reset();

      message(
        "Пользователь создан.",
        "good"
      );

      await loadUsers();

    } catch (error) {
      message(
        error.message,
        "error"
      );
    }
  }
);

byId(
  "password-form"
).addEventListener(
  "submit",
  async (event) => {
    event.preventDefault();

    const username =
      byId(
        "password-username"
      ).value;

    const password =
      byId(
        "change-password"
      ).value;

    const repeat =
      byId(
        "change-password-repeat"
      ).value;

    if (password !== repeat) {
      message(
        "Пароли не совпадают.",
        "error"
      );

      return;
    }

    try {
      await request(
        `/api/v1/users/${
          encodeURIComponent(
            username
          )
        }/password`,
        {
          method: "PUT",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            password,
          }),
        }
      );

      event.target.reset();

      byId(
        "password-panel"
      ).hidden = true;

      if (
        username === currentUser
      ) {
        alert(
          "Пароль изменён. "
          + "Необходимо войти заново."
        );

        window.location.replace(
          "/login"
        );

        return;
      }

      message(
        "Пароль изменён.",
        "good"
      );

    } catch (error) {
      message(
        error.message,
        "error"
      );
    }
  }
);

byId(
  "password-cancel"
).addEventListener(
  "click",
  () => {
    byId(
      "password-panel"
    ).hidden = true;

    byId(
      "password-form"
    ).reset();
  }
);

byId(
  "users-refresh"
).addEventListener(
  "click",
  loadUsers
);

byId(
  "logout"
).addEventListener(
  "click",
  async () => {
    await fetch(
      "/api/v1/auth/logout",
      {
        method: "POST",
        credentials:
          "same-origin",
      }
    );

    window.location.replace(
      "/login"
    );
  }
);

(async () => {
  try {
    await loadMe();
    await loadUsers();

  } catch (error) {
    message(
      error.message,
      "error"
    );
  }
})();
