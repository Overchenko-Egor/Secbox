"use strict";

const form =
  document.getElementById("login-form");

const username =
  document.getElementById("login-username");

const password =
  document.getElementById("login-password");

const error =
  document.getElementById("login-error");

const submit =
  document.getElementById("login-submit");

function targetPath() {
  const params =
    new URLSearchParams(
      window.location.search
    );

  const value =
    params.get("next") || "/";

  if (
    !value.startsWith("/")
    || value.startsWith("//")
    || value.startsWith("/login")
  ) {
    return "/";
  }

  return value;
}

form.addEventListener(
  "submit",
  async (event) => {
    event.preventDefault();

    error.textContent = "";
    submit.disabled = true;
    submit.textContent = "Вход…";

    try {
      const response = await fetch(
        "/api/v1/auth/login",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            username:
              username.value.trim(),
            password:
              password.value,
          }),
        }
      );

      let body = null;

      try {
        body = await response.json();
      } catch {
        body = null;
      }

      if (!response.ok) {
        throw new Error(
          body?.detail
          || "Неверное имя пользователя или пароль."
        );
      }

      window.location.replace(
        targetPath()
      );

    } catch (exception) {
      error.textContent =
        exception.message
        || "Ошибка авторизации.";

      password.select();

    } finally {
      submit.disabled = false;
      submit.textContent = "Войти";
    }
  }
);
