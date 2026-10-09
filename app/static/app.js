function fallbackCopy(value) {
  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.left = "-9999px";
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_) {
    copied = false;
  }
  area.remove();
  return copied;
}

// Provide a fallback where navigator.clipboard is unavailable.
async function copyValue(value) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_) {
      return fallbackCopy(value);
    }
  }
  return fallbackCopy(value);
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = document.getElementById(button.dataset.copyTarget);
    const original = button.textContent;
    const title = button.title;
    const copied = input ? await copyValue(input.value) : false;
    button.textContent = copied ? "已复制" : "失败";
    button.title = copied ? "已复制" : "复制失败，请手动选中";
    button.setAttribute("aria-label", button.title);
    window.setTimeout(() => {
      button.textContent = original;
      button.title = title;
      button.setAttribute("aria-label", title);
    }, 1600);
  });
});

document.querySelectorAll(".howto-devices > .platform-block").forEach((platform) => {
  platform.addEventListener("toggle", () => {
    if (!platform.open) return;
    document.querySelectorAll(".howto-devices > .platform-block").forEach((other) => {
      if (other !== platform) other.open = false;
    });
  });
});

/* Expand and collapse connection details. */
document.querySelectorAll("[data-toggle-target]").forEach((button) => {
  const original = button.textContent.trim();
  const alt = button.dataset.toggleAlt || original;
  button.setAttribute("aria-controls", button.dataset.toggleTarget);
  button.setAttribute("aria-expanded", "false");
  button.addEventListener("click", () => {
    const panel = document.getElementById(button.dataset.toggleTarget);
    if (!panel) return;
    panel.hidden = !panel.hidden;
    button.textContent = panel.hidden ? original : alt;
    button.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
  });
});

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.passwordToggle);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
    button.textContent = input.type === "password" ? "显示" : "隐藏";
  });
});

document.querySelectorAll("form[data-confirm], form[data-wait-form]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
      return;
    }
    if (!form.hasAttribute("data-wait-form")) return;
    const button = form.querySelector("button[type='submit']");
    if (!button) return;
    button.disabled = true;
    button.textContent = button.dataset.waitText || "正在处理…";
  });
});

/* Persist the dismissed state of the first-run guide. */
(function () {
  const modal = document.getElementById("guide-modal");
  if (!modal) return;
  const dialog = modal.querySelector('[role="dialog"]');
  const DISMISS_KEY = "guide_dismissed";
  let returnFocus = null;

  function showStep(step) {
    modal.querySelectorAll("[data-guide-step]").forEach((section) => {
      section.hidden = Number(section.dataset.guideStep) !== step;
    });
    modal.querySelectorAll("[data-step-dot]").forEach((dot) => {
      const n = Number(dot.dataset.stepDot);
      dot.classList.toggle("on", n === step);
      dot.classList.toggle("done", n < step);
      if (n === step) dot.setAttribute("aria-current", "step");
      else dot.removeAttribute("aria-current");
    });
    dialog.setAttribute("aria-labelledby", step === 1 ? "guide-title" : "guide-title-" + step);
  }

  function open(step) {
    returnFocus = document.activeElement;
    showStep(step);
    modal.hidden = false;
    modal.removeAttribute("aria-hidden");
    document.body.classList.add("modal-open");
    const field = modal.querySelector('[data-guide-step="1"]:not([hidden]) input[name="name"]');
    if (field) field.focus();
  }

  function close() {
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
    document.body.classList.remove("modal-open");
    try {
      window.localStorage.setItem(DISMISS_KEY, "1");
    } catch (_) {
      /* localStorage may be unavailable in private browsing. */
    }
    if (returnFocus && typeof returnFocus.focus === "function") returnFocus.focus();
  }

  modal.querySelectorAll("[data-guide-close]").forEach((b) => b.addEventListener("click", close));
  modal.querySelectorAll("[data-guide-next]").forEach((b) => {
    b.addEventListener("click", () => showStep(Number(b.dataset.guideNext)));
  });
  // Close on backdrop clicks, not clicks inside the dialog.
  modal.addEventListener("click", (event) => {
    if (event.target === modal) close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modal.hidden) close();
    if (event.key === "Tab" && !modal.hidden) {
      const focusable = Array.from(dialog.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled])'
      )).filter((item) => !item.closest('[hidden]'));
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    }
  });
  document.querySelectorAll("[data-guide-open]").forEach((b) => {
    b.addEventListener("click", () => open(1));
  });

  const step = Number(modal.dataset.openStep || 0);
  let dismissed = false;
  try {
    dismissed = window.localStorage.getItem(DISMISS_KEY) === "1";
  } catch (_) {
    dismissed = false;
  }
  // Keep the guide open when returning from the add-user flow; the server marks
  // the very first dashboard visit so the guide opens even on a reused browser.
  const first = modal.dataset.first === "1";
  if (step === 2 || (step === 1 && (first || !dismissed))) open(step);
})();

/* Follow a panel update until it reports a final state. */
(function () {
  const box = document.getElementById("update-progress");
  if (!box) return;
  const title = box.querySelector("[data-update-title]");
  const message = box.querySelector("[data-update-message]");
  const hint = box.querySelector("[data-update-hint]");
  const back = box.querySelector("[data-update-done]");
  const titles = { done: "更新完成", latest: "已经是最新版本", failed: "更新没有完成" };
  const deadline = Date.now() + 20 * 60 * 1000;
  function finish(heading, text) {
    title.textContent = heading;
    message.textContent = text;
    hint.hidden = true;
    back.hidden = false;
  }
  async function poll() {
    try {
      const response = await fetch(box.dataset.statusUrl, { cache: "no-store", credentials: "same-origin" });
      if (response.ok) {
        const status = await response.json();
        if (status.message) message.textContent = status.message;
        if (titles[status.state]) return finish(titles[status.state], status.message || "");
      }
    } catch (_) {
      /* The panel is restarting during the update. */
    }
    if (Date.now() > deadline) {
      return finish("更新没有完成", "等了 20 分钟仍没有结果。请稍后打开设置页查看，或 SSH 运行 renrenvpn update 查看原因。");
    }
    setTimeout(poll, 5000);
  }
  setTimeout(poll, 3000);
})();
