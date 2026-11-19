/* Shared Orochi UI helpers: theme toggle, password visibility, and #modal-update lifecycle */
(function () {
  "use strict";

  var lastModalInvoker = null;

  function applyStoredThemeFromStorage() {
    var stored = null;
    try {
      stored = localStorage.getItem("color-theme");
    } catch (e) {
      stored = null;
    }
    var prefersDark =
      window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    var isDark = stored === "dark" || (!stored && prefersDark);
    document.documentElement.classList.toggle("dark", isDark);
    syncThemeToggleUI();
    var activePopup = document.querySelector(".swal2-popup");
    if (activePopup && typeof window.applySwalTheme === "function") {
      window.applySwalTheme(activePopup);
    }
  }

  function syncThemeToggleUI() {
    var darkIcon = document.getElementById("theme-toggle-dark-icon");
    var lightIcon = document.getElementById("theme-toggle-light-icon");
    var toggleText = document.getElementById("theme-toggle-text");
    var isDark = document.documentElement.classList.contains("dark");
    if (darkIcon && lightIcon) {
      darkIcon.classList.toggle("hidden", isDark);
      lightIcon.classList.toggle("hidden", !isDark);
    }
    if (toggleText) {
      toggleText.textContent = isDark ? "Light Mode" : "Dark Mode";
    }
    var meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) {
      var stored = null;
      try {
        stored = localStorage.getItem("color-theme");
      } catch (e) {
        stored = null;
      }
      meta.content = stored ? (isDark ? "dark" : "light") : "light dark";
    }
  }

  window.syncThemeToggleUI = syncThemeToggleUI;

  window.openOrochiModal = function (widthClass) {
    var modal = document.getElementById("modal-update");
    if (!modal) return;
    if (modal.classList.contains("hidden") && document.activeElement instanceof HTMLElement) {
      lastModalInvoker = document.activeElement;
    }
    var wrapper = modal.firstElementChild;
    if (wrapper) {
      wrapper.classList.remove(
        "max-w-md",
        "max-w-xl",
        "max-w-2xl",
        "max-w-3xl",
        "max-w-4xl",
        "max-w-5xl",
        "max-w-6xl",
        "max-w-7xl"
      );
      wrapper.classList.add(widthClass || "max-w-2xl");
    }
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    modal.setAttribute("aria-hidden", "false");
    modal.setAttribute("aria-modal", "true");
  };

  window.closeOrochiModal = function () {
    var modal = document.getElementById("modal-update");
    if (!modal) return;
    modal.classList.add("hidden");
    modal.classList.remove("flex");
    modal.setAttribute("aria-hidden", "true");
    modal.removeAttribute("aria-modal");
    var wrapper = modal.firstElementChild;
    if (wrapper) {
      wrapper.classList.remove(
        "max-w-3xl",
        "max-w-4xl",
        "max-w-5xl",
        "max-w-6xl",
        "max-w-7xl"
      );
      if (!wrapper.classList.contains("max-w-2xl")) {
        wrapper.classList.add("max-w-2xl");
      }
    }
    if (lastModalInvoker && document.contains(lastModalInvoker)) {
      try {
        lastModalInvoker.focus();
      } catch (e) {
        // Ignore focus errors on non-focusable elements
      }
    }
    lastModalInvoker = null;
  };

  document.addEventListener("DOMContentLoaded", function () {
    // 1. Accessible password visibility toggle
    document.addEventListener("click", function (e) {
      var btn = e.target.closest(".toggle-password-visibility");
      if (!btn) return;
      var input = document.getElementById(btn.getAttribute("data-target"));
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
      var icon = btn.querySelector("i, svg");
      if (icon) {
        icon.classList.toggle("fa-eye", !show);
        icon.classList.toggle("fa-eye-slash", show);
      }
    });

    // 2. Theme toggle + cross-tab storage synchronization
    syncThemeToggleUI();
    var themeToggleBtn = document.getElementById("theme-toggle");
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", function () {
        var nextDark = !document.documentElement.classList.contains("dark");
        document.documentElement.classList.toggle("dark", nextDark);
        try {
          localStorage.setItem("color-theme", nextDark ? "dark" : "light");
        } catch (e) {
          // Storage disabled; theme still applies for current page
        }
        syncThemeToggleUI();
        var activePopup = document.querySelector(".swal2-popup");
        if (activePopup && typeof window.applySwalTheme === "function") {
          window.applySwalTheme(activePopup);
        }
      });
    }
    window.addEventListener("storage", function (e) {
      if (e.key === "color-theme") {
        applyStoredThemeFromStorage();
      }
    });

    // 3. Universal #modal-update HTMX, backdrop, Escape & dismiss handlers
    if (document.body) {
      document.body.addEventListener("htmx:beforeRequest", function (evt) {
        if (evt.detail && evt.detail.target && evt.detail.target.id === "orochi-modal-content") {
          evt.detail.target.innerHTML =
            '<div class="p-8 text-center text-xs text-zinc-500 dark:text-zinc-400">' +
            '<i class="fas fa-spinner fa-spin mr-2"></i>Loading...</div>';
          window.openOrochiModal("max-w-2xl");
        }
      });

      document.body.addEventListener("closeModal", function () {
        window.closeOrochiModal();
      });

      document.body.addEventListener("showMessage", function (evt) {
        if (typeof window.toast === "function" && evt.detail) {
          window.toast(evt.detail);
        }
      });
    }

    document.addEventListener("click", function (e) {
      var modal = document.getElementById("modal-update");
      if (modal && e.target === modal) {
        window.closeOrochiModal();
        return;
      }
      var dismissBtn = e.target.closest(
        '[data-modal-hide="modal-update"], [data-modal-dismiss="modal-update"]'
      );
      if (dismissBtn) {
        e.preventDefault();
        window.closeOrochiModal();
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        var modal = document.getElementById("modal-update");
        if (modal && !modal.classList.contains("hidden")) {
          window.closeOrochiModal();
        }
      }
    });
  });
})();
