document.addEventListener("DOMContentLoaded", () => {

    chrome.storage.local.get("status", (data) => {

        const el = document.getElementById("status");

        if (data.status === "invalid") {
            el.textContent = "🔵 Not a valid website";
            el.className = "status invalid";

        } else if (data.status === 1) {
            el.textContent = "⚠️ Dangerous Website";
            el.className = "status danger";

        } else {
            el.textContent = "✅ Safe Website";
            el.className = "status safe";
        }
    });

});