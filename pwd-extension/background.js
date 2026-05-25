const API_URL = "https://pwd-ai.onrender.com/api/check";

// =====================================
// SIMPLE INVALID URL CHECK
// =====================================
function isBasicInvalid(url) {

    try {

        const u = new URL(url);

        const hostname = u.hostname;

        // Ignore browser search pages
        if (
            url.includes("google.com/search") ||
            url.includes("?q=")
        ) {
            return true;
        }

        // Must contain dot
        if (!hostname.includes(".")) {
            return true;
        }

        return false;

    } catch {

        return true;
    }
}

// =====================================
// MAIN TAB LISTENER
// =====================================
chrome.tabs.onUpdated.addListener(

    async (tabId, changeInfo, tab) => {

        if (
            changeInfo.status !== "complete" ||
            !tab.url
        ) {
            return;
        }

        // Ignore internal browser pages
        if (
            tab.url.startsWith("chrome://") ||
            tab.url.startsWith("edge://") ||
            tab.url.startsWith("about:") ||
            tab.url.startsWith("file://")
        ) {
            return;
        }

        const finalURL = tab.url;

        // =====================================
        // ONLY BASIC INVALID CHECK
        // =====================================
        if (isBasicInvalid(finalURL)) {

            chrome.storage.local.set({
                status: "invalid"
            });

            chrome.action.setIcon({

                path: {
                    "16": "icons/invalid.png",
                    "48": "icons/invalid.png",
                    "128": "icons/invalid.png"
                }
            });

            return;
        }

        try {

            // =====================================
            // SEND FINAL URL TO API
            // =====================================
            const response = await fetch(API_URL, {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: finalURL
                })
            });

            if (!response.ok) {
                throw new Error("Server Error");
            }

            const data = await response.json();

            // Save result
            chrome.storage.local.set({
                status: data.result
            });

            // =====================================
            // 🚨 PHISHING
            // =====================================
            if (data.result === 1) {

                chrome.notifications.create({

                    type: "basic",

                    iconUrl: "icons/danger.png",

                    title: "⚠️ Phishing Alert",

                    message:
                        "This website may be dangerous!"
                });

                chrome.action.setIcon({

                    path: {
                        "16": "icons/danger.png",
                        "48": "icons/danger.png",
                        "128": "icons/danger.png"
                    }
                });
            }

            // =====================================
            // 🔵 INVALID
            // =====================================
            else if (
                data.result === "invalid"
            ) {

                chrome.action.setIcon({

                    path: {
                        "16": "icons/invalid.png",
                        "48": "icons/invalid.png",
                        "128": "icons/invalid.png"
                    }
                });
            }

            // =====================================
            // ✅ SAFE
            // =====================================
            else {

                chrome.action.setIcon({

                    path: {
                        "16": "icons/safe.png",
                        "48": "icons/safe.png",
                        "128": "icons/safe.png"
                    }
                });
            }

        } catch (err) {

            console.log(
                "API ERROR:",
                err
            );

            // Fallback icon
            chrome.action.setIcon({

                path: {
                    "16": "icons/invalid.png",
                    "48": "icons/invalid.png",
                    "128": "icons/invalid.png"
                }
            });
        }
    }
);
