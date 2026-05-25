from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import joblib
import math
import os

from urllib.parse import urlparse

import pandas as pd

from security_layer import *

app = Flask(__name__)
CORS(app)

# =================================
# LOAD ML MODEL
# =================================
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

model_path = os.path.join(
    BASE_DIR,
    "advanced_phishing_model.sav"
)

try:

    model = joblib.load(model_path)

except Exception as e:

    model = None

    print("⚠️ Model not loaded:", e)

# =================================
# LOAD TRUSTED DOMAINS TXT
# =================================
trusted_domains = set()

try:

    trusted_file = os.path.join(
        BASE_DIR,
        "website_url.txt"
    )

    with open(
        trusted_file,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            domain = line.strip().lower()

            # Remove protocols
            domain = domain.replace(
                "https://",
                ""
            )

            domain = domain.replace(
                "http://",
                ""
            )

            # Remove www
            if domain.startswith("www."):
                domain = domain[4:]

            # Remove path
            domain = domain.split("/")[0]

            if domain:
                trusted_domains.add(domain)

except Exception as e:

    print(
        "⚠️ Error loading trusted domains:",
        e
    )

# =================================
# TRUSTED DOMAIN CHECK
# =================================
def is_trusted_domain(domain):

    domain = domain.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    # Exact match
    if domain in trusted_domains:
        return True

    # Subdomains allowed
    for trusted in trusted_domains:

        if domain.endswith("." + trusted):
            return True

    return False

# =================================
# ENTROPY
# =================================
def entropy(text):

    if len(text) == 0:
        return 0

    prob = [
        text.count(c) / len(text)
        for c in set(text)
    ]

    return -sum([
        p * math.log2(p)
        for p in prob
    ])

# =================================
# FEATURE EXTRACTION
# =================================
def extract_features(url):

    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        int("https" in url),
        sum(c.isdigit() for c in url),
        entropy(url)
    ]

# =================================
# URL HIGHLIGHTING
# =================================
def highlight_url(url):

    highlighted = ""

    i = 0

    suspicious_words = [
        "login",
        "secure",
        "verify",
        "update"
    ]

    while i < len(url):

        c = url[i]

        # Highlight digits
        if c.isdigit():

            highlighted += (
                f"<span style='color:red'>"
                f"{c}</span>"
            )

            i += 1
            continue

        # Highlight suspicious chars
        if c in ["@", "-"]:

            highlighted += (
                f"<span style='color:red;"
                f"font-weight:bold'>{c}</span>"
            )

            i += 1
            continue

        matched = False

        # Highlight suspicious words
        for word in suspicious_words:

            if (
                url[i:i+len(word)].lower()
                == word
            ):

                highlighted += (
                    f"<span style='color:red;"
                    f"font-weight:bold'>"
                    f"{url[i:i+len(word)]}"
                    f"</span>"
                )

                i += len(word)

                matched = True

                break

        if matched:
            continue

        highlighted += c

        i += 1

    return highlighted

# =================================
# HOME PAGE
# =================================
@app.route("/")
def home():

    return render_template("index.html")

# =================================
# WEBSITE PREDICTION
# =================================
@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    try:

        url = request.form.get(
            "url",
            ""
        ).strip()

        if not url:

            return render_template(
                "index.html",
                prediction_text=
                "⚠️ Please enter a URL"
            )

        # =================================
        # NORMALIZE URL
        # =================================
        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url

        parsed = urlparse(url)

        url = parsed.geturl()

        domain = extract_domain(url)

        # =================================
        # ML FEATURES
        # =================================
        feature_names = [
            "length",
            "dots",
            "hyphens",
            "at",
            "https",
            "digits",
            "entropy"
        ]

        features = extract_features(url)

        features_df = pd.DataFrame(
            [features],
            columns=feature_names
        )

        ml_prob = 0.5

        ml_pred = 0

        if model:

            try:

                ml_prob = (
                    model.predict_proba(
                        features_df
                    )[0][1]
                )

                ml_pred = (
                    model.predict(
                        features_df
                    )[0]
                )

            except Exception as e:

                print("ML ERROR:", e)

        # =================================
        # DNS + SSL
        # =================================
        dns = check_dns(domain)

        ssl_status = check_ssl(url)

        # =================================
        # DECISION LOGIC
        # =================================
        reasons = []

        # 🔵 INVALID
        if is_invalid_domain(domain):

            prediction = (
                "⚠️ Invalid URL"
            )

            risk_score = 30

            reasons.append(
                "Invalid domain format"
            )

        # 🚨 CREDENTIAL
        elif has_credentials(url):

            prediction = (
                "🚨 Credential Injection Attack"
            )

            risk_score = 95

            reasons.append(
                "Contains '@' symbol"
            )

        # ✅ TRUSTED
        elif is_trusted_domain(domain):

            prediction = (
                "🟢 Legitimate Website"
            )

            risk_score = 5

            reasons.append(
                "Trusted domain whitelist"
            )

        # 🚨 BRAND ATTACK
        elif is_brand_attack(domain):

            prediction = (
                "🚨 Brand Impersonation"
            )

            risk_score = 98

            reasons.append(
                "Brand impersonation detected"
            )

        # ⚠️ SUSPICIOUS
        elif is_suspicious_domain(domain):

            prediction = (
                "⚠️ Suspicious Website"
            )

            risk_score = 70

            reasons.append(
                "Suspicious keywords found"
            )

        # 🤖 ML DETECTION
        else:

            if ml_pred == 1:

                prediction = (
                    "🚨 Phishing Website (ML)"
                )

                risk_score = round(
                    ml_prob * 100,
                    2
                )

                reasons.append(
                    "ML detected phishing pattern"
                )

            else:

                prediction = (
                    "🟢 Legitimate Website"
                )

                risk_score = round(
                    (1 - ml_prob) * 20,
                    2
                )

                reasons.append(
                    "ML classified safe"
                )

        # =================================
        # URL HIGHLIGHT
        # =================================
        highlighted_url = (
            highlight_url(url)
        )

        # =================================
        # SCREENSHOT
        # =================================
        screenshot = None

        try:

            if (
                not is_invalid_domain(domain)
                and dns
            ):

                screenshot = (
                    get_screenshot_url(url)
                )

        except:

            screenshot = None

        # =================================
        # RETURN RESULT
        # =================================
        return render_template(

            "index.html",

            prediction_text=prediction,

            url=url,

            highlighted_url=highlighted_url,

            confidence=risk_score,

            reasons=reasons,

            dns=dns,

            ssl=ssl_status,

            screenshot=screenshot
        )

    except Exception as e:

        print("ERROR:", e)

        return render_template(
            "index.html",
            prediction_text=
            "❌ Internal Server Error"
        )

# =================================
# API FOR EXTENSION
# =================================
@app.route(
    "/api/check",
    methods=["POST"]
)
def api_check():

    try:

        data = request.get_json()

        url = data.get(
            "url",
            ""
        ).strip()

        if not url:

            return jsonify({
                "result": 0
            })

        # =================================
        # NORMALIZE URL
        # =================================
        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url

        parsed = urlparse(url)

        url = parsed.geturl()

        domain = extract_domain(url)

        # 🔵 INVALID
        if is_invalid_domain(domain):

            return jsonify({
                "result": "invalid"
            })

        # 🚨 CREDENTIAL
        if has_credentials(url):

            return jsonify({
                "result": 1
            })

        # ✅ TRUSTED
        if is_trusted_domain(domain):

            return jsonify({
                "result": 0
            })

        # 🚨 BRAND ATTACK
        if is_brand_attack(domain):

            return jsonify({
                "result": 1
            })

        # ⚠️ SUSPICIOUS
        if is_suspicious_domain(domain):

            return jsonify({
                "result": 1
            })

        # =================================
        # ML CHECK
        # =================================
        if model:

            feature_names = [
                "length",
                "dots",
                "hyphens",
                "at",
                "https",
                "digits",
                "entropy"
            ]

            features = extract_features(url)

            features_df = pd.DataFrame(
                [features],
                columns=feature_names
            )

            ml_pred = (
                model.predict(
                    features_df
                )[0]
            )

            if ml_pred == 1:

                return jsonify({
                    "result": 1
                })

        # ✅ SAFE
        return jsonify({
            "result": 0
        })

    except Exception as e:

        print("API ERROR:", e)

        return jsonify({
            "result": 0
        })

# =================================
# RUN APP
# =================================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
