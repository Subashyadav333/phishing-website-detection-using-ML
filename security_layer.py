import socket
import ssl

from urllib.parse import urlparse
from difflib import SequenceMatcher

# =================================
# KNOWN BRANDS
# =================================
KNOWN_BRANDS = [
    "google",
    "facebook",
    "amazon",
    "paypal",
    "microsoft",
    "apple",
    "yahoo",
    "bing",
    "instagram",
    "netflix"
]

# =================================
# EXTRACT DOMAIN
# =================================
def extract_domain(url):

    parsed = urlparse(url)

    netloc = parsed.netloc.lower()

    # Remove credentials
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # Remove port
    if ":" in netloc:
        netloc = netloc.split(":")[0]

    # Remove www
    if netloc.startswith("www."):
        netloc = netloc[4:]

    return netloc

# =================================
# INVALID DOMAIN CHECK
# =================================
VALID_TLDS = {
    "com", "org", "net", "edu", "gov",
    "io", "co", "in", "uk", "us",
    "biz", "info", "online", "site",
    "store", "xyz"
}

def is_invalid_domain(domain):

    # Must contain dot
    if "." not in domain:
        return True

    parts = domain.split(".")

    tld = parts[-1].lower()

    # TLD must contain only alphabets
    if not tld.isalpha():
        return True

    # Minimum TLD length
    if len(tld) < 2:
        return True

    # TLD must exist in valid list
    if tld not in VALID_TLDS:
        return True

    return False
# =================================
# CREDENTIAL INJECTION
# =================================
def has_credentials(url):

    return "@" in url

# =================================
# NORMALIZATION
# =================================
def normalize(text):

    return (
        text.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
    )

# =================================
# BRAND IMPERSONATION
# =================================
def is_brand_attack(domain):

    domain = domain.lower()

    # Remove www
    if domain.startswith("www."):
        domain = domain[4:]

    suspicious_keywords = [
        
        "verify",
        "update",
        "account",
        "signin",
        "bank"
    ]

    domain_name = domain.split(".")[0]

    clean_name = normalize(domain_name)

    for brand in KNOWN_BRANDS:

        # ✅ Exact brand safe
        if domain == brand + ".com":
            return False

        # ✅ Legit subdomain safe
        if domain.endswith("." + brand + ".com"):
            return False

        # 🔴 Typo attack
        if clean_name == brand and domain_name != brand:
            return True

        # 🔴 Similarity attack
        similarity = SequenceMatcher(
            None,
            clean_name,
            brand
        ).ratio()

        if similarity > 0.88 and clean_name != brand:
            return True

        # 🔴 Brand keyword phishing
        if brand in domain_name and clean_name != brand:

            for word in suspicious_keywords:

                if word in domain:
                    return True

            return True

    return False

# =================================
# SUSPICIOUS DOMAIN
# =================================
def is_suspicious_domain(domain):

    suspicious_words = [
        "login",
        "secure",
        "verify",
        "update",
        "signin",
        "account",
        "bank"
    ]

    return any(word in domain for word in suspicious_words)

# =================================
# DNS CHECK
# =================================
def check_dns(domain):

    try:

        socket.gethostbyname(domain)

        return True

    except:

        return False

# =================================
# SSL CHECK
# =================================
def check_ssl(url):

    try:

        if not url.startswith("https"):
            return False

        parsed = urlparse(url)

        hostname = parsed.netloc

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=3
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ):

                return True

    except:

        return False

# =================================
# WEBSITE SCREENSHOT
# =================================
def get_screenshot_url(url):

    return f"https://image.thum.io/get/{url}"
