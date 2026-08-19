"""Shared signals for brand impersonation and risky domains."""

BRANDS = {
    # Indian banks, payments, marketplaces, and telecom
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "googlepay",
    "kotak", "yesbank", "indusind", "flipkart", "jio", "airtel", "vodafone",
    "myntra",
    # Global technology and social platforms
    "google", "amazon", "whatsapp", "telegram", "microsoft", "apple",
    "facebook", "instagram", "netflix", "linkedin", "twitter", "yahoo",
    "outlook", "dropbox", "adobe",
    # Payments and commerce
    "paypal", "ebay", "stripe", "visa", "mastercard", "americanexpress",
    # Banks
    "chase", "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
    # Couriers
    "dhl", "fedex", "ups", "usps",
}

HIGH_RISK_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "tk", "ml", "ga", "cf", "gq",
}

SUSPICIOUS_HOSTNAME_PREFIXES = (
    "secure-", "verify-", "login-", "account-", "update-",
)
