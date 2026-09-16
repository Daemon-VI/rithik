"""Every tunable number in the scam checker lives here, so tuning never means hunting through regexes.

A key is either a reason code ("otp_request") or a code plus a variant ("account_blocked.past").
The variant lets one reason fire at different strengths without inventing new codes that JSON
consumers would have to learn; the Reason that reaches the user always carries the bare code.
"""

from __future__ import annotations

# Rough scale: ~0.5-1 is a weak nudge, ~1.5-2 is a real red flag that still has innocent uses,
# 3+ is something a genuine sender essentially never asks for.
WEIGHTS: dict[str, float] = {
    # --- things legitimate senders never ask for -------------------------------------------
    "otp_request": 3.0,
    "upi_pin_to_receive": 3.0,
    "upi_collect_refund": 2.5,
    "remote_access_app": 2.5,
    "remote_access_app.install": 3.0,
    "apk_download": 3.0,
    "apk_download.file": 2.5,
    "digital_arrest": 3.5,
    "authority_threat": 2.5,
    "authority_threat.parcel_contraband": 3.0,
    "utility_disconnection": 3.0,
    "utility_disconnection.officer": 2.5,
    "utility_disconnection.bill": 2.0,
    "utility_disconnection.generic": 2.5,
    "investment_scheme.doubling": 3.0,
    "investment_scheme.daily": 2.5,
    # --- strong pretexts that genuine messages occasionally resemble ------------------------
    "kyc_update": 2.0,
    "account_blocked": 1.75,
    # A past-tense "your card has been blocked" is also how real banks confirm a block the
    # customer asked for, so on its own it must stay below the SUSPICIOUS line.
    "account_blocked.past": 0.75,
    "sim_deactivation": 2.0,
    "sim_deactivation.trai": 3.0,
    "prize_lottery": 2.5,
    # A lakh-sized win from a lottery or KBC is never real: nobody runs such draws by SMS.
    "prize_lottery.big": 3.0,
    "prize_lottery.kbc": 1.5,
    "prize_lottery.mention": 1.5,
    "task_job_offer": 2.0,
    "task_job_offer.task": 2.5,
    "task_job_offer.chat": 1.5,
    "parcel_held": 2.0,
    "parcel_held.address": 1.0,
    "loan_offer": 1.5,
    "loan_offer.no_checks": 2.0,
    "advance_fee": 1.5,
    # Genuine loan disbursal messages mention processing fees, so alone this stays quiet.
    "advance_fee.processing": 0.75,
    "reward_points": 1.75,
    # Insurers legitimately advertise "guaranteed returns"; only doubling or a daily
    # percentage is scam-only.
    "investment_scheme": 2.0,
    "investment_scheme.crypto": 1.5,
    "tax_refund": 2.0,
    "tax_refund.status": 1.0,
    "echallan": 0.5,
    # A challan notice is only a red flag once it carries a link that is not the government's.
    "echallan.link": 2.5,
    "mistaken_transfer": 1.5,
    # --- pressure language: never enough on its own ----------------------------------------
    "threat_of_loss": 1.25,
    "urgency": 0.75,
    "urgency.offer": 0.5,
    # --- link analysis ----------------------------------------------------------------------
    "url_brand_impersonation": 2.5,
    "url_apk": 2.5,
    "url_ip_host": 2.0,
    "url_punycode": 2.0,
    "url_userinfo": 2.0,
    "url_risky_tld": 1.5,
    "chat_link_money": 1.5,
    "url_shortener": 1.0,
    "url_many_subdomains": 1.0,
    "link_with_request": 1.0,
    "url_plain_http": 0.5,
    # --- reassuring patterns (negative) -----------------------------------------------------
    "official_link": -1.25,
    "otp_warning": -1.0,
}

# score = 1 - exp(-raw / SCORE_SCALE). With a scale of 3, one 3.0 signal lands at 0.63 and two
# of them at 0.86, so extra evidence keeps raising confidence without ever reaching 1.0.
SCORE_SCALE = 3.0

# In raw terms SCAM starts at ~2.75 (one never-legitimate ask, or two strong pretexts) and
# SUSPICIOUS at ~0.86 (anything above a single pressure word).
SCAM_THRESHOLD = 0.60
SUSPICIOUS_THRESHOLD = 0.25

# Once any single signal is this heavy, reassuring signals are dropped entirely: a scammer can
# paste a genuine bank link next to "send me the OTP", and that link must not buy them a pass.
STRONG_SIGNAL = 2.5

# Reassurance can offset weak pressure language, never a pile of red flags.
NEGATIVE_FLOOR = -1.5

# Evidence shown to the user is a pointer into the message, not a copy of it.
EVIDENCE_MAX_CHARS = 80

# Real messages carry a handful of links; beyond this we stop collecting so a pasted dump of
# thousands of domains cannot stall the checker.
MAX_URLS = 50
