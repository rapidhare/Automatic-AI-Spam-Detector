from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse
import joblib
import numpy as np
import pandas as pd
import requests
from deep_translator import GoogleTranslator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

socket.setdefaulttimeout(1.5)

app = FastAPI(title="Spam Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

bundle = joblib.load("veritas_spam_model.joblib")
custom_model = bundle["model"]
model_acc = bundle["acc"]
model_f1 = bundle["f1"]
total_rows = bundle["rows"]

executor = ThreadPoolExecutor(max_workers=4)

TRUSTED_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "youtube.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.sg", "amazon.in"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "poslaju": ["pos.com.my"],
    "maybank": ["maybank2u.com.my", "maybank.com"],
    "cimb": ["cimbclicks.com.my", "cimb.com"],
    "netflix": ["netflix.com"],
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly",
    "shorturl.at", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".vip", ".click", ".loan", ".work",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".rest", ".cam",
}

NON_ENGLISH_HINT = re.compile(
    r"(?:[^\x00-\x7F]|\b(?:tahniah|akaun|digantung|sahkan|kata laluan|menang|hadiah|pautan|segera|sekatan|sila|anda|cuenta|suspendida|contraseña|urgente|premio|verifique|correo)\b)",
    re.IGNORECASE,
)


def extract_features(df_input):
    feats = pd.DataFrame(index=df_input.index)
    msg = df_input["message"].astype(str)
    msg_lower = msg.str.lower()
    char_len = msg.str.len().replace(0, 1)

    feats["digit_ratio"] = msg.str.count(r"\d") / char_len
    feats["has_long_number"] = msg.str.contains(r"\b\d{5,}\b", regex=True).astype(int)
    feats["has_currency"] = msg.str.contains(
        r"[$£€]|\brs\.?|\brm\s?\d|\busd\b|\bmyr\b", case=False, regex=True
    ).astype(int)
    feats["has_url"] = msg.str.contains(
        r"https?://|www\.|\.com|\.co\.uk|\.in|\.me|\.org|\.net|\.my|\.xyz|\.top|\.vip",
        case=False,
        regex=True,
    ).astype(int)
    feats["exclamation_count"] = msg.str.count(r"!")
    feats["uppercase_ratio"] = msg.str.count(r"[A-Z]") / char_len

    feats["credential_harvest_cues"] = msg_lower.str.count(
        r"\b(?:password|credential|credentials|login|log in|sign in|ssn|bank account|kyc|pin|otp|billing|wallet|verify your|confirm your|validate|security alert|new sign-in)\b"
    )
    feats["urgency_threat_cues"] = msg_lower.str.count(
        r"\b(?:suspended|locked|restricted|unauthorized|unusual activity|expire|expires|expired|immediately|urgent|action required|within 24 hours|deactivated|terminated|final reminder)\b"
    )
    feats["authority_impersonation"] = msg_lower.str.count(
        r"\b(?:it helpdesk|help desk|security team|support team|customer service|administrator|admin|paypal|microsoft|apple|google|irs|dhl|fedex|usps|poslaju|maybank|cimb)\b"
    )
    feats["payment_or_giftcard_lure"] = msg_lower.str.count(
        r"\b(?:gift card|gift cards|apple card|google play|steam card|bitcoin|crypto|usdt|wire transfer|western union|reimburse|cash reward|prize|claim)\b"
    )
    feats["job_or_easy_money_lure"] = msg_lower.str.count(
        r"\b(?:part-time|part time|work from home|remote job|remote reviewers|daily income|per day|daily|hiring|commission|whatsapp|telegram)\b"
    )
    feats["parcel_delivery_lure"] = msg_lower.str.count(
        r"\b(?:parcel|package|delivery failed|redelivery|incomplete address|customs|tracking|reschedule delivery)\b"
    )
    feats["wrong_number_lure"] = msg_lower.str.count(
        r"\b(?:lost my contacts|still your number|new phone|wrong number|bother you)\b"
    )
    feats["multilingual_scam_cues"] = msg_lower.str.count(
        r"(?:\b(?:tahniah|akaun|digantung|sahkan|kata laluan|menang|hadiah|pautan|segera|sekatan|cuenta|suspendida|contraseña|urgente|premio|verifique)\b|账户|密码|验证|中奖|链接)"
    )

    total_lures = (
        feats["credential_harvest_cues"]
        + feats["urgency_threat_cues"]
        + feats["payment_or_giftcard_lure"]
        + feats["job_or_easy_money_lure"]
        + feats["parcel_delivery_lure"]
        + feats["wrong_number_lure"]
        + feats["multilingual_scam_cues"]
    )
    raw_conv = msg_lower.str.count(
        r"\b(?:i|im|i'm|my|me|we|our|you|u|ur|hey|hi|thanks|thank|sorry|please|pls|ok|okay|lol|haha|regards|cheers)\b"
    )
    feats["pure_conversational_cues"] = np.where(total_lures == 0, raw_conv, 0)
    feats["total_scam_signals"] = (
        total_lures + feats["has_url"] + feats["has_long_number"] + feats["has_currency"]
    )
    return feats


def predict_probs(texts):
    temp_df = pd.DataFrame({"message": texts})
    temp_feats = extract_features(temp_df)
    temp_X = pd.concat([temp_df, temp_feats], axis=1)
    return custom_model.predict_proba(temp_X)[:, 1]


def _run_google_translate(masked_text):
    return GoogleTranslator(source="auto", target="en").translate(masked_text[:2000])


def translate_preserving_urls(text):
    # Skip external network translation completely for plain English text
    if not NON_ENGLISH_HINT.search(text):
        return text, False

    urls = re.findall(r"https?://\S+|www\.\S+", text)
    masked = text
    for idx, u in enumerate(urls):
        masked = masked.replace(u, f"URLTOKEN{idx}")

    translated_flag = False
    future = executor.submit(_run_google_translate, masked)
    try:
        translated = future.result(timeout=2.5)
        if translated and translated.strip().lower() != masked.strip().lower():
            translated_flag = True
        else:
            translated = masked
    except (FuturesTimeoutError, Exception):
        translated = masked

    for idx, u in enumerate(urls):
        translated = translated.replace(f"URLTOKEN{idx}", u)
    return translated, translated_flag


def is_public_hostname(hostname):
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip_obj = ipaddress.ip_address(info[4][0])
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return False
        return True
    except Exception:
        return False


def trace_safe_redirects(raw_url, max_hops=2):
    current = raw_url
    for _ in range(max_hops):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
            break
        host = (parsed.hostname or "").lower()
        if not is_public_hostname(host):
            break
        try:
            resp = requests.head(
                current,
                allow_redirects=False,
                timeout=1.5,
                headers={"User-Agent": "SpamDetector-LinkCheck/1.2"},
            )
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                current = urljoin(current, resp.headers["Location"])
            else:
                break
        except Exception:
            break
    return current


def analyze_sender(sender_name, sender_email, is_verified):
    findings = []
    risk_boost = 0.0

    name_lower = (sender_name or "").strip().lower()
    email_lower = (sender_email or "").strip().lower()
    domain = email_lower.split("@")[-1] if "@" in email_lower else ""

    if is_verified and domain:
        findings.append(f"Verified sender badge confirmed for {domain}")
        return -0.12, findings

    for brand, official_domains in TRUSTED_BRANDS.items():
        if brand in name_lower and domain:
            matches_official = any(
                domain == d or domain.endswith("." + d) for d in official_domains
            )
            if not matches_official:
                findings.append(
                    f'Sender claims to be "{sender_name}" but uses unverified domain "{domain}"'
                )
                risk_boost += 0.35
                break

    if domain and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        findings.append(f'Sender domain "{domain}" uses a high-risk top-level domain')
        risk_boost += 0.25

    return risk_boost, findings


def analyze_links(links):
    findings = []
    risk_boost = 0.0
    seen_hrefs = set()
    network_checks_used = 0

    for item in (links or [])[:5]:
        href = (item.get("href") or "").strip()
        visible = (item.get("text") or "").strip()
        if not href or href in seen_hrefs or not href.startswith(("http://", "https://")):
            continue
        seen_hrefs.add(href)

        parsed = urlparse(href)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if not host:
            continue

        if parsed.username or "@" in parsed.netloc:
            findings.append(f'Deceptive "@" credential-masking URL targeting "{host}"')
            risk_boost += 0.35

        if host.startswith("xn--") or ".xn--" in host:
            findings.append(f'Punycode lookalike domain detected ("{host}")')
            risk_boost += 0.35

        try:
            ipaddress.ip_address(host)
            findings.append(f'Link points directly to a raw IP address ("{host}")')
            risk_boost += 0.30
        except ValueError:
            pass

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append(f'Link leads to high-risk domain "{host}"')
            risk_boost += 0.22

        if re.match(r"^https?://", visible, re.IGNORECASE):
            vis_host = (urlparse(visible).hostname or "").lower().removeprefix("www.")
            if vis_host and vis_host != host:
                findings.append(
                    f'Mismatched link: visible text says "{vis_host}" but points to "{host}"'
                )
                risk_boost += 0.35

        # Only perform 1 live redirect check for URL shorteners so scans stay under 2s
        if host in SHORTENER_DOMAINS and network_checks_used < 1:
            network_checks_used += 1
            final_url = trace_safe_redirects(href)
            final_host = (urlparse(final_url).hostname or "").lower().removeprefix("www.")
            if final_host and final_host != host:
                findings.append(f'Shortened link ({host}) redirects to "{final_host}"')
                risk_boost += 0.12
                if any(final_host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    findings.append(f'Redirect destination "{final_host}" uses a high-risk TLD')
                    risk_boost += 0.25

    return min(risk_boost, 0.55), findings[:4]


class ScanRequest(BaseModel):
    message: str
    threshold: float = 0.50
    quick_mode: bool = False
    sender_name: str = ""
    sender_email: str = ""
    is_verified: bool = False
    links: list[dict] = []


@app.get("/")
def health_check():
    return {
        "status": "online",
        "model": "Spam Detector 98k Phishing & Scam Engine",
        "training_records": total_rows,
        "accuracy": round(model_acc, 4),
        "f1_score": round(model_f1, 4),
    }


@app.post("/scan_email")
def scan_email(req: ScanRequest):
    text = (req.message or "").strip()[:4000]
    if not text:
        return {
            "verdict": "SAFE",
            "spam_probability": 0.0,
            "ham_probability": 1.0,
            "top_triggers": [],
            "security_findings": [],
            "verified_sender": False,
        }

    eval_text, was_translated = translate_preserving_urls(text)
    words = re.findall(r"\S+", eval_text)
    eval_indices = [i for i, w in enumerate(words[:20]) if re.search(r"\w", w)]

    candidates = [eval_text] + [
        " ".join(words[:idx] + words[idx + 1 :]) for idx in eval_indices
    ]
    probs = predict_probs(candidates)
    base_spam_prob = float(probs[0])

    if req.quick_mode:
        sender_boost, link_boost, all_findings = 0.0, 0.0, []
    else:
        sender_boost, sender_findings = analyze_sender(
            req.sender_name, req.sender_email, req.is_verified
        )
        link_boost, link_findings = analyze_links(req.links)
        all_findings = sender_findings + link_findings

    adjusted_prob = float(np.clip(base_spam_prob + sender_boost + link_boost, 0.001, 0.999))

    suspicious_floor = max(0.30, req.threshold - 0.15)
    if adjusted_prob >= req.threshold:
        verdict = "SPAM"
    elif adjusted_prob >= suspicious_floor:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    top_triggers = []
    if len(eval_indices) > 1:
        impacts = [
            {
                "word": words[idx],
                "impact_pct": round((base_spam_prob - float(p)) * 100, 1),
            }
            for idx, p in zip(eval_indices, probs[1:])
            if (base_spam_prob - float(p)) * 100 > 0.5
        ]
        top_triggers = sorted(impacts, key=lambda x: x["impact_pct"], reverse=True)[:5]

    return {
        "verdict": verdict,
        "spam_probability": round(adjusted_prob, 4),
        "ham_probability": round(1.0 - adjusted_prob, 4),
        "top_triggers": top_triggers,
        "security_findings": all_findings,
        "verified_sender": False if req.quick_mode else bool(req.is_verified),
        "translated_text": eval_text if was_translated else None,
    }
