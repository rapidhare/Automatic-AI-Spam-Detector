import re
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from deep_translator import GoogleTranslator

app = FastAPI(title="Veritas AI Phishing & Scam API")

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

def extract_features(df_input):
    feats = pd.DataFrame(index=df_input.index)
    msg = df_input["message"].astype(str)
    msg_lower = msg.str.lower()
    char_len = msg.str.len().replace(0, 1)

    feats["digit_ratio"] = msg.str.count(r"\d") / char_len
    feats["has_long_number"] = msg.str.contains(r"\b\d{5,}\b", regex=True).astype(int)
    feats["has_currency"] = msg.str.contains(r"[$£€]|\brs\.?|\brm\s?\d|\busd\b|\bmyr\b", case=False, regex=True).astype(int)
    feats["has_url"] = msg.str.contains(r"https?://|www\.|\.com|\.co\.uk|\.in|\.me|\.org|\.net|\.my|\.xyz|\.top|\.vip", case=False, regex=True).astype(int)
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
    feats["total_scam_signals"] = total_lures + feats["has_url"] + feats["has_long_number"] + feats["has_currency"]
    return feats

def predict_probs(texts):
    temp_df = pd.DataFrame({"message": texts})
    temp_feats = extract_features(temp_df)
    temp_X = pd.concat([temp_df, temp_feats], axis=1)
    return custom_model.predict_proba(temp_X)[:, 1]

def translate_preserving_urls(text):
    urls = re.findall(r"https?://\S+|www\.\S+", text)
    masked = text
    for idx, u in enumerate(urls):
        masked = masked.replace(u, f"URLTOKEN{idx}")
    translated_flag = False
    try:
        translated = GoogleTranslator(source="auto", target="en").translate(masked[:4500])
        if translated and translated.strip().lower() != masked.strip().lower():
            translated_flag = True
        else:
            translated = masked
    except Exception:
        translated = masked
    for idx, u in enumerate(urls):
        translated = translated.replace(f"URLTOKEN{idx}", u)
    return translated, translated_flag

class ScanRequest(BaseModel):
    message: str
    threshold: float = 0.50

@app.get("/")
def health_check():
    return {
        "status": "online",
        "model": "Veritas AI 98k Phishing & Scam Detector",
        "training_records": total_rows,
        "accuracy": round(model_acc, 4),
        "f1_score": round(model_f1, 4),
    }

@app.post("/scan_email")
def scan_email(req: ScanRequest):
    text = (req.message or "").strip()
    if not text:
        return {"verdict": "SAFE", "spam_probability": 0.0, "ham_probability": 1.0, "top_triggers": []}

    eval_text, was_translated = translate_preserving_urls(text)
    words = re.findall(r"\S+", eval_text)
    eval_indices = [i for i, w in enumerate(words[:40]) if re.search(r"\w", w)]

    candidates = [eval_text] + [
        " ".join(words[:idx] + words[idx + 1:]) for idx in eval_indices
    ]
    probs = predict_probs(candidates)
    spam_prob = float(probs[0])

    suspicious_floor = max(0.30, req.threshold - 0.15)
    if spam_prob >= req.threshold:
        verdict = "SPAM"
    elif spam_prob >= suspicious_floor:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    top_triggers = []
    if len(eval_indices) > 1:
        impacts = [
            {"word": words[idx], "impact_pct": round((spam_prob - float(p)) * 100, 1)}
            for idx, p in zip(eval_indices, probs[1:])
            if (spam_prob - float(p)) * 100 > 0.5
        ]
        top_triggers = sorted(impacts, key=lambda x: x["impact_pct"], reverse=True)[:5]

    return {
        "verdict": verdict,
        "spam_probability": round(spam_prob, 4),
        "ham_probability": round(1.0 - spam_prob, 4),
        "top_triggers": top_triggers,
        "translated_text": eval_text if was_translated else None,
    }