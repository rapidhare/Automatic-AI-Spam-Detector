# Spam Detector: AI Phishing & Scam Protection for Webmail

**Spam Detector** is an explainable machine learning Chrome extension that protects users from phishing emails, scam links, and fraudulent messages in real time. Built for Gmail and Outlook Web, it scans incoming emails automatically, flags risky messages directly in the inbox list, and explains *why* a message was flagged so users can make informed decisions.

---

## Features

1. **Automatic Scanning**
   When you open your Webmail, the AI will automatically scan your emails for spam and show a red indicator on them when it detects them as spam

2. **Certainty & description**
   When the AI detects spam emails, it will tell you its % certainty reasoning

3. **Automatic spam folder**
   The User can set a % certainty threshold at which the AI will automatically filter emails and put them in a spam folder

4. **22 supported languages**
   Please expect an additional 2-5 second delay with translations, as they have to go through a Google Translation layer, which in some instances can cause delays.
   The current supported languages are:
   - English
   - Chinese Simplified (中文 简体)
   - Chinese Traditional (中文 繁體)
   - Spanish (Español)
   - French (Français)
   - German (Deutsch)
   - Portuguese (Português)
   - Italian (Italiano)
   - Dutch (Nederlands)
   - Swedish (Svenska)
   - Polish (Polski)
   - Hindi (हिन्दी)
   - Russian (Русский)
   - Japanese (日本語)
   - Korean (한국어)
   - Arabic (العربية)
   - Turkish (Türkçe)
   - Bahasa Melayu (Malay)
   - Bahasa Indonesia (Indonesian)
   - Tagalog (Filipino)
   - Vietnamese (Tiếng Việt)
   - Thai (ไทย)
  
## Installation
**PLEASE NOTE: This release supports only Chromium-based browsers (Chrome, Brave, Microsoft Edge, etc.). For Webmail, currently only Gmail is supported.** 
1. **Download the Extension Folder**
   Download and unzip the extension folder (`spam_detect_v1.0.0`) onto your computer (e.g., on your Desktop).
2. **Open Chrome Extensions**
   Open Google Chrome, type `chrome://extensions` into the address bar, and press **Enter**.
3. **Enable Developer Mode**
   Turn on the **Developer mode** toggle switch in the top-right corner of the page.
4. **Load the Extension**
   Click **Load unpacked** in the top-left corner and select the unzipped extension folder (the folder containing `manifest.json`).
5. **Pin to Toolbar**
   Click the puzzle-piece **Extensions** icon in the top-right corner of Chrome and click the **Pin** icon next to **Spam Detector**.

## How It Works

1. **Lightweight Browser Extension (Manifest V3)**
   The Chrome extension reads visible email text, sender details (including Gmail's Verified Sender checkmark), and destination links locally in the browser without storing personal emails.

2. **Hybrid Machine Learning Engine (98,150 Training Records)**
   Message content is analyzed by a cloud FastAPI backend running a custom-trained Scikit-Learn model (**98.34% accuracy**, **0.9785 F1 score**). Instead of relying on simple keyword blacklists, the model combines:
   - **Word & Character N-Gram TF-IDF:** Captures both full phrases (1–3 words) and subword spelling tricks/typosquatting (3–5 characters).
   - **16 Engineered Phishing Signals:** Detects urgency threats, credential-harvesting requests, gift-card/crypto lures, suspicious currency/number patterns, and multilingual scam cues.
   - **Multilingual Support:** Automatically translates non-English messages while preserving URLs intact for accurate risk scoring.

3. **Sender & Link Verification**
   - **Verified Sender Recognition:** Detects Gmail's official Verified Sender badge and checks whether links match the sender's real domain, preventing false alarms on legitimate verification codes.
   - **Impersonation & Link Checks:** Flags mismatched display names (e.g., claiming to be a major bank or service from a free webmail address), punycode lookalike domains, raw IP URLs, and shortened link redirects.

4. **Explainable Results & Optional Auto-Quarantine**
   - Displays a colour-coded security banner (`SAFE`, `SUSPICIOUS`, or `SPAM`) above opened emails showing the exact risk percentage, specific trigger words, and a reminder to read carefully since no automated detector is 100% accurate.
   - Includes an optional **Auto-Move** toggle with an adjustable AI certainty slider (60%–99%) to automatically move high-confidence spam into Gmail's Spam folder or a custom label.

### Quick Testing Guide
- **Test in Gmail:** Open [mail.google.com](https://mail.google.com) and click any email. A **Spam Detector** banner will appear automatically above the email body, and flagged inbox rows will display a red `!` icon. *(Note: The backend runs on a free cloud instance that sleeps after 15 minutes of inactivity; if it is asleep, the first scan takes ~20–30 seconds to wake up, after which scans complete in ~1–2 seconds.)*
- **Test with Custom Messages:** Click the **Spam Detector** icon in your Chrome toolbar, paste any sample phishing or legitimate message into **Quick Text / SMS Scan**, and click **Analyze Text**.

---

## Key Features

- **Inbox List Warning Badges:** Places a red `!` badge on the right side of flagged emails in the Gmail inbox list so users can spot potential spam before opening it.
- **Automatic In-Email Banner:** Scans opened emails automatically and highlights the exact phrases or link anomalies that triggered the alert.
- **Auto-Move Controls:** Toggle automatic filtering on/off in the popup and set your preferred certainty threshold and destination folder.
- **Quick Text / SMS Scanner:** Paste any suspicious SMS, WhatsApp message, or email text into the extension popup for an instant risk check.

---

## Training Datasets & Tech Stack Credits

- **Phishing Email Dataset (`zefang-liu/phishing-email-dataset`):** Enron, SpamAssassin, and Nazario phishing email corpora.
- **DIFrauD Corpus (`redasers/difraud`):** Multi-domain phishing benchmark dataset from the ReDAS Lab (University of Houston).
- **Multi-Source SMS Spam Dataset:** Combined SMS spam/ham corpus.
- **Technologies:** Python, Scikit-Learn, FastAPI, Uvicorn, `deep-translator`, and Chrome Extension Manifest V3 (JavaScript/HTML/CSS).
