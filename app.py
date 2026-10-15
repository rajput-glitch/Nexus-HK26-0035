import os
import re
import io
import json
import hashlib
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from flask import (
    Flask, request, render_template_string,
    flash, redirect, url_for
)
from werkzeug.utils import secure_filename
from PIL import Image, ExifTags, UnidentifiedImageError

try:
    import cv2
    import numpy as np
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


app = Flask(__name__)
app.secret_key = os.environ.get("TRUSTRA_SECRET", "change-this-local-secret")
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_MEDIA = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif",
    ".bmp", ".mp4", ".mov", ".mp3", ".wav",
    ".pdf", ".txt"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".click", ".top", ".work",
    ".country", ".gq", ".tk", ".xyz"
}

# All analysis is performed locally. Submitted URLs are never visited.


def result_report(title, score, findings, summary=None):
    score = max(0, min(100, int(score)))

    if score >= 65:
        level = "HIGH RISK"
        color = "danger"
    elif score >= 30:
        level = "SUSPICIOUS"
        color = "warning"
    else:
        level = "LOW INDICATED RISK"
        color = "safe"

    return {
        "title": title,
        "score": score,
        "level": level,
        "color": color,
        "findings": findings,
        "summary": summary or
            "This result is based on local indicators, not a guarantee of safety."
    }


def analyze_link(raw_url):
    findings = []
    score = 0
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return result_report(
            "Link Analysis", 0,
            ["No URL was supplied."],
            "Enter a URL to analyze."
        )

    # Accept a bare hostname by adding HTTPS for parsing only.
    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return result_report(
            "Link Analysis", 80,
            ["The URL could not be parsed reliably."],
            "Treat this URL cautiously."
        )

    if not host:
        findings.append("No valid hostname could be extracted.")
        score += 40
    else:
        findings.append("Hostname extracted: " + host)

    if parsed.scheme.lower() not in ("https", "http"):
        findings.append("Unusual or potentially unsafe URL scheme.")
        score += 45
    elif parsed.scheme.lower() == "http":
        findings.append("HTTP is used instead of encrypted HTTPS.")
        score += 10

    if "@" in parsed.netloc:
        findings.append("The URL contains '@', which can disguise its destination.")
        score += 25

    if host and host in SHORTENERS:
        findings.append("The hostname belongs to a known URL-shortening service.")
        score += 25

    if host and host.startswith("xn--"):
        findings.append("The hostname contains an internationalized/punycode label.")
        score += 20

    if host and any(label.startswith("xn--") for label in host.split(".")):
        findings.append("Punycode may conceal visually similar characters.")
        score += 15

    try:
        ipaddress.ip_address(host)
        findings.append("The URL uses a raw IP address instead of a domain name.")
        score += 20
    except ValueError:
        pass

    if host and any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        findings.append("The domain uses a TLD that warrants additional scrutiny.")
        score += 15

    if host.count("-") >= 3:
        findings.append("The hostname contains multiple hyphens.")
        score += 10

    if len(host) > 50:
        findings.append("The hostname is unusually long.")
        score += 10

    if re.search(r"(login|verify|secure|account|password|wallet|bank)", host):
        findings.append("The hostname contains account or authentication-related terms.")
        score += 10

    if parsed.scheme == "https":
        findings.append("HTTPS is present; this alone does not establish trustworthiness.")

    if not findings:
        findings.append("No configured suspicious URL indicators were found.")

    return result_report(
        "Link Analysis", score, findings,
        "Heuristic URL inspection only. The destination was not opened, "
        "and no reputation service was queried."
    )


def analyze_email(sender_name, sender_email, reply_to, subject, message):
    findings = []
    score = 0

    combined = " ".join([
        sender_name or "", sender_email or "",
        reply_to or "", subject or "", message or ""
    ]).lower()

    urgency_patterns = [
        r"\bimmediately\b", r"\burgent\b", r"\bwithin 24 hours\b",
        r"\baccount will be suspended\b", r"\blast warning\b",
        r"\bact now\b", r"\bexpires today\b"
    ]
    credential_patterns = [
        r"\bpassword\b", r"\botp\b", r"\bone.time password\b",
        r"\bverification code\b", r"\bcredentials\b",
        r"\bconfirm your account\b", r"\blog in to verify\b"
    ]
    payment_patterns = [
        r"\bgift card\b", r"\bwire transfer\b",
        r"\bcrypto payment\b", r"\bpay immediately\b",
        r"\bpayment required\b", r"\bbank details\b"
    ]
    secrecy_patterns = [
        r"\bkeep this confidential\b", r"\bdo not tell anyone\b",
        r"\bdo not discuss\b", r"\bsecret transaction\b"
    ]

    def match_group(patterns, label, points):
        nonlocal score
        if any(re.search(pattern, combined) for pattern in patterns):
            findings.append(label)
            score += points

    match_group(
        urgency_patterns,
        "Urgency or account-pressure language detected.", 20
    )
    match_group(
        credential_patterns,
        "Possible request for credentials or verification codes.", 25
    )
    match_group(
        payment_patterns,
        "Payment or financial manipulation language detected.", 25
    )
    match_group(
        secrecy_patterns,
        "Language encouraging secrecy was detected.", 15
    )

    urls = re.findall(r"https?://[^\s<>\"']+", message or "", re.I)
    if urls:
        findings.append(f"{len(urls)} URL(s) found in the message.")
        score += min(20, len(urls) * 5)

    if sender_email and reply_to:
        try:
            sender_domain = sender_email.rsplit("@", 1)[1].lower()
            reply_domain = reply_to.rsplit("@", 1)[1].lower()
            if sender_domain != reply_domain:
                findings.append(
                    "Reply-to domain differs from sender domain."
                )
                score += 25
        except (IndexError, AttributeError):
            findings.append("Sender or reply-to email format may be invalid.")
            score += 10

    if sender_email and not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender_email
    ):
        findings.append("Sender email format appears invalid.")
        score += 10

    if not findings:
        findings.append("No configured phishing language indicators were detected.")

    return result_report(
        "Email Analysis", score, findings,
        "Rule-based screening, not a trained AI model. Email authentication "
        "records and the actual sender identity have not been verified."
    )


def analyze_qr(file_storage):
    if not QR_AVAILABLE:
        return result_report(
            "QR Analysis", 0,
            ["QR decoding is unavailable because OpenCV is not installed."],
            "Install dependencies from requirements.txt."
        )

    try:
        data = file_storage.read()
        image_array = np.frombuffer(data, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            return result_report(
                "QR Analysis", 0,
                ["The uploaded file could not be read as an image."]
            )

        detector = cv2.QRCodeDetector()
        decoded, points, _ = detector.detectAndDecode(image)

        if not decoded:
            return result_report(
                "QR Analysis", 0,
                ["No decodable QR code was found in this image."],
                "Try a clearer image with the complete QR code visible."
            )

        findings = ["QR content successfully decoded."]

        if decoded.lower().startswith(("http://", "https://")):
            link_result = analyze_link(decoded)
            findings.append("Decoded content is a URL.")
            findings.extend(link_result["findings"])

            return result_report(
                "QR Analysis", link_result["score"], findings,
                "Decoded content: " + decoded +
                ". URL checks were performed locally; the URL was not opened."
            )

        findings.append("The QR code contains non-URL content.")
        return result_report(
            "QR Analysis", 5, findings,
            "Decoded content: " + decoded[:500]
        )

    except Exception as exc:
        app.logger.warning("QR analysis failed: %s", exc)
        return result_report(
            "QR Analysis", 0,
            ["The image could not be analyzed."]
        )


def analyze_media(file_storage):
    findings = []
    score = 0

    filename = secure_filename(file_storage.filename or "upload")
    extension = os.path.splitext(filename)[1].lower()

    if extension not in ALLOWED_MEDIA:
        return result_report(
            "Media Analysis", 0,
            ["Unsupported file extension."],
            "Allowed formats: common images, MP4, MOV, MP3, WAV, PDF, and TXT."
        )

    content = file_storage.read()
    if not content:
        return result_report(
            "Media Analysis", 0, ["The uploaded file is empty."]
        )

    digest = hashlib.sha256(content).hexdigest()
    findings.append("SHA-256: " + digest)
    findings.append(f"File size: {len(content):,} bytes.")
    findings.append("File extension: " + extension)

    # Check whether the extension matches recognizable file content.
    signature_map = {
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".gif": content.startswith((b"GIF87a", b"GIF89a")),
        ".pdf": content.startswith(b"%PDF-"),
        ".mp3": content.startswith(b"ID3") or content.startswith(b"\xff\xfb"),
        ".wav": content.startswith(b"RIFF") and content[8:12] == b"WAVE",
        ".mp4": len(content) >= 12 and content[4:8] == b"ftyp",
        ".mov": len(content) >= 12 and content[4:8] == b"ftyp",
    }

    if extension in signature_map:
        if signature_map[extension]:
            findings.append("File signature is consistent with the extension.")
        else:
            findings.append("File signature does not match the expected format.")
            score += 35

    if extension in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}:
        try:
            image = Image.open(io.BytesIO(content))
            findings.append(f"Detected image format: {image.format}.")
            findings.append(f"Image dimensions: {image.width} × {image.height}.")

            exif = image.getexif()
            if exif:
                findings.append(f"Image metadata fields found: {len(exif)}.")
                readable = []
                for key, value in exif.items():
                    tag = ExifTags.TAGS.get(key, str(key))
                    if tag in {"Software", "DateTime", "Make", "Model"}:
                        readable.append(f"{tag}: {str(value)[:100]}")
                findings.extend(readable[:5])
            else:
                findings.append("No standard EXIF metadata was found.")

        except (UnidentifiedImageError, OSError):
            findings.append("The image content could not be decoded.")
            score += 30

    if len(content) > 10 * 1024 * 1024:
        findings.append("File is large; inspect it carefully before sharing.")
        score += 5

    findings.append(
        "A hash was calculated for file identification; it does not prove authenticity."
    )

    return result_report(
        "Media Analysis", score, findings,
        "Basic file forensics only. This module does not detect deepfakes, "
        "malware, or hidden payloads, and does not verify media authenticity."
    )


PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TRUSTRA | Cybersecurity Intelligence</title>
<style>
:root {
 --bg:#07111e; --panel:#101e30; --panel2:#14243a;
 --line:#263a53; --text:#eaf2ff; --muted:#92a5bf;
 --cyan:#50e4ef; --blue:#6298ff; --red:#ff647c;
 --amber:#ffc65c; --green:#4fe0b0;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at top,#102945 0,#07111e 55%);
 color:var(--text);font-family:Inter,system-ui,-apple-system,sans-serif;min-height:100vh}
header{border-bottom:1px solid var(--line);padding:20px 6%;display:flex;
 align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}
.brand{font-size:25px;font-weight:900;letter-spacing:3px}
.brand span{color:var(--cyan)}
.tag{color:var(--muted);font-size:12px;letter-spacing:2px}
main{max-width:1150px;margin:auto;padding:36px 22px 60px}
.eyebrow{color:var(--cyan);font-size:12px;letter-spacing:3px;font-weight:800}
h1{font-size:clamp(30px,5vw,48px);line-height:1.1;margin:12px 0}
.subtitle{color:var(--muted);max-width:680px;line-height:1.7}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:17px;margin:30px 0}
.card{background:linear-gradient(145deg,#122238,#0c1929);border:1px solid var(--line);
 border-radius:17px;padding:23px;min-width:0}
.card:hover{border-color:#3c718d}
.number{color:var(--cyan);font-size:12px;letter-spacing:2px;font-weight:800}
h2{font-size:20px;margin:10px 0}
.desc{color:var(--muted);font-size:14px;line-height:1.65;min-height:44px}
label{display:block;color:#c4d3e8;font-size:13px;margin:14px 0 7px}
input,textarea{width:100%;background:#081422;color:var(--text);border:1px solid #30435a;
 border-radius:9px;padding:12px;font:inherit}
textarea{min-height:105px;resize:vertical}
input:focus,textarea:focus{outline:1px solid var(--cyan);border-color:var(--cyan)}
button{border:0;border-radius:9px;padding:12px 17px;background:linear-gradient(90deg,#31cbdc,#648fff);
 color:#04111c;font-weight:850;cursor:pointer;margin-top:15px;width:100%}
button:hover{filter:brightness(1.08)}
.result{margin-top:24px;overflow:hidden}
.result-head{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.score{font-size:35px;font-weight:900}
.pill{padding:7px 10px;border-radius:7px;font-size:11px;font-weight:900;letter-spacing:1px}
.danger{color:#ff91a1;background:#4b1927}
.warning{color:#ffd781;background:#46351a}
.safe{color:#72f0c4;background:#123b34}
ul{padding-left:21px;line-height:1.8;color:#c7d5e8;overflow-wrap:anywhere}
.notice{font-size:12px;color:var(--muted);line-height:1.7}
.flash{padding:12px;border:1px solid #76404a;background:#301b27;border-radius:10px}
footer{text-align:center;color:#6e839d;padding:25px;border-top:1px solid var(--line);font-size:12px}
@media(max-width:700px){.grid{grid-template-columns:1fr}header{padding:18px 22px}.desc{min-height:0}}
</style>
</head>
<body>
<header>
 <div class="brand">TRUS<span>TRA</span></div>
 <div class="tag">LOCAL CYBER THREAT INTELLIGENCE</div>
</header>
<main>
 <div class="eyebrow">SECURITY OPERATIONS / 01</div>
 <h1>See the threat.<br>Understand the evidence.</h1>
 <p class="subtitle">A unified security workspace for inspecting QR codes,
 links, media files, and suspicious emails. Results explain the indicators
 found instead of presenting an unexplained verdict.</p>

 {% with messages = get_flashed_messages() %}
 {% if messages %}{% for message in messages %}
 <div class="flash">{{ message }}</div>
 {% endfor %}{% endif %}
 {% endwith %}

 <div class="grid">
  <section class="card">
   <div class="number">01 / QR INTELLIGENCE</div>
   <h2>QR Analyzer</h2>
   <p class="desc">Decode a QR image and inspect any URL it contains.</p>
   <form action="{{ url_for('qr') }}" method="post" enctype="multipart/form-data">
    <label>QR image</label>
    <input type="file" name="file" accept="image/*" required>
    <button>Analyze QR code →</button>
   </form>
  </section>

  <section class="card">
   <div class="number">02 / URL INTELLIGENCE</div>
   <h2>Link Analyzer</h2>
   <p class="desc">Check domain structure, URL schemes, and suspicious patterns.</p>
   <form action="{{ url_for('link') }}" method="post">
    <label>URL to inspect</label>
    <input name="url" type="text" placeholder="https://example.com" required>
    <button>Inspect link →</button>
   </form>
  </section>

  <section class="card">
   <div class="number">03 / FILE FORENSICS</div>
   <h2>Media Analyzer</h2>
   <p class="desc">Inspect supported files, metadata, signatures, and SHA-256 hashes.</p>
   <form action="{{ url_for('media') }}" method="post" enctype="multipart/form-data">
    <label>Media or document file (max 12 MB)</label>
    <input type="file" name="file" required>
    <button>Analyze file →</button>
   </form>
  </section>

  <section class="card">
   <div class="number">04 / MESSAGE INTELLIGENCE</div>
   <h2>Email Analyzer</h2>
   <p class="desc">Find phishing language, credential requests, payment pressure, and sender mismatches.</p>
   <form action="{{ url_for('email') }}" method="post">
    <label>Sender display name</label>
    <input name="sender_name" placeholder="IT Support">
    <label>Sender email</label>
    <input name="sender_email" type="email" placeholder="support@example.com">
    <label>Reply-to email (optional)</label>
    <input name="reply_to" type="text" placeholder="different@example.com">
    <label>Subject</label>
    <input name="subject" placeholder="Urgent account verification">
    <label>Email body</label>
    <textarea name="message" placeholder="Paste the email text here..." required></textarea>
    <button>Analyze email →</button>
   </form>
  </section>
 </div>

 {% if report %}
 <section class="card result">
  <div class="result-head">
   <div>
    <div class="number">ANALYSIS REPORT</div>
    <h2>{{ report.title }}</h2>
    <span class="pill {{ report.color }}">{{ report.level }}</span>
   </div>
   <div class="score">{{ report.score }}<span style="font-size:15px;color:#92a5bf"> / 100</span></div>
  </div>
  <div style="height:8px;background:#26374d;border-radius:8px;margin:18px 0">
   <div style="height:8px;width:{{ report.score }}%;border-radius:8px;
   background:{% if report.score >= 65 %}#ff647c{% elif report.score >= 30 %}#ffc65c{% else %}#4fe0b0{% endif %}"></div>
  </div>
  <h2>Evidence and findings</h2>
  <ul>{% for finding in report.findings %}<li>{{ finding }}</li>{% endfor %}</ul>
  <p class="notice">{{ report.summary }}</p>
  <p class="notice">Risk score is a heuristic indicator, not a probability of compromise.
  A low score does not guarantee safety.</p>
  <button onclick="window.print()">Print / Save report</button>
 </section>
 {% endif %}
 <p class="notice" style="margin-top:24px">Privacy note: files and messages are processed
 locally by this application. Do not expose this development server to the public internet.
 Submitted links are not visited.</p>
</main>
<footer>TRUSTRA • CYBERSECURITY ANALYSIS WORKSPACE • LOCAL DEMO</footer>
</body>
</html>
"""


def render_page(report=None):
    return render_template_string(PAGE, report=report)


@app.get("/")
def home():
    return render_page()


@app.post("/qr")
def qr():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a QR image first.")
        return redirect(url_for("home"))
    return render_page(analyze_qr(uploaded))


@app.post("/link")
def link():
    raw_url = request.form.get("url", "")
    if len(raw_url) > 3000:
        flash("The URL is too long.")
        return redirect(url_for("home"))
    return render_page(analyze_link(raw_url))


@app.post("/media")
def media():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file first.")
        return redirect(url_for("home"))
    return render_page(analyze_media(uploaded))


@app.post("/email")
def email():
    fields = [
        request.form.get("sender_name", ""),
        request.form.get("sender_email", ""),
        request.form.get("reply_to", ""),
        request.form.get("subject", ""),
        request.form.get("message", "")
    ]

    if not fields[4].strip():
        flash("Please enter the email body.")
        return redirect(url_for("home"))

    if sum(len(value) for value in fields) > 20000:
        flash("Email content is too long. Limit the total input to 20,000 characters.")
        return redirect(url_for("home"))

    report = analyze_email(*fields)
    return render_page(report)


@app.errorhandler(413)
def too_large(_error):
    return (
        "Upload too large. Please keep files below 12 MB and try again.",
        413
    )


if __name__ == "__main__":
    print("TRUSTRA starting at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)