TRUSTRA — Cybersecurity Threat Analysis Platform

TRUSTRA is a Python and Flask-based cybersecurity platform that helps users identify potential digital threats through four analyzers: QR codes, links, media files, and emails. It provides explainable findings and indicative risk scores through a unified cybersecurity dashboard.

Features

* QR Analyzer: Decodes QR code images and examines embedded URLs for suspicious indicators.
* Link Analyzer: Inspects URLs for suspicious patterns and potential phishing indicators.
* Media Analyzer: Performs basic file inspection, checks selected file signatures, extracts available image metadata, and calculates SHA-256 hashes.
* Email Analyzer: Detects common phishing and social-engineering indicators, including urgency, credential requests, and payment pressure.
* Risk Reports: Presents findings and indicative risk scores through a dark cybersecurity-themed interface.

Technologies Used

Python, Flask, OpenCV, Pillow, HTML, and CSS.

Installation and Setup

1. Clone the repository:

git clone https://github.com/rajput-glitch/Nexus-HK26-0035.git

2. Open the project directory:

cd Nexus-HK26-0035

3. Create and activate a virtual environment:

py -m venv venv
venv\Scripts\activate

4. Install the dependencies:

pip install -r requirements.txt

5. Run the application:

python app.py

6. Open http://127.0.0.1:5000 in your browser.

Analyzer Sequence

1. QR Analyzer
2. Link Analyzer
3. Media Analyzer
4. Email Analyzer

Disclaimer

TRUSTRA performs preliminary, rule-based analysis. Its findings may include false positives or miss threats. A low risk score does not guarantee safety. The current version does not provide comprehensive malware scanning or validated deepfake detection.

Objective

To improve cybersecurity awareness by making preliminary digital threat analysis more accessible and understandable.