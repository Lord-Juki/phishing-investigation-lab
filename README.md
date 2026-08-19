**#Phishing Email Investigation Lab**

Author: Anirudh (lord-juki)
Date: 2026-08-18
Category: Email Forensics / OSINT
Tools: Kali Linux, mail-parser, whois, dig, curl

Overview

This lab walks through a full phishing email investigation workflow on Kali Linux. It covers two samples: a controlled lab email we built to understand the methodology, and a real confirmed phishing domain pulled from PhishTank. The goal is to go from a raw email or URL to a full set of IOCs (indicators of compromise) using only built-in and lightweight tools.

Setup
bash
# Install mail-parser (everything else comes with Kali)
pip3 install mail-parser --break-system-packages
Part 1: Controlled Sample — Fake PayPal Phish
Step 1: Build the Sample Email

We created a realistic phishing email mimicking PayPal to practice header analysis without needing a live malicious sample.

bash
cat > sample1.eml << 'EOF'
From: "PayPal Security" <security@paypa1-verify.com>
To: victim@gmail.com
Subject: Urgent: Your account has been limited
Date: Mon, 18 Aug 2026 10:23:11 -0500
Message-ID: <abc123@paypa1-verify.com>
Received: from mail.paypa1-verify.com (192.168.66.22) by smtp.gmail.com
Received: from suspicious-host.ru (185.220.101.45) by mail.paypa1-verify.com
MIME-Version: 1.0
Content-Type: text/html
X-Mailer: Microsoft Outlook 16.0
Return-Path: bounce@totally-not-phish.xyz

<html>
<body>
<p>Dear Customer,</p>
<p>Your PayPal account has been limited. Click below to verify:</p>
<a href="http://paypa1-verify.com/login">Restore My Account</a>
</body>
</html>
EOF
Step 2: Parse the Headers
bash
python3 -c "
import mailparser
mail = mailparser.parse_from_file('sample1.eml')
for key, val in mail.headers.items():
    print(f'{key}: {val}')
"

Output:

From: [('PayPal Security', 'security@paypa1-verify.com')]
To: [('', 'victim@gmail.com')]
Subject: Urgent: Your account has been limited
Received: ['from mail.paypa1-verify.com (192.168.66.22) by smtp.gmail.com',
           'from suspicious-host.ru (185.220.101.45) by mail.paypa1-verify.com']
Return-Path: bounce@totally-not-phish.xyz

Red flags identified:

Finding	Why It's Suspicious
paypa1-verify.com	Typosquatted domain, "1" instead of "l"
Return-Path: bounce@totally-not-phish.xyz	Completely different domain from sender
from suspicious-host.ru in Received chain	Email routed through Russia
"Urgent: Your account has been limited"	Classic urgency-based social engineering
Step 3: Trace the IP
bash
whois 185.220.101.45

Key findings:

netname: TOR-EXIT
descr:   Network for Tor-Exit traffic.
remarks: We do not have any logs at all.
org-name: ForPrivacyNET
country: DE

The IP resolves to a Tor exit node in Germany operated by ForPrivacyNET. The attacker intentionally routed the email through Tor to make tracing impossible. The operator explicitly states they keep no logs.

Step 4: Extract the Malicious Link
bash
python3 -c "
import mailparser
mail = mailparser.parse_from_file('sample1.eml')
print(mail.text_html)
"

Link found: http://paypa1-verify.com/login

This reinforces the typosquatting finding from the headers.

Part 2: Real Sample — PhishTank Entry #9507321

Domain: ne12netempresas.com (confirmed Valid Phish, Online as of 2026-08-18)

Step 1: Resolve the Domain to IPs
bash
dig +short ne12netempresas.com
104.21.84.55
172.67.187.24

Two IPs returned, both belonging to Cloudflare. The attacker is using Cloudflare as a reverse proxy to hide the real origin server.

Step 2: Whois the IP
bash
whois 104.21.84.55
NetName:      CLOUDFLARENET
Organization: Cloudflare, Inc.
Country:      US

Confirmed Cloudflare. Real origin IP is not obtainable without a subpoena to Cloudflare.

Step 3: Whois the Domain
bash
whois ne12netempresas.com

Key findings:

Creation Date: 2026-08-17T13:47:24Z
Registrar:    Sav.com, LLC
Name Server:  ullis.ns.cloudflare.com
Name Server:  weston.ns.cloudflare.com
DNSSEC:       unsigned

Domain was registered the day before it was reported as a phishing site. This is one of the strongest signals in phishing investigations. Legitimate businesses don't stand up domains and start phishing within 24 hours.

Step 4: DNS Enumeration
bash
dig any ne12netempresas.com
ne12netempresas.com.  IN  NS  weston.ns.cloudflare.com.
ne12netempresas.com.  IN  NS  ullis.ns.cloudflare.com.
ne12netempresas.com.  IN  HINFO "RFC8482" ""

RFC8482 response means Cloudflare is actively blocking ANY record queries. No additional info leaked.

IOC Summary
Part 1 (Controlled Sample)
Type	Value
Sender Domain	paypa1-verify.com
Malicious URL	http://paypa1-verify.com/login
Suspicious IP	185.220.101.45
IP Classification	Tor Exit Node (ForPrivacyNET, DE)
Return-Path Domain	totally-not-phish.xyz
Part 2 (Real Sample)
Type	Value
Phishing Domain	ne12netempresas.com
Resolved IPs	104.21.84.55, 172.67.187.24
IP Owner	Cloudflare (origin hidden)
Domain Age	1 day at time of report
Registrar	Sav.com, LLC
DNSSEC	Unsigned
Key Takeaways
Read the Received chain bottom to top. That's the actual path the email traveled. Unexpected hops through foreign or anonymizing infrastructure are immediate red flags.
Domain age matters. Anything under 30 days is suspicious. Under 7 days during an active phishing campaign is basically a confirmed indicator.
Tor exit nodes + "no logs" = intentional anonymization. The attacker knew what they were doing.
Cloudflare hiding origin is standard modern phishing infra. You won't get the real IP without going through Cloudflare's abuse process.
Typosquatting is subtle. paypa1 vs paypal is easy to miss at a glance, which is the whole point.
Reporting

If you find a live phishing site, report it:

Cloudflare abuse: https://www.cloudflare.com/abuse (fastest takedown)
Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish
PhishTank: https://phishtank.org (feeds into browser blocklists)
