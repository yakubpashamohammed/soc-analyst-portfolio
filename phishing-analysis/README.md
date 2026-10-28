# Phishing Email Analysis

Three phishing emails triaged the way I would handle a user report as a Tier 1 analyst. All three samples are from the public MalwareCube SOC101 training repo, so none are live incidents.

## Cases

| # | Report | Date of email | Verdict | Severity |
|---|---|---|---|---|
| 01 | [Chase impersonation](./reports/email-01-chase-impersonation.md) | 2024-05-01 | Phishing (sender spoofing) | Medium |
| 02 | [Amazon impersonation via bulk-email service](./reports/email-02-amazon-impersonation.md) | 2023-12-15 | Phishing (brand impersonation) | Medium |
| 03 | [Invoice lure with ISO attachment](./reports/email-03-iso-attachment.md) | 2020-01-14 | Phishing (malware delivery) | High |

## What each case taught me

**Email 01: Chase.** The From line said chase.com, but Reply-To, Return-Path and Message-ID all pointed to Proton Mail. SPF and DMARC showed "pass", but for protonmail.com, not Chase. VirusTotal showed 0 detections on the link, and I didn't treat that as proof of safety. The verdict rests on the sender and link mismatch.

**Email 02: Amazon.** The sender was an unrelated company's address, sent through a Sendinblue account. SPF passed for the Sendinblue bounce domain and DKIM for a third domain, so both passes were real but meaningless for the From domain, and DMARC failed. I decided not to recommend blocking the sender's domain or the tracking domain, because one is a real company and the other is a legitimate mail service.

**Email 03: ISO attachment.** SPF failed, there was no DKIM, and the sending IP belonged to a hosting provider. I hashed the attachment without ever opening it and searched the hash on VirusTotal, where 40 of 61 vendors flagged it. I rated it High and not Critical because I had no evidence the user opened it, and I wrote down what would change that rating.

## Screenshots

The screenshots are in `screenshots/`, with one sub-folder per email. Each report shows the same images in the step where I used them.

### Email 01: Chase impersonation

**Email as the user sees it (remote content blocked)**

![Email as the user sees it (remote content blocked)](./screenshots/email-01-screenshots/e1-01-thunderbird-view.png)

**Raw headers**

![Raw headers](./screenshots/email-01-screenshots/e1-02-headers-sublime.png)

**MXToolbox header analysis**

![MXToolbox header analysis](./screenshots/email-01-screenshots/e1-03-mxtoolbox-header-analysis.png)

**Chase's DMARC record, for comparison**

![Chase's DMARC record, for comparison](./screenshots/email-01-screenshots/e1-04-chase-dmarc.png)

**Finding the real link in the raw body**

![Finding the real link in the raw body](./screenshots/email-01-screenshots/e1-05-href-raw.png)

**Decoding the link in CyberChef**

![Decoding the link in CyberChef](./screenshots/email-01-screenshots/e1-06-cyberchef-decode.png)

**VirusTotal search for the link**

![VirusTotal search for the link](./screenshots/email-01-screenshots/e1-07-vt-dsgo.png)

**VirusTotal details**

![VirusTotal details](./screenshots/email-01-screenshots/e1-08-vt-dsgo-details.png)

**WHOIS for the link domain**

![WHOIS for the link domain](./screenshots/email-01-screenshots/e1-09-whois-dsgo.png)

**Sending IP lookups**

![Sending IP lookups](./screenshots/email-01-screenshots/e1-10-ip-lookups.png)

### Email 02: Amazon impersonation

**Email as the user sees it (remote content blocked)**

![Email as the user sees it (remote content blocked)](./screenshots/email-02-screenshots/e2-01-thunderbird-view.png)

**Raw headers**

![Raw headers](./screenshots/email-02-screenshots/e2-02-headers-sublime.png)

**Header analyzer**

![Header analyzer](./screenshots/email-02-screenshots/e2-03-header-analyzer.png)

**Sender domain DMARC record**

![Sender domain DMARC record](./screenshots/email-02-screenshots/e2-04-fareast-dmarc.png)

**Sender domain SPF record**

![Sender domain SPF record](./screenshots/email-02-screenshots/e2-05-fareast-spf.png)

**Amazon DMARC record, for comparison**

![Amazon DMARC record, for comparison](./screenshots/email-02-screenshots/e2-06-amazon-dmarc.png)

**Sending IP on AbuseIPDB**

![Sending IP on AbuseIPDB](./screenshots/email-02-screenshots/e2-07-abuseipdb.png)

**WHOIS for the sender domain (1)**

![WHOIS for the sender domain (1)](./screenshots/email-02-screenshots/e2-08a-whois-fareast.png)

**WHOIS for the sender domain (2)**

![WHOIS for the sender domain (2)](./screenshots/email-02-screenshots/e2-08b-whois-fareast.png)

**VirusTotal for the tracking domain**

![VirusTotal for the tracking domain](./screenshots/email-02-screenshots/e2-09-vt-sendibt3.png)

### Email 03: ISO attachment

**Email as the user sees it (remote content blocked)**

![Email as the user sees it (remote content blocked)](./screenshots/email-03-screenshots/e3-01-thunderbird-view.png)

**Raw headers**

![Raw headers](./screenshots/email-03-screenshots/e3-02-sublime-headers.png)

**MXToolbox header analyzer**

![MXToolbox header analyzer](./screenshots/email-03-screenshots/e3-03-mxtoolbox-header-analyzer.png)

**Finding the attachment with grep**

![Finding the attachment with grep](./screenshots/email-03-screenshots/e3-04-grep-attachment.png)

**Extracting it with munpack**

![Extracting it with munpack](./screenshots/email-03-screenshots/e3-05-munpack.png)

**File type and hashes**

![File type and hashes](./screenshots/email-03-screenshots/e3-06-hash-and-file.png)

**VirusTotal detections for the hash**

![VirusTotal detections for the hash](./screenshots/email-03-screenshots/e3-07-vt-detection.png)

**VirusTotal details**

![VirusTotal details](./screenshots/email-03-screenshots/e3-08-vt-details.png)

**whois on the sending IP**

![whois on the sending IP](./screenshots/email-03-screenshots/e3-10-whois-ip.png)

**RIPE whois**

![RIPE whois](./screenshots/email-03-screenshots/e3-10b-ripe-whois.png)

**AbuseIPDB**

![AbuseIPDB](./screenshots/email-03-screenshots/e3-11-abuseipdb.png)

**whois for the sender domain**

![whois for the sender domain](./screenshots/email-03-screenshots/e3-12-whois-domain.png)

**SPF and DMARC for the sender domain**

![SPF and DMARC for the sender domain](./screenshots/email-03-screenshots/e3-13-spf-dmarc.png)

**Hovering over the body links**

![Hovering over the body links](./screenshots/email-03-screenshots/e3-14a-hr-link-hover.png)

**Extracting URLs from the body**

![Extracting URLs from the body](./screenshots/email-03-screenshots/e3-15-url-extraction.png)

## Method

1. Open the email in an isolated Kali VM with remote content blocked. Keep the original `.eml` untouched.
2. Compare the claimed sender with the real one (From, Reply-To, Return-Path, Message-ID).
3. Read the Received chain from bottom to top and check SPF, DKIM and DMARC against the right domain.
4. Decode the body (quoted-printable in CyberChef) and pull out the real link targets without visiting them.
5. For attachments: extract, check the real file type, hash it, and search the hash only.
6. Look up domains and IPs passively (MXToolbox, VirusTotal search, AbuseIPDB, whois).
7. Write the verdict, severity with its rationale, defanged IOCs, MITRE ATT&CK mapping and recommended actions for L2.

## Labels used in the reports

- **Confirmed:** I saw it directly in the email or in a lookup.
- **Likely:** a reasonable conclusion I couldn't fully prove.
- **Not determined:** I looked but couldn't work out the answer.
- **Not observed:** I didn't see it or couldn't check it safely.

## MITRE ATT&CK mapping

| Technique | Email 01 | Email 02 | Email 03 |
|---|---|---|---|
| T1566.001 Spearphishing Attachment | | | Yes |
| T1566.002 Spearphishing Link | Yes | Yes | |
| T1656 Impersonation | Yes | Yes | |
| T1583.006 Acquire Infrastructure: Web Services | | Likely | |
| T1204.002 User Execution: Malicious File | | | Yes |
| T1036 Masquerading | | | Yes |

## Handling and limits

- No link was clicked and no attachment was opened, mounted or run.
- All indicators are defanged. Only hashes are published for the ISO sample, and `*.iso` is in `.gitignore`.
- Lookups (whois, DNS, VirusTotal, AbuseIPDB) were done in 2026 on emails from 2020 to 2024, so current data may differ from what it was at the time. Each report lists its own limitations.
