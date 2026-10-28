# Email 01: Chase Impersonation Phishing

SOC L1 triage report. Main focus: email header analysis.

## Summary

| Field | Details |
|---|---|
| Subject | Your Bank Account has been blocked due to unusual activities |
| Sent | 2024-05-01 20:04:05 UTC |
| From (claimed) | alerts[at]chase[.]com |
| Reply-To / Return-Path | kellyellin426[at]proton[.]me |
| Sending server | mail-40140[.]protonmail[.]ch (185[.]70[.]40[.]140) |
| Link | hxxps://dsgo[.]to/CQECQEC... |
| Attachments | None |
| Verdict | Phishing (sender spoofing / brand impersonation) |
| Severity | Medium (High if the link was clicked or credentials were entered) |

The email says it is from Chase, but the headers show it was sent from a Proton Mail account. The "Reactivate Your Account" button goes to a domain that has nothing to do with Chase. SPF and DMARC both showed "pass", but they passed for protonmail[.]com, not chase[.]com, so they do not prove the email is from Chase.

## Scope

This report is mainly about header analysis (sender identity, Reply-To and Return-Path mismatch, SPF/DKIM/DMARC results and the Received chain). For the link I only did passive checks: decoding the body, a VirusTotal search and a WHOIS lookup. I did not open the link and I did not detonate it in a sandbox.

The sample looks like a training email and not a live incident. The tenant ID is masked (`aaaaaaaaaaaa`) and an image in the email is hosted in a public GitHub training repo (MalwareCube/SOC101). I could not confirm this, so I am treating it as likely.

## How I labelled findings

- **Confirmed**: I saw it directly in the email or in a lookup.
- **Likely**: a reasonable conclusion that I could not fully prove.
- **Not observed**: I did not see it or could not check it safely.

All indicators are defanged (`hxxps`, `[.]`, `[at]`) so nobody clicks them by mistake.

## Tools and safe handling

| Tool | Used for |
|---|---|
| Kali Linux VM (snapshot taken first) | Isolated environment |
| Thunderbird (remote content blocked) | Viewing the email like a user would |
| Sublime Text | Reading raw headers and body |
| MXToolbox | Header analyzer, SPF and DMARC lookups |
| CyberChef | Decoding the quoted-printable body |
| VirusTotal (search only) | URL reputation, nothing submitted |
| whois | Domain and IP registration details |

I kept the original `.eml` file untouched, never clicked or visited any link, and did not submit anything to a scanner.

## Investigation

### Step 1: First look

I opened the email in Thunderbird with remote content blocked. Things I noticed straight away:

- Generic greeting ("Dear Customer")
- Urgency and a threat (account blocked or suspended)
- A spelling mistake ("tempory")
- A "Reactivate Your Account" button
- Signed off as "Chase Online Service"

![Thunderbird view](../screenshots/email-01-screenshots/e1-01-thunderbird-view.png)

### Step 2: Header analysis

I opened the raw headers in Sublime Text and compared who the email claims to be with who the headers say sent it.

| Header | Value | Status |
|---|---|---|
| From | alerts[at]chase[.]com | Confirmed (only the claimed sender) |
| Reply-To | kellyellin426[at]proton[.]me | Confirmed mismatch |
| Return-Path | kellyellin426[at]proton[.]me | Confirmed mismatch |
| Message-ID | ...@protonmail[.]com, plus `X-Pm-Message-ID` | Confirmed, the message was created in Proton's system |
| Authentication-Results | spf=pass (smtp.mailfrom=protonmail[.]com); dkim=timeout (key query timeout); dmarc=pass (header.from=protonmail[.]com) | Confirmed |
| SCL / BCL / PCL | 1 / 0 / 2 | Microsoft rated it low risk |
| Sender's real IP | Hidden by Proton | Not observed |

The DKIM timeout is inconclusive. It is not the same as a DKIM fail, so I did not count it as one.

The main point here is that SPF and DMARC passed for protonmail[.]com. A pass only means the email is genuine for the domain that was checked, and that domain is not Chase.

![Raw headers](../screenshots/email-01-screenshots/e1-02-headers-sublime.png)

### Step 3: Received chain

I pasted the headers into the MXToolbox Header Analyzer and read the hops from bottom to top. The first hop is mail-40140.protonmail.ch (185[.]70[.]40[.]140), followed by three internal Microsoft hops. The total delay was 5 seconds and I did not see any odd relays.

The tool shows green ticks for blacklist checks, but those only apply to the Microsoft and Proton servers in the chain. They do not mean the email is safe.

![MXToolbox](../screenshots/email-01-screenshots/e1-03-mxtoolbox-header-analysis.png)

I also looked up the sending IP with a few public lookup sites. Since Proton hides the client IP, this only tells me about Proton's relay and not about the real sender, so I did not use it for the verdict.

![IP lookups](../screenshots/email-01-screenshots/e1-10-ip-lookups.png)

### Step 4: What the real Chase setup looks like

I checked Chase's DMARC record. Chase uses `p=reject; pct=100`, which is the strictest policy (Confirmed). In this sample, though, DMARC was checked against protonmail[.]com, so Chase's policy was never applied (Confirmed from `header.from`).

I could not work out why the visible From shows chase[.]com while `header.from` shows protonmail[.]com. The sample may have been edited or anonymized.

I also looked up Chase's SPF record for comparison.

![Chase DMARC](../screenshots/email-01-screenshots/e1-04-chase-dmarc.png)

### Step 5: Link analysis (without opening it)

1. I found the real link by searching for `href=` in the raw body.

   ![Raw href](../screenshots/email-01-screenshots/e1-05-href-raw.png)

2. The body is quoted-printable (it has `=3D` and `=` at line ends), so the link was broken up. I decoded it in CyberChef using only the From Quoted Printable recipe. The character count went from 418 to 398, which confirmed the decode worked.

   ![CyberChef](../screenshots/email-01-screenshots/e1-06-cyberchef-decode.png)

3. I searched the full decoded URL on VirusTotal. I used search only and did not click Reanalyze.

   ![VirusTotal](../screenshots/email-01-screenshots/e1-07-vt-dsgo.png)

4. I checked the VirusTotal Details tab and ran a WHOIS lookup on the domain.

   ![VT details](../screenshots/email-01-screenshots/e1-08-vt-dsgo-details.png)
   ![WHOIS](../screenshots/email-01-screenshots/e1-09-whois-dsgo.png)

| Field | Value | Status |
|---|---|---|
| Visible text | "Reactivate Your Account" | Confirmed |
| Real href | hxxps://dsgo[.]to/CQECQEC... | Confirmed |
| Related to chase[.]com | No | Confirmed |
| VirusTotal (report dated 2026-10-15) | 0/93 flagged | Not flagged, but this does not mean safe |
| VirusTotal final URL | hxxps://www[.]google[.]com/recaptcha/api2/bframe... | Seen by the VT crawler, probably a CAPTCHA iframe (not confirmed) |
| VirusTotal tags | iframes, password-input, third-party-cookies, external-resources | Seen by VT, not by me |
| Earlier search with a shortened URL (2026-07-03) | 0/92, ended at hxxps://dsgo[.]to/ | Different result, noted separately |
| Vendor category | Information technology / online storage | Fits a redirector (Likely) |
| WHOIS for dsgo[.]to (checked 2026-10-19) | Created 2023-12-15, registrar Ascio Technologies (Denmark), Cloudflare name servers, registrant hidden | Confirmed |
| Domain age when the email was sent | About 4.5 months | Fairly new, but only a weak indicator |
| Credential-harvesting page | Based on the email wording and the `password-input` tag | Likely, not observed |
| Landing page | I never opened it | Not observed |

## Red flags

1. The From domain does not match the Return-Path or Reply-To.
2. Replies would go to a free mail address.
3. Generic greeting and a spelling mistake.
4. Urgency and a threat (account blocked).
5. The link goes to a third-party domain and not chase[.]com.
6. The authentication passes belong to protonmail[.]com and not the brand in the From line.

## Conclusion

The From line says chase[.]com, but the Return-Path, Reply-To, Message-ID, sending server and authentication domain all point to Proton. The SPF and DMARC passes are for protonmail[.]com, so they do not verify Chase. The button points to an unrelated domain.

0 detections on VirusTotal does not clear the link. My verdict is based on the sender and link mismatch and not on the reputation score.

**Verdict: Phishing (sender spoofing / brand impersonation). Severity: Medium.**

## IOCs (defanged)

| Type | Value |
|---|---|
| Email (Reply-To / Return-Path) | kellyellin426[at]proton[.]me |
| Spoofed sender | alerts[at]chase[.]com |
| IP | 185[.]70[.]40[.]140 |
| Host | mail-40140[.]protonmail[.]ch |
| Domain | dsgo[.]to |
| URL | hxxps://dsgo[.]to/CQECQEC... |

## MITRE ATT&CK

| ID | Technique | Reason |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | The email delivers a suspicious link |
| T1656 | Impersonation | It pretends to be Chase |

## Recommended actions

As L1 I would recommend these and leave the actions to L2.

1. Block the sender address and dsgo[.]to at the mail gateway and proxy.
2. Search for other emails from the same sender or with the same subject.
3. Check proxy logs for any connection to dsgo[.]to.
4. If the user clicked the link, escalate to L2, reset their credentials and review their sign-ins.
5. L2 can detonate the URL in a sandbox and check the redirect chain.
6. Report it to the user, Chase's phishing reporting address and the registrar abuse contact (billing[at]ascio[.]com).

## Limitations

- I did not open the landing page, so I do not know how it behaves.
- The VirusTotal results are from 2026 and the email is from 2024, so the page may have looked different when it was sent.
- The WHOIS data is from 2026 (the domain was updated 2026-03-19) and may not match 2024.
- I do not know who the real sender is because Proton hides the client IP.
- I could not explain why `header.from` shows protonmail[.]com.
