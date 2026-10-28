# Email 02: Amazon Impersonation via a Bulk-Email Service

SOC L1 triage report.

## Summary

| Field | Details |
|---|---|
| Subject | [ACTION REQUEST] You have been red flagged for violating our terms |
| Sent | 2023-12-15 00:43:28 UTC |
| From (claimed) | "Amazon Help Center" <amz[at]fareast[.]com[.]sg> |
| Return-Path | bounces-93450922-amz=fareast[.]com[.]sg@hn[.]d[.]sender-sib[.]com |
| Sending server | hn[.]d[.]sender-sib[.]com (77[.]32[.]148[.]40), Sendinblue/Brevo |
| Authentication | SPF pass (hn[.]d[.]sender-sib[.]com), DKIM pass (email[.]myghs[.]com), **DMARC fail** (header.from=fareast[.]com[.]sg), compauth fail |
| Links | 2 text links, both on hxxps://chdgiei[.]r[.]bh[.]d[.]sendibt3[.]com/tr/cl/... (click tracker) |
| Attachments | None |
| Mailbox result | SCL 5, `RF:JunkEmail` in the delivery header |
| Verdict | Phishing (Amazon impersonation, sender spoofing through a bulk-email account, link hidden behind click tracking) |
| Severity | Medium (High if the link was clicked or the code was entered) |

The email pretends to be "Amazon Help Center" but the sender address belongs to an unrelated company, fareast[.]com[.]sg. It was sent through a Sendinblue account and signed with a third domain, email[.]myghs[.]com. SPF and DKIM passed, but only for those bulk-mail domains. DMARC failed because none of them match the From domain. The "AMAZON.COM" link in the body actually goes to a click tracker, so I could not see where it really leads.

## About the sample

This looks like a training sample and not a live incident. The Amazon logo is loaded from a public GitHub training repo (MalwareCube/SOC101) and the tenant ID is masked (`aaaaaaaaaaaa`). The file name in Sublime was `sample3.eml`. I could not confirm this, so I am treating it as likely.

## How I labelled findings

- **Confirmed**: I saw it directly in the email or in a lookup.
- **Likely**: a reasonable conclusion that I could not fully prove.
- **Not determined**: I looked but could not work out the answer.
- **Not observed**: I did not see it or could not check it safely.

All indicators are defanged (`hxxps`, `[.]`, `[at]`) so nobody clicks them by mistake.

## Tools and safe handling

| Tool | Used for |
|---|---|
| Kali Linux VM | Isolated environment |
| Thunderbird (remote content blocked) | Viewing the email like a user would |
| Sublime Text | Reading raw headers and body |
| MXToolbox | MX, SPF and DMARC lookups, header analyzer |
| CyberChef | Decoding the quoted-printable body and extracting URLs |
| VirusTotal (domain search only) | Domain reputation |
| AbuseIPDB, whois | IP and domain context |

I kept the original `.eml` file untouched, never clicked any link, and did not search or submit the tracking URLs anywhere.

## Investigation

### Step 1: First look

I opened the email in Thunderbird with remote content blocked, so the logo showed as a broken image. Things I noticed:

- Display name is "Amazon Help Center" but the domain is unrelated
- Generic greeting ("Dear Amazon Customer")
- An "Account Suspended" heading
- A fake security code
- A "Fraudulent Activity Report" link

The subject says I was "red flagged for violating our terms" but the body says an order was canceled due to fraudulent activity. These are two different problems. This is only a weak indicator but I noted it.

![Thunderbird view](../screenshots/email-02-screenshots/e2-01-thunderbird-view.png)

### Step 2: Header analysis

I opened the raw headers in Sublime Text.

| Header | Value | Status |
|---|---|---|
| From | "Amazon Help Center" <amz[at]fareast[.]com[.]sg> | Confirmed (claimed identity only) |
| Return-Path | bounces-93450922-amz=fareast[.]com[.]sg@hn[.]d[.]sender-sib[.]com | Confirmed, this is a Sendinblue bounce domain |
| Reply-To | Not present | Confirmed |
| First Received hop | hn[.]d[.]sender-sib[.]com (77[.]32[.]148[.]40) | Confirmed |
| SPF | pass, smtp.mailfrom=hn[.]d[.]sender-sib[.]com | Confirmed, it verifies Sendinblue and not fareast[.]com[.]sg or Amazon |
| DKIM | pass, d=email[.]myghs[.]com, s=mail | Confirmed, a third unrelated domain |
| DMARC | fail, action=none, header.from=fareast[.]com[.]sg | Confirmed, neither the SPF domain nor the DKIM domain matches the From domain |
| compauth | fail, reason=001 | Confirmed |
| SCL / BCL / PCL | 5 / 0 / 2 | Confirmed, SCL 5 means spam |
| Mailbox delivery | `RF:JunkEmail` | Confirmed as a header value, Junk placement is likely |
| `X-Mailin-EID` | Base64, decodes to a campaign ID, a message ID and a recipient address that is different from the To header | Confirmed. I could not work out why, the To field may have been edited or anonymized |

The key point is that SPF and DKIM both passed but for the wrong domains. SPF passed for the Sendinblue bounce domain and DKIM passed for email[.]myghs[.]com. Neither is fareast[.]com[.]sg or Amazon, which is why DMARC failed.

![Raw headers](../screenshots/email-02-screenshots/e2-02-headers-sublime.png)

### Step 3: Received chain

I read the chain from bottom to top. It starts at hn[.]d[.]sender-sib[.]com (77[.]32[.]148[.]40), goes through three Microsoft hops, and ends with final delivery over HTTPS. The total time was about 2 seconds and I did not see any odd relays.

![Header analyzer](../screenshots/email-02-screenshots/e2-03-header-analyzer.png)

### Step 4: Checking the domains

| Record | Result | Status |
|---|---|---|
| fareast[.]com[.]sg DMARC | `v=DMARC1; p=none` with reports sent to a third-party DMARC service | Confirmed, this explains `action=none` because nothing is enforced |
| fareast[.]com[.]sg SPF | Ends with `-all`. Includes Mimecast, Microsoft, synxis and a transactional-mail include, plus many ip4 ranges. I could not see Sendinblue or 77[.]32[.]148[.]40 in it | Likely not authorized (I did not expand the includes) |
| fareast[.]com[.]sg MX | Mimecast Australia | Confirmed, inbound mail routing only |
| fareast[.]com[.]sg WHOIS | Registrant FAR EAST PROPERTY SALES PTE. LTD., registrar CSC Corporate Domains, created 1996-06-23, updated 2026-06-23, expires 2027-06-23 (fetched 2026-10-22) | Confirmed |
| amazon[.]com DMARC | `p=quarantine; pct=100` | Confirmed, for comparison only because this email never used an amazon[.]com From address |

The SPF pass in the email was for hn[.]d[.]sender-sib[.]com, so fareast[.]com[.]sg's own SPF record was not what passed.

![fareast DMARC](../screenshots/email-02-screenshots/e2-04-fareast-dmarc.png)
![fareast SPF](../screenshots/email-02-screenshots/e2-05-fareast-spf.png)
![Amazon DMARC](../screenshots/email-02-screenshots/e2-06-amazon-dmarc.png)
![fareast WHOIS](../screenshots/email-02-screenshots/e2-08a-whois-fareast.png)
![fareast WHOIS](../screenshots/email-02-screenshots/e2-08b-whois-fareast.png)

My reading is that fareast[.]com[.]sg is an old, real company domain with no DMARC enforcement and not a lookalike registered by the attacker (Likely). The most probable explanation is that the attacker sent as that domain from their own Sendinblue account, signed as email[.]myghs[.]com. Whether the domain owner or the myghs[.]com account was compromised is not determined.

### Step 5: Sending IP and mail service reputation

| Item | Result | Status |
|---|---|---|
| 77[.]32[.]148[.]40 on AbuseIPDB | 16 reports from 5 sources, first reported 2021-11-16, categories Email Spam and Brute-Force, several comments mention `hn.d.sender-sib.com` | Confirmed. It is a shared mail-service IP so the reports come from many senders |
| sendibt3[.]com on VirusTotal | 0/92 flagged, registrar OVH, created about 11 years ago, tags web and email marketing and top-10K, community score -33 | Not flagged, but this does not mean safe. It is a real tracking domain used by many senders |

![AbuseIPDB](../screenshots/email-02-screenshots/e2-07-abuseipdb.png)
![VirusTotal sendibt3](../screenshots/email-02-screenshots/e2-09-vt-sendibt3.png)

### Step 6: Body analysis

The body is one `text/html` part encoded as quoted-printable. I decoded it in CyberChef using From Quoted Printable and then Extract URLs.

| Item | Finding | Status |
|---|---|---|
| "AMAZON.COM" link text | The href is hxxps://chdgiei[.]r[.]bh[.]d[.]sendibt3[.]com/tr/cl/... | Confirmed mismatch |
| "Fraudulent Activity Report" | Same click-tracking domain | Confirmed |
| Images | 4 in total: 1 logo (GitHub training repo) and 3 one-pixel tracking images | Confirmed. The pixels did not load because remote content was blocked |
| Forms and scripts | None found | Confirmed (searched for `form`, `input` and `script` with Ctrl+F) |
| Fake security code | Present (hidden in this report) | Confirmed, it is a social-engineering lure |
| Unsubscribe header | One-click link on the same tracker | Not used, because clicking it would confirm the address is live |
| Mail service account ID | `2736848` (in `Feedback-ID` and image paths) | Confirmed |
| Campaign ID | `93450922` (in Return-Path and tracking header) | Confirmed |
| Where the links finally go | Hidden behind the tracker | Not observed |
| Page that collects credentials or the code | Based on the lure | Likely, not observed |

## Red flags

1. The display name says Amazon but the From domain belongs to an unrelated company.
2. The Return-Path and DKIM domains are different from the From domain, and DMARC failed.
3. The SPF and DKIM passes belong to bulk-mail infrastructure and not to the claimed sender.
4. The link text says AMAZON.COM but the real link goes to a third-party tracker.
5. Generic greeting, urgency and a security code in the body.
6. The subject and body describe different problems.
7. Microsoft gave it SCL 5 and marked it for Junk.

## Conclusion

The email claims to be Amazon but was sent as fareast[.]com[.]sg through a Sendinblue account signed as email[.]myghs[.]com. SPF and DKIM passed only for those mail-service domains. DMARC failed, and because fareast[.]com[.]sg publishes `p=none`, nothing was done to stop it. The visible "AMAZON.COM" link points to a click tracker, and I did not see its final destination.

0 detections on the tracker domain does not clear it, because it is a legitimate service that many senders use.

**Verdict: Phishing (brand impersonation and sender spoofing through an abused bulk-email service). Severity: Medium.**

## IOCs (defanged)

| Type | Value | How to use it |
|---|---|---|
| Sender address (spoofed) | amz[at]fareast[.]com[.]sg | Block only when it arrives through Sendinblue |
| Return-Path | bounces-93450922-amz=fareast[.]com[.]sg@hn[.]d[.]sender-sib[.]com | Hunting |
| Sending host / IP | hn[.]d[.]sender-sib[.]com / 77[.]32[.]148[.]40 | Context only. Shared mail service, do not block |
| DKIM domain | email[.]myghs[.]com | Hunting and detection |
| Tracking URLs (2) | hxxps://chdgiei[.]r[.]bh[.]d[.]sendibt3[.]com/tr/cl/... | Block the specific URLs at the proxy, not the whole domain |
| Mail service account ID | 2736848 | Abuse report |
| Campaign ID | 93450922 | Abuse report |
| Message-Id | 202312150043.82962697325@smtp-relay[.]mailin[.]fr | Hunting |
| Subject | [ACTION REQUEST] You have been red flagged for violating our terms | Hunting |

I would not block fareast[.]com[.]sg or sendibt3[.]com as whole domains. The first belongs to a real company and the second is a real email-marketing service, so blocking them would cause false positives.

## MITRE ATT&CK

| ID | Technique | Reason |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | The email delivers links |
| T1656 | Impersonation | It pretends to be Amazon |
| T1583.006 | Acquire Infrastructure: Web Services | Likely use of a Sendinblue account to send (not confirmed) |

## Recommended actions

As L1 I would recommend these and leave the actions to L2.

1. Search mailbox logs for other emails from amz[at]fareast[.]com[.]sg or with the DKIM domain email[.]myghs[.]com.
2. Search proxy logs for hits on the specific tracking URLs.
3. If a user clicked or entered the code, escalate to L2, reset their credentials and review their sign-ins.
4. L2 can detonate the links in a sandbox to find the final destination.
5. Report abuse to Sendinblue/Brevo using account ID 2736848 and campaign ID 93450922.
6. Tell the owner of fareast[.]com[.]sg that their domain is being spoofed and that they publish `p=none`.
7. Tell the user the email is phishing and should be deleted.

## Limitations

- I did not see where the links finally go because they use a tracking redirect and I did not visit them.
- I could not determine whether fareast[.]com[.]sg or email[.]myghs[.]com is compromised.
- The To header does not match the recipient inside the tracking header, so the sample may have been edited or anonymized.
- 77[.]32[.]148[.]40 is a shared mail-service address, so its reputation reflects other senders too.
- The sample is from 2023 and I ran all lookups in 2026, so current records may be different from when the email was sent.
