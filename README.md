# Leakin  
<img src="leakin.svg" alt="Leakin Security Scan Chrome Extension" width="128" height="128">

> Nothing kills a startup faster than leaking your keys, except probably your pitch deck. 

---
## Table of Contents

- [Leakin](#leakin)
  - [Table of Contents](#table-of-contents)
  - [What is Leakin?](#what-is-leakin)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Why Would Anyone Need Leakin?](#why-would-anyone-need-leakin)
    - [What's Special About Leakin’s Detection?](#whats-special-about-leakins-detection)
  - [Features](#features)
  - [Supported Credential Types](#supported-credential-types)
    - [Bots Scrape This Stuff FAST](#bots-scrape-this-stuff-fast)
  - [False Positives (And Honeytokens)](#false-positives-and-honeytokens)
    - [Leakin Tries To Filter Out:](#leakin-tries-to-filter-out)
    - [Honeytokens (What are Those?)](#honeytokens-what-are-those)
  - [Best Practices (If You Care About That Sort of Thing)](#best-practices-if-you-care-about-that-sort-of-thing)
  - [License and Warranty](#license-and-warranty)

---

## What is Leakin?

Leakin is a **Chrome extension** for the vibe coding era. It scans your web pages for leaked API keys, credentials, tokens, and other secrets you *probably* didn't mean to expose.  

Perfect for AI-powered devs building entire apps without reading their own code, or for the old guard who just want to watch the world burn a little slower.

If you ever copied code from ChatGPT and shipped it without reading, Leakin was made for you.  


## Installation

1. Clone this repo or download the zip
2. Go to `chrome://extensions/` in your browser
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" → select the unzipped `leakin` folder

## Usage

1. Leakin runs on page load, or you can click the Leakin icon in your Chrome toolbar
2. View the scan status and any detected credential leaks in the panel and devtools console
3. Check Leakin's Chrome extension error logs for a complete history of findings

---

## Why Would Anyone Need Leakin?  
You're in the arena. Vibe coding things. Not reading or attempting to understand your own code. 

LLMs don't give af about security (or billing quotas) and the free market loves an unsecured endpoint.  

Building in public sounds like a good idea, but it's always a very very bad idea.

Leakin scans for:
- Hardcoded secrets  
- JWTs floating in global variables  
- Unrestricted API keys  
- Tokens with **no expiration date** (YOLO)  
- Database connection strings (yes, we've seen that)  
 
**Leakin doesn't fix your mistakes.**   
What happens next is between you, your cloud provider, and whatever forked version of VSCode your favorite LLM likes.


### What's Special About Leakin’s Detection?
- ✅ **False Positive Filtering**  
  Filters out dummy/test creds (like `pk_test_`, `AIzaFake...`) and common error messages.

- ✅ **Deduplication**  
  Combines duplicate matches across multiple sources for easier review.

- ✅ **JWT Decoding + Analysis**  
  Extracts header & payload for insight on expiration, issuer, and PII exposure.

- ✅ **Runs Fully Locally**  
  Zero exfiltration. Your data stays your data. Leakin **snitches on leaks, not on you**.

---

## Features  
 
- **Finds the usual suspects:** Google API keys, AWS keys, Stripe secrets, JWTs, GitHub tokens, database creds, and more.  
- **Export and copy findings** for when you need to explain to your cofounder why it's over before it ever began.  
- **False positive filtering** because *not* everything called “password” is your actual password.  
- **Decodes JWTs** so you can see which secrets you've been handing out like candy.  
- **Chrome Extension Error Logs** double as your **scan history**.  
- **Runs locally only**. No servers, no snitching.  
- **Runs on page load.** Never think again.  

---

## Supported Credential Types  

> _“The keys to the kingdom are usually lying around in plain sight. Leakin picks them up before someone else does.”_

| **Type**                          | **Pattern Example**               | **Risk Level** | **What Could Happen?**                                                   |
|-----------------------------------|-----------------------------------|---------------:|--------------------------------------------------------------------------|
| **Google API Key**                | `AIza...`                         | 🔥 High        | Unauthorized access to Maps, YouTube, Firebase → $$$ billing spikes     |
| **Google OAuth Client ID**        | `xxx.apps.googleusercontent.com`  | ⚠️ Medium      | Potential abuse in OAuth phishing schemes                               |
| **AWS Access Key ID**             | `AKIA...`                         | 🚨 Critical    | Full AWS access → crypto mining, data exfiltration, total account takeover |
| **AWS Secret Access Key**         | `wJalrXUtnFEMI/K7MDENG/bPxRfiCY...` | 🚨 Critical | Used with Access Key ID → unlocks entire AWS environment                |
| **Firebase API Key**              | `AIza...`                         | ⚠️ Medium      | Potential abuse of Firebase services → data theft, billing hits         |
| **Stripe Publishable Key**        | `pk_live_...`                     | 🟡 Low/Medium  | Can be used in *checkout* abuse if domain restrictions aren't set       |
| **Stripe Secret Key**             | `sk_live_...`                     | 🚨 Critical    | Full control over Stripe account → charge cards, access customer data   |
| **SendGrid API Key**              | `SG.xxxxxxxx`                    | 🔥 High        | Send spam/phishing emails from your domain → blacklisting risks         |
| **GitHub Personal Access Token**  | `ghp_...`                         | 🔥 High        | Repo access → code leaks, secrets exposed, malware injections           |
| **GitHub OAuth Token**            | `gho_...`                         | 🔥 High        | User impersonation → repo control, PR abuse                            |
| **OpenAI API Key**                | `sk-...`                          | ⚠️ Medium      | Abuse OpenAI endpoints → cost escalation, account depletion             |
| **Twilio API Key**                | `SK...`                           | ⚠️ Medium      | Send SMS/calls → account charges, potential fraud                      |
| **Slack Tokens**                  | `xoxb-...`, `xoxp-...`           | 🔥 High        | Full access to Slack → data leaks, impersonation, internal chaos        |
| **Bearer Tokens**                | `Authorization: Bearer ...`      | 🚨 Critical    | Direct API access → impersonate users, gain access to protected endpoints |
| **MongoDB URI**                  | `mongodb+srv://user:pass@host`   | 🚨 Critical    | Direct database access → data theft, data loss, ransom potential        |
| **PostgreSQL URI**               | `postgres://user:pass@host/db`   | 🚨 Critical    | Same as above → full DB control                                         |
| **MySQL URI**                    | `mysql://user:pass@host/db`      | 🚨 Critical    | Same as above → full DB control                                         |
| **JWT Token**                    | `eyJhbGciOi...`                  | 🔥 High        | Impersonate users, access protected resources, privilege escalation     |
| **Private Key (RSA/DSA/ECDSA)**  | `-----BEGIN PRIVATE KEY-----`    | 🚨 Critical    | Full access to servers/infrastructure, decrypted data risk              |
| **Generic Client Secret**        | `client_secret=...`              | ⚠️ Medium      | OAuth abuse, bypass security mechanisms                                 |
| **Secret Variables**             | `secret=...`                     | ⚠️ Medium      | General misuse → further recon, potential data exposure                 |
| **Hardcoded Passwords**          | `password=...`                   | 🚨 Critical    | Compromise user/admin accounts, total system access                     |
| **Authorization Bearer Token**   | `Authorization: Bearer ...`      | 🚨 Critical    | API calls impersonation → data theft, fraudulent activity               |
| **Window Object Secrets**        | Dynamic detection                | 🔥 High        | Sensitive tokens/keys floating in memory → immediate exploitation       |
| **Decoded JWTs with PII**        | Custom decoded payloads          | 🔥 High        | PII exposure → GDPR/CCPA risk, identity theft                          |
| **Platform-Specific Tokens**     | e.g. CNN, Adobe JWTs             | 🔥 High        | Service impersonation, access to protected resources, session hijacking |

---

### Bots Scrape This Stuff FAST  
The time between leak and breach is measured in **minutes**, not hours and you'll wake up to emails saying: 

> "We've disabled your account due to suspicious activity."

---

## False Positives (And Honeytokens)  

### Leakin Tries To Filter Out:
- Example API keys in docs  
- Test credentials (`pk_test_`, `AIzaFakeKey`)  
- Placeholder strings (`your-api-key-here`)  
- Common framework error messages (`wrong-password`)  

### Honeytokens (What are Those?)
Honeytokens are **fake** credentials meant to catch attackers. 

Leakin tries to **flag** potential honeytokens.

If you see `canarytoken` or `honeytrap`, congrats:  
1. Someone's watching.  
2. Maybe it's you.  

---

## Best Practices (If You Care About That Sort of Thing)

For **Vibe Coders**:
- Never hardcode credentials in client-side code.  
- Use server-side APIs with proper auth flows.  
- Lock down API keys by domain, IP, or service.  
- Rotate keys regularly. Yes, regularly.  
- Monitor key usage. Set alerts.  
- Use secrets managers (AWS Secrets Manager, Vault, etc.). 
- Read [Why Would Anyone Need Leakin?](#why-would-anyone-need-leakin) 
- Please #learntocode (or at least learn to revoke a key). 

For **Security "Researchers"**:
- **Responsible disclosure only.**    
- Don't validate keys extensively or you might violate ToS.  
- Be respectful when reporting. Their startup is already on fire.

## License and Warranty

Non-Commercial Use Only. Not for distribution or commercial applications. 

Use at your own risk. It's never too late to delete all your code and start over, or give up entirely.