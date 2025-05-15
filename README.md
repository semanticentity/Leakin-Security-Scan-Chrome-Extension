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
  - [Shoutouts](#shoutouts)

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

<img width="430" alt="whoops" src="https://github.com/user-attachments/assets/3f62dcca-aae6-48ba-a0f4-42deb71fe744" />

Leakin runs on page load while it's active. View the scan status and any detected potential leaks in the panel or devtools console

   
<img width="430" alt="chatty help" src="https://github.com/user-attachments/assets/db21e571-940d-46b8-94be-ccf98071a81a" />

Copy the findings with an LLM friendly prompt that will attempt to ELY5

   
<img width="430" alt="errorlogs" src="https://github.com/user-attachments/assets/c08e933e-efc1-4023-8be8-08fea271a177" />

Check Leakin's Chrome extension error logs for a complete history of findings under chrome://extensions/



---

## Why Would Anyone Need Leakin?  
You're in the arena. Vibe coding things. Not reading or attempting to understand your own code. 

LLMs don't give af about security (or billing quotas) and the free market loves an unsecured endpoint.  

Building in public sounds like a good idea, but it's always a very very bad idea.

<img width="1348" alt="Karpathy what have you done?" src="https://github.com/user-attachments/assets/c2390a15-c1cf-4fcc-9c9d-d744feafda87" />

---

**Leakin scans for:**
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

> *"The keys to the kingdom are usually lying around in plain sight. Leakin picks them up before someone else does."*

| **Type**                     | **Pattern Example**                | **Risk Level** | **What Leakin Does**                                                              |
| ---------------------------- | ---------------------------------- | -------------- | --------------------------------------------------------------------------------- |
| Google OAuth Client ID       | `xxx.apps.googleusercontent.com`   | 🟡 Low         | Flags potential phishing targets, filters test creds                              |
| Stripe Publishable Key       | `pk_live_...`                      | ⚠️ Medium      | Warns if domain restrictions not present                                          |
| Google API Key               | `AIza...`                          | ⚠️ Medium      | Checks for Maps/Firebase access, dedupes, filters examples, warns if unrestricted |
| Firebase API Key             | `AIza...`                          | ⚠️ Medium      | Flags if used with Firebase endpoints                                             |
| OpenAI API Key               | `sk-...`                           | ⚠️ Medium      | Detected in scripts or memory, alerts on potential billing abuse                  |
| Twilio API Key               | `SK...`                            | ⚠️ Medium      | Flags SMS/email abuse potential                                                   |
| Client Secret                | `client_secret=...`                | ⚠️ Medium      | OAuth or backend misuse risk                                                      |
| AWS Access Key ID            | `AKIA...`                          | 🚨 Critical    | Checks for pairing with secret key, high alert                                    |
| AWS Secret Access Key        | `wJalrXUtnFEMI...`                 | 🚨 Critical    | Full AWS access detection, checks pairing and context                             |
| Stripe Secret Key            | `sk_live_...`                      | 🚨 Critical    | Full Stripe access, clearly labeled                                               |
| SendGrid API Key             | `SG....`                           | 🚨 Critical    | Triggers phishing/spam risk warning                                               |
| GitHub Token                 | `ghp_...`, `gho_...`               | 🚨 Critical    | Shows origin, suggests revocation if valid                                        |
| Slack Token                  | `xox[baprs]-...`                   | 🚨 Critical    | Detects across scripts and memory, alerts for internal access                     |
| Bearer Token                 | `Authorization: Bearer ...`        | 🚨 Critical    | Flags any usage, explains impersonation risk                                      |
| Authorization Bearer Token   | `Authorization: Bearer ...`        | 🚨 Critical    | Matches headers or JS values, warns if public-facing                              |
| JWT Token                    | `eyJhbGciOi...`                    | 🚨 Critical    | Decodes payload, checks issuer, PII, expiration, session IDs                      |
| Decoded JWTs with PII        | Custom payload with `email`, `sub` | 🚨 Critical    | Highlights identity exposure, GDPR/CCPA violations                                |
| Platform Tokens (Adobe, etc) | JWTs with known issuer             | 🚨 Critical    | Custom decoding and pattern detection                                             |
| MongoDB URI                  | `mongodb+srv://...`                | 🚨 Critical    | Flags direct DB access, warns about ransom/data loss                              |
| PostgreSQL URI               | `postgres://...`                   | 🚨 Critical    | Full DB access risk                                                               |
| MySQL URI                    | `mysql://...`                      | 🚨 Critical    | Full DB access risk                                                               |
| Private Key                  | `-----BEGIN PRIVATE KEY-----`      | 🚨 Critical    | Full infra compromise if real                                                     |
| Hardcoded Password           | `password="..."`                   | 🚨 Critical    | Filters false positives, flags real secrets                                       |
| Window Object Secrets        | `window.app.authToken = "...";`    | 🚨 Critical    | Recursively scanned with pattern match + dedupe                                   |

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

## Shoutouts 

Big respect to WarrenBuffering for believing in dreams

<img width="584" alt="Screenshot 2025-03-27 at 4 02 50 AM" src="https://github.com/user-attachments/assets/b9ce56bd-c94c-46f7-bf23-f61e803d0a80" />

https://x.com/WarrenInTheBuff/status/1903471480140140854
