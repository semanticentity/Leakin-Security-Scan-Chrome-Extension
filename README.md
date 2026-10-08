# Leakin

<img src="leakin.svg" alt="Leakin Security Scan Chrome Extension" width="128" height="128">

**A local Chrome extension for finding credentials and other sensitive values exposed in web pages.**

Leakin scans page content, scripts, and selected browser objects for patterns associated with API keys, access tokens, database connection strings, private keys, and hardcoded passwords. It groups duplicate findings, filters common placeholders, decodes JWT payloads for inspection, and explains the likely risk of each match.

Leakin is a triage tool. A match is evidence to investigate, not proof that a credential is valid or exploitable.

## Installation

1. Clone this repository or download it as a ZIP file.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode**.
4. Select **Load unpacked** and choose the repository directory.

The extension runs locally in the browser. It does not send findings to a Leakin service. When enabled, its content script runs on matching pages and may read linked scripts so it can scan their text.

## Usage

1. Open the page you want to inspect.
2. Select the Leakin extension and run a scan.
3. Review each finding in context before taking action.
4. If the credential belongs to you, restrict or revoke it and move privileged operations behind a server-side boundary.
5. If it belongs to someone else, follow the owner's responsible-disclosure process.

<img width="430" alt="Leakin scan result" src="https://github.com/user-attachments/assets/3f62dcca-aae6-48ba-a0f4-42deb71fe744" />

<img width="430" alt="Leakin finding explanation" src="https://github.com/user-attachments/assets/db21e571-940d-46b8-94be-ccf98071a81a" />

## What it detects

- Google, AWS, Stripe, GitHub, Slack, SendGrid, and other recognizable key formats
- Bearer tokens and JWTs
- MongoDB, PostgreSQL, and MySQL connection strings
- Private keys, client secrets, and hardcoded passwords
- Potentially sensitive values exposed through page scripts or browser objects

## How findings are handled

- **Pattern detection:** Finds values that match known credential formats.
- **Contextual risk labels:** Explains the likely consequence if a match is real.
- **False-positive filtering:** Removes common examples, placeholders, and framework error strings.
- **Deduplication:** Groups the same value found in multiple locations.
- **JWT inspection:** Decodes readable header and payload fields without asserting that the token is valid.
- **Local processing:** Findings remain in the browser unless the user explicitly copies or exports them.

## Limitations

- Pattern matching can produce false positives and false negatives.
- Leakin does not establish whether a detected credential is active.
- A client-visible key is not always a secret; some publishable keys are designed for browser use but may still require domain or API restrictions.
- JWT decoding does not verify a signature.
- Browser access controls, cross-origin restrictions, and dynamically generated content can limit coverage.

## Responsible use

Use Leakin only on systems you own or are authorized to assess. Do not attempt to use detected credentials. Report third-party exposures through an appropriate security contact or disclosure program.

For applications you control:

- Keep privileged credentials out of client-side code.
- Restrict public keys by domain, IP address, API, or service where supported.
- Rotate exposed credentials and inspect their usage history.
- Use a secrets manager for server-side credentials.
- Add secret scanning to development and deployment workflows.

## License

See [LICENSE](LICENSE). The repository's license includes a non-commercial-use limitation.
