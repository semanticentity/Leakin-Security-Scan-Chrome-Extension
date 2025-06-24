/**
 * Content script for Leakin
 * Scans web pages for exposed API keys, credentials, and secrets.
 */

// Global variables to store findings and settings
let findings = [];
// Default scan settings, can be overridden by message from popup
let scanSettings = {
  scanInlineScripts: true,
  scanExternalScripts: true,
  scanWindowObjects: true,
  validateOnScan: false,
  showPopupOnScan: true
};

// --- Pattern Definitions (Global Scope) ---

const sensitivePatterns = [
  { label: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{20,}/ig,
    description: 'Google API keys (starting with AIza) can provide access to various Google services including Maps, YouTube, and Cloud APIs. If unrestricted, these can lead to unauthorized usage and billing charges.' },
  { label: 'Google OAuth Client ID', pattern: /client[_-]?id\s*[:=]\s*['"]([0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com)['"]/ig,
    description: 'Google OAuth Client IDs are used in authentication flows. Exposure might aid phishing attempts.' },
  { label: 'AWS Access Key ID', pattern: /(?:AWS|aws|Aws)[ \t\r\n\f]*(?:access_key_id|accessKeyId|ACCESS_KEY_ID)[ \t\r\n\f]*[:=][ \t\r\n\f]*["'](AKIA[0-9A-Z]{16})["']/ig },
  { label: 'AWS Secret Access Key', pattern: /(?:AWS|aws|Aws)[ \t\r\n\f]*(?:secret_access_key|secretAccessKey|SECRET_ACCESS_KEY)[ \t\r\n\f]*[:=][ \t\r\n\f]*["']([A-Za-z0-9\/+=]{40})["']/ig },
  { label: 'Authorization Bearer', pattern: /(authorization\s*[:=]\s*['"]Bearer\s+|Authorization:["']Bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)['"]/ig,
    description: 'CRITICAL: Bearer tokens grant direct API access. Exposure allows impersonation and unauthorized actions.' },
  { label: 'Private Key', pattern: /-----BEGIN[ A-Z0-9]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9]+PRIVATE KEY-----/is,
    description: 'CRITICAL: Private keys are fundamental for cryptographic operations. Exposure can compromise system security.' },
  { label: 'Client Secret', pattern: /client[_-]?secret\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]/ig,
    description: 'Client secrets are used in OAuth flows. Exposure can lead to token forgery and unauthorized access.' },
  { label: 'Firebase API Key', pattern: /firebase[_-]?api[_-]?key\s*[:=]\s*['"](AIza[0-9A-Za-z\-_]{35})['"]/ig,
    description: 'Firebase API keys (subset of Google API Keys) grant access to your Firebase project resources.' }, // Often same as Google API Key
  { label: 'Stripe Publishable Key', pattern: /pk_(?:test|live)_[A-Za-z0-9]{24,}/ig,
    description: 'Stripe publishable keys are meant for client-side use but should be domain-restricted in Stripe dashboard.' },
  { label: 'Stripe Secret Key', pattern: /sk_(?:test|live)_[A-Za-z0-9]{24,}/ig,
    description: 'CRITICAL: Stripe secret keys grant full API access to your Stripe account. Never expose client-side.' },
  { label: 'GitHub Token', pattern: /(github|gh)[_\-\.]?(?:token|key)\s*[:=]\s*['"](gh[pousr]_[a-zA-Z0-9_]{36,})['"]/ig,
    description: 'GitHub tokens (PATs) can grant access to repositories and organization data. Exposure is a high risk.' },
  { label: 'MongoDB URI', pattern: /mongodb(?:\+srv)?:\/\/[^\s"']+/ig,
    description: 'CRITICAL: MongoDB connection URIs grant direct database access. Exposure leads to data breaches.' },
  { label: 'PostgreSQL URI', pattern: /postgres(?:ql)?:\/\/[^\s"']+/ig, description: 'CRITICAL: PostgreSQL connection URIs grant direct database access.' },
  { label: 'MySQL URI', pattern: /mysql:\/\/[^\s"']+/ig, description: 'CRITICAL: MySQL connection URIs grant direct database access.' },
  { label: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    description: 'JSON Web Tokens (JWTs) are used for authentication/authorization. Exposure can lead to impersonation.' },
  { label: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/ig,
    description: 'Slack tokens grant access to Slack API, potentially exposing messages and user data.' },
  { label: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ig,
    description: 'CRITICAL: SendGrid API keys allow sending emails via your account, risking spam or phishing attacks.' },
  { label: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{30,}/ig, // OpenAI keys are typically sk- followed by 48 chars
    description: 'OpenAI API keys grant access to AI models, exposure can lead to unauthorized usage and billing.' },
  { label: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/ig, // Twilio Account SID (AC...) + Auth Token or API Key (SK...)
    description: 'Twilio API keys (SK...) grant access to Twilio services like SMS and voice calls.' },
  { label: 'Password', pattern: /(password|pass|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]/ig, // General password pattern
    description: 'CRITICAL: Hardcoded passwords are a major security risk.' },
  { label: 'API Key', pattern: /api[_-]?key\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,})['"]/ig, // Generic API key
    description: 'A generic API key was found. Its specific risk depends on the service it connects to.' },
  { label: 'Secret', pattern: /secret\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,})['"]/ig, // Generic secret
    description: 'A generic secret was found. Its specific risk depends on its usage.' },
];

const windowObjectScanPatterns = [ // Subset/Variant of sensitivePatterns, tailored for typical string values in window objects
  { label: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{20,}/, description: 'Google API Key found in window object.' },
  { label: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/, description: 'AWS Access Key ID found in window object.' },
  { label: 'Stripe API Key', pattern: /(pk|sk)_(test|live)_[0-9a-zA-Z]{24}/, description: 'Stripe API Key (publishable or secret) found in window object.' },
  { label: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}/, description: 'GitHub Token found in window object.' },
  { label: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48}/, description: 'OpenAI API Key found in window object.' },
  { label: 'Firebase API Key', pattern: /AIza[0-9A-Za-z_-]{35}/, description: 'Firebase API Key found in window object.' }, // Often same as Google API Key
  { label: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/, description: 'Twilio API Key found in window object.' },
  { label: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z_-]{22}\.[a-zA-Z0-9_-]{43}/, description: 'SendGrid API Key found in window object.' },
  { label: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, description: 'JWT Token found in window object.' },
  { label: 'Authorization Bearer', pattern: /bearer\s+([a-zA-Z0-9_\-.~+\/]+=*)/i, description: 'Bearer Token found in window object.' },
  { label: 'MongoDB URI', pattern: /mongodb(?:\+srv)?:\/\/[^\s"']+/, description: 'MongoDB URI found in window object.' },
  { label: 'MySQL URI', pattern: /mysql:\/\/[^\s"']+/, description: 'MySQL URI found in window object.' },
  { label: 'PostgreSQL URI', pattern: /postgres(?:ql)?:\/\/[^\s"']+/, description: 'PostgreSQL URI found in window object.' },
  { label: 'Password', pattern: /['"]([^'"]{6,})['"]/, valueSourceGroup: 1, contextKeywords: ['password', 'secret', 'token', 'apiKey', 'pass', 'pwd'], description: 'Potential hardcoded password/secret in window object string.' }, // More generic for window strings
  { label: 'API Key', pattern: /['"]([A-Za-z0-9\-_]{16,})['"]/, valueSourceGroup: 1, contextKeywords: ['apiKey', 'api_key', 'token', 'secret'], description: 'Potential generic API key/secret in window object string.' },
];

const falsePositivePatterns = [
  /example/i, /sample/i, /test/i, /demo/i, /placeholder/i,
  /your[-_]?key[-_]?here/i, /your[-_]?token[-_]?here/i, /your[-_]?api[-_]?key/i,
  /your[-_]?secret/i, /your[-_]?password/i, /your[-_]?credentials/i,
  /replace[-_]?with[-_]?your/i, /insert[-_]?your/i, /change[-_]?this/i,
  // Framework-specific error codes and constants
  /wrong[-_]?password/i, /missing[-_]?password/i, /invalid[-_]?password/i,
  /incorrect[-_]?password/i, /password[-_]?incorrect/i, /password[-_]?mismatch/i,
  /password[-_]?required/i, /password[-_]?invalid/i, /password[-_]?error/i,
  /weak[-_]?password/i, /"password":\s*"(wrong|weak|missing|invalid)-password"/i,
  /"passwordError":/i, /"error":\s*"(wrong|weak|missing|invalid)-password"/i,
  /"code":\s*"auth\/(wrong|weak|missing|invalid)-password"/i, /"code":\s*"auth\/user-not-found"/i,
  // Next.js specific patterns
  /PASSWORD:['"](auth\/)?[a-z-]+-password['"]/i,
  /PASSWORD:['"](wrong|weak|missing|invalid)-password['"]/i,
  /PASSWORD:['"]auth\/[a-z-]+['"]/i, /CredentialsSignin:['"]\w+['"]/i,
];

const falsePositiveStrings = [ // Exact strings that are often placeholders
  'XXXX', 'xxxx', '****', '0000', 'AAAA', 'aaaa', 'ABCD', 'abcd',
  'password', 'Password', 'PASSWORD', 'apikey', 'ApiKey', 'APIKEY',
  'token', 'Token', 'TOKEN', 'secret', 'Secret', 'SECRET',
  'key', 'Key', 'KEY', 'username', 'Username', 'USERNAME',
  'user', 'User', 'USER', 'login', 'Login', 'LOGIN',
  'credential', 'Credential', 'CREDENTIAL', 'AIzaFakeKey', 'pk_test_xxxxxxxx', 'sk_test_xxxxxxxx'
];

const riskMap = {
  'API Key': 'MEDIUM',
  'Google API Key': 'MEDIUM',
  'Google OAuth Client ID': 'LOW',
  'Secret': 'HIGH',
  'Password': 'CRITICAL',
  'AWS Access Key ID': 'CRITICAL',
  'AWS Secret Access Key': 'CRITICAL',
  'Authorization Bearer': 'CRITICAL',
  'Private Key': 'CRITICAL',
  'Client Secret': 'CRITICAL',
  'Firebase API Key': 'MEDIUM',
  'Stripe Publishable Key': 'MEDIUM',
  'Stripe Secret Key': 'CRITICAL',
  'GitHub Token': 'CRITICAL',
  'MongoDB URI': 'CRITICAL',
  'JWT Token': 'CRITICAL',
  'Slack Token': 'CRITICAL',
  'SendGrid API Key': 'CRITICAL',
  'OpenAI API Key': 'HIGH', // Elevated due to potential cost
  'Twilio API Key': 'HIGH', // Elevated due to potential cost/abuse
  'PostgreSQL URI': 'CRITICAL',
  'MySQL URI': 'CRITICAL',
  // Window specific labels if they don't map directly
  'Stripe API Key': 'CRITICAL', // Generic from window, specific pk/sk are better
  'Decoded JWTs with PII': 'CRITICAL',
  'Platform Tokens': 'CRITICAL',
  'Window Object Secrets': 'CRITICAL',
};

// --- Core Logic Functions ---

function executeBookmarklet(settings = {}) {
  if (Object.keys(settings).length > 0) {
    scanSettings = { ...scanSettings, ...settings };
  }
  console.log('Executing Leakin with settings:', scanSettings);
  findings = []; // Reset findings for a new scan
  runScans();
}

function isFalsePositive(text, contextPath = "") {
  if (!text) return true; // Treat empty strings as false positives to avoid noise
  const trimmedText = text.trim();
  if (trimmedText.length < 8 && !trimmedText.startsWith("eyJ") && !trimmedText.startsWith("AIza")) { // Exception for very short JWTs/Google Keys
      // Very short strings are often not real keys unless they fit specific short formats
      if (!/\d/.test(trimmedText) || !/[a-zA-Z]/.test(trimmedText)) return true; // Skip if not alphanumeric mix for short strings
  }


  if (falsePositiveStrings.some(fp => trimmedText === fp)) {
    return true;
  }
  for (const pattern of falsePositivePatterns) {
    if (pattern.test(trimmedText)) {
      return true;
    }
  }
  // Contextual false positive for window objects: if key name itself is a common placeholder
  if (contextPath) {
      const keyName = contextPath.substring(contextPath.lastIndexOf('.') + 1).toLowerCase();
      if (['example', 'sample', 'test', 'demo', 'mock', 'dummy', 'placeholder'].includes(keyName)) {
          return true;
      }
  }
  return false;
}

function analyzeContext({ source, extractedValue }) {
  let originDomain = null;
  let contextNote = null;
  const googleOwned = [
    'google.com', 'googleapis.com', 'gstatic.com', 'withgoogle.com',
    'maps.gstatic.com', 'maps.googleapis.com'
  ];
  const urlMatch = source.match(/\(([^)]+)\)/);
  if (urlMatch && urlMatch[1]) {
    try {
      const srcUrl = new URL(urlMatch[1]);
      originDomain = srcUrl.hostname;
      if (googleOwned.some(domain => originDomain.endsWith(domain))) {
        contextNote = 'This key was found in a script from a Google-owned domain. It might be a public key for services like Maps and not necessarily a leak.';
      }
    } catch (_) { /* Invalid URL */ }
  }
  return { originDomain, contextNote };
}

function getRiskLevel(label) {
  const normalizedLabel = {
    'Authorization Bearer Token': 'Authorization Bearer',
    'Hardcoded Password': 'Password',
    'MongoDB Connection String': 'MongoDB URI',
    'MySQL Connection String': 'MySQL URI',
    'PostgreSQL Connection String': 'PostgreSQL URI',
    'AWS Access Key': 'AWS Access Key ID',
    'Secret Key': 'Secret',
  }[label] || label;
  return riskMap[normalizedLabel] || 'LOW';
}

function scanText(content, source, patternsToScan = sensitivePatterns) {
  if (!content || typeof content !== 'string') return;

  patternsToScan.forEach(({ label, pattern, description, valueSourceGroup = 1 }) => {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const fullMatch = match[0];
      const extractedValue = match[valueSourceGroup] || fullMatch;

      if (isFalsePositive(extractedValue, source) || isFalsePositive(fullMatch, source)) {
        console.info(`ℹ️ Ignored potential false positive in ${source} for pattern ${label}: ${fullMatch.substring(0,100)}...`);
        continue;
      }
      const isDuplicate = findings.some(f =>
        f.source === source && f.match === fullMatch && f.pattern === label
      );
      if (!isDuplicate) {
        const { originDomain, contextNote } = analyzeContext({ source, extractedValue });
        findings.push({
          source,
          match: fullMatch,
          extractedValue,
          pattern: label,
          description,
          originDomain,
          contextNote,
          foundAt: new Date().toISOString(),
          riskLevel: getRiskLevel(label)
        });
        console.group(`🚨 Credentials found in ${source} [${label}]:`);
        console.warn(fullMatch.substring(0, 200) + (fullMatch.length > 200 ? "..." : "")); // Log truncated match
        if (description) console.info(description);
        console.groupEnd();
      }
    }
  });
}

function scanInlineScripts() {
  if (!scanSettings.scanInlineScripts) return Promise.resolve();
  console.log('Scanning inline scripts...');
  Array.from(document.querySelectorAll('script:not([src])')).forEach((script, index) => {
    scanText(script.textContent, `inline script #${index + 1}`);
  });
  return Promise.resolve();
}

function scanExternalScripts() {
  if (!scanSettings.scanExternalScripts) return Promise.resolve();
  console.log('Scanning external scripts...');
  const scriptPromises = Array.from(document.querySelectorAll('script[src]'))
    .filter(script => {
      try {
        const scriptUrl = new URL(script.src, location.href);
        return scriptUrl.origin === location.origin;
      } catch (e) {
        console.warn(`❗ Invalid or cross-origin script URL (will not fetch): ${script.src}`);
        return false;
      }
    })
    .map(script =>
      fetch(script.src)
        .then(res => {
          if (!res.ok) throw new Error(`HTTP error! status: ${res.status} for ${script.src}`);
          return res.text();
        })
        .then(js => scanText(js, `external script (${script.src})`))
        .catch(error => console.warn(`❗ Could not fetch or scan ${script.src}: ${error.message}`))
    );
  return Promise.all(scriptPromises.map(p => p.catch(e => e)));
}

function scanWindowObjectProperties() {
  if (!scanSettings.scanWindowObjects) return Promise.resolve();
  console.log('Scanning window object properties...');
  const visited = new Set();
  const MAX_DEPTH = 7;

  function scanObjectRecursively(obj, path = 'window', depth = 0) {
    if (depth > MAX_DEPTH || obj === null || typeof obj === 'undefined' || visited.has(obj)) {
      return;
    }
    visited.add(obj);

    if (typeof obj === 'string' && obj.length > 5) { // Only scan strings of reasonable length
        windowObjectScanPatterns.forEach(({ label, pattern: regex, description, valueSourceGroup = 0, contextKeywords }) => {
            // If contextKeywords are defined, check if path contains any of them
            if (contextKeywords) {
                const lowerPath = path.toLowerCase();
                if (!contextKeywords.some(kw => lowerPath.includes(kw))) {
                    return; // Skip if path doesn't match context keywords
                }
            }

            const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
            let match;
            while ((match = globalRegex.exec(obj)) !== null) {
                const fullMatch = match[0];
                const extractedValue = match[valueSourceGroup] || fullMatch; // Use specified group or full match

                if (isFalsePositive(extractedValue, path) || isFalsePositive(fullMatch, path)) {
                    // console.info(`ℹ️ Ignored window false positive in ${path} for ${label}: ${extractedValue.substring(0,100)}`);
                    continue;
                }
                const isDuplicate = findings.some(f =>
                    f.source === path && f.match === fullMatch && f.pattern === label);
                if (!isDuplicate) {
                    findings.push({
                        source: path,
                        match: fullMatch,
                        extractedValue,
                        pattern: label,
                        description,
                        foundAt: new Date().toISOString(),
                        riskLevel: getRiskLevel(label)
                    });
                    console.group(`🚨 Credentials found in ${path} [${label}]:`);
                    console.warn(fullMatch.substring(0,100) + "...");
                    if (description) console.info(description);
                    console.groupEnd();
                }
            }
        });
    } else if (typeof obj === 'object') {
      const keys = Object.keys(obj);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        // Skip common, noisy, or problematic properties
        if (['webkitStorageInfo', 'webkitResolveLocalFileSystemURL', 'frameElement', 'launchQueue', 'event', 'performance', 'localStorage', 'sessionStorage', 'document', 'customElements', 'history', 'navigator', 'screen', 'speechSynthesis', 'visualViewport', 'styleMedia'].includes(key)) continue;
        if (obj[key] instanceof Node || typeof obj[key] === 'function' || obj[key] instanceof Window || obj[key] === window ) continue;
        if (path.startsWith('window.localStorage') || path.startsWith('window.sessionStorage')) continue; // Already handled or too noisy

        try {
          scanObjectRecursively(obj[key], `${path}.${key}`, depth + 1);
        } catch (e) { /* console.debug(`Could not access property ${path}.${key}: ${e.message}`); */ }
      }
    }
  }
  return new Promise(resolve => {
    setTimeout(() => {
      try {
        scanObjectRecursively(window);
      } catch (e) { console.error('Error during top-level window object scan:', e); }
      resolve();
    }, 0);
  });
}

async function runScans() {
  console.time('LeakinScanTime');
  await scanInlineScripts();
  await scanExternalScripts();
  await scanWindowObjectProperties();
  console.timeEnd('LeakinScanTime');
  processAndDisplayFindings();
}

// --- Result Processing and Display ---

function processJWT(finding) {
  if (finding.pattern === 'JWT Token' && finding.match) {
    try {
      const jwtParts = finding.match.split('.');
      if (jwtParts.length === 3) {
        const header = JSON.parse(atob(jwtParts[0]));
        const payload = JSON.parse(atob(jwtParts[1]));
        finding.decoded = { header, payload, signature: jwtParts[2] };
        if (payload.exp) finding.description += ` Expires: ${new Date(payload.exp * 1000).toLocaleString()}.`;
        if (payload.iss) finding.description += ` Issuer: ${payload.iss}.`;
        if (payload.email || payload.sub || payload.name || payload.preferred_username) {
            finding.description += ' Contains PII.';
            // If this specific finding type isn't set, upgrade it
            if (finding.pattern === 'JWT Token') finding.pattern = 'Decoded JWTs with PII';
            finding.riskLevel = getRiskLevel('Decoded JWTs with PII'); // Ensure high risk
        }
      }
    } catch (e) { console.warn('Error decoding JWT:', e); }
  }
  return finding;
}

function dedupFindings(rawFindings) {
  const seen = new Map();
  rawFindings.forEach(finding => {
    const key = `${finding.extractedValue}-${finding.pattern}`; // Dedupe based on value and type
    if (!seen.has(key)) {
      seen.set(key, { ...finding, sources: [finding.source] });
    } else {
      const existing = seen.get(key);
      if (!existing.sources.includes(finding.source)) {
        existing.sources.push(finding.source);
      }
      // Prioritize more specific descriptions or decoded JWTs
      if (finding.decoded && !existing.decoded) existing.decoded = finding.decoded;
      if (finding.description && (!existing.description || finding.description.length > existing.description.length)) {
          existing.description = finding.description;
      }
       if (getRiskLevel(finding.pattern) > getRiskLevel(existing.pattern)) { // Higher risk pattern takes precedence
          existing.pattern = finding.pattern;
          existing.riskLevel = getRiskLevel(finding.pattern);
      }
    }
  });
  return Array.from(seen.values());
}


function processAndDisplayFindings() {
  let processedFindings = findings.map(processJWT); // Process JWTs first
  processedFindings = dedupFindings(processedFindings); // Then deduplicate

  if (processedFindings.length > 0) {
    console.log(`Leakin found ${processedFindings.length} potential leaks.`, processedFindings);
    if (scanSettings.showPopupOnScan) {
      showPopup(processedFindings);
    }
  } else {
    console.log('✅ Leakin: No obvious credential leaks found.');
  }
  // Update global findings with processed ones if needed elsewhere, or ensure popup gets these
  findings = processedFindings;
}


function scrubPII(dataToScrub) { // dataToScrub can be findings object or array
  const piiPatterns = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone: /(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g,
    // Add more specific patterns as needed
  };
  // Deep clone to avoid modifying original findings array/objects
  const scrubbedData = JSON.parse(JSON.stringify(dataToScrub));

  function scrubValue(str) {
    if (!str || typeof str !== 'string') return str;
    let result = str;
    for (const [type, pattern] of Object.entries(piiPatterns)) {
      result = result.replace(pattern, match => {
        if (type === 'email') {
          const [local, domain] = match.split('@');
          return `${local[0]}***@${domain[0]}***${domain.slice(-4)}`;
        }
        return `${match[0]}${'*'.repeat(Math.max(0,match.length - 2))}${match.length > 1 ? match[match.length - 1] : ''}`;
      });
    }
    return result;
  }

  function recursiveScrub(obj) {
    if (Array.isArray(obj)) {
      obj.forEach(item => recursiveScrub(item));
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (typeof obj[key] === 'string') {
          // Specifically scrub 'match', 'extractedValue', and JWT payload values
          if (key === 'match' || key === 'extractedValue') {
            obj[key] = scrubValue(obj[key]);
          }
          if (key === 'decoded' && obj.decoded && obj.decoded.payload) {
             for(const payloadKey in obj.decoded.payload) {
                 if(typeof obj.decoded.payload[payloadKey] === 'string') {
                    obj.decoded.payload[payloadKey] = scrubValue(obj.decoded.payload[payloadKey]);
                 }
             }
          }
        } else if (typeof obj[key] === 'object') {
          recursiveScrub(obj[key]);
        }
      }
    }
  }
  recursiveScrub(scrubbedData);
  return scrubbedData;
}

function copyToClipboard(dataForPrompt) {
  const scrubbedFindingsForPrompt = scrubPII(dataForPrompt); // Scrub before generating prompt
  const prompt = `Hey boss, I need you to analyze a potential credential leak detected by **Leakin**, every vibe coder's fav Chrome extension.

Here's the leak finding as a JSON payload from Leakin:

${JSON.stringify(scrubbedFindingsForPrompt, null, 2)}

👉 I need you to help me figure out:
1. **What is this?** (Type of key/secret, service it belongs to)
2. **Why is it dangerous (if it is)?** (Potential impact of exposure)
3. **How to spot FALSE POSITIVES and make sure they're not an issue?** (Common examples, test data)
4. **If this is MY app:** what should I do to fix it, prevent it, and avoid embarrassing myself in the future? (Remediation, prevention)
5. **If this is SOMEONE ELSE'S app:** how do I report it responsibly without being a troll or breaking any laws? (Responsible disclosure)
6. **Explain like I who skipped class the day they taught "Don't hardcode secrets" and now my life may be in your hands.** (Simple explanation)

DISCLAIMER: This is for **education**, **security awareness**, and **responsible development**.
PII has been attempted to be scrubbed, but review carefully.
`;
  navigator.clipboard.writeText(prompt).then(() => {
    const btn = document.getElementById('copy-llm-btn');
    if (btn) {
      btn.textContent = '✓ Copied to Clipboard!';
      btn.style.background = '#373d35'; // Success indication
      setTimeout(() => {
        btn.textContent = 'Copy with LLM prompt';
        btn.style.background = ''; // Reset style
      }, 2500);
    }
  }).catch(err => console.error('Failed to copy to clipboard:', err));
}

function exportFindings(dataToExport, filename = 'leakin-findings.json') {
  const scrubbedFindingsToExport = scrubPII(dataToExport); // Scrub before export
  const blob = new Blob([JSON.stringify(scrubbedFindingsToExport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  console.info(`📦 Findings exported as ${filename}`);
}

function copyFindingsToClipboard(dataToCopy) {
    const scrubbedFindings = scrubPII(dataToCopy); // Scrub before copying raw JSON
    const text = JSON.stringify(scrubbedFindings, null, 2);
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text)
        .then(() => console.info('📋 Findings (scrubbed JSON) copied to clipboard'))
        .catch(err => {
            console.warn('❌ Clipboard write failed, using prompt fallback:', err);
            window.prompt('Copy findings manually (PII scrubbed):', text);
        });
    } else {
      window.prompt('Copy findings manually (PII scrubbed):', text);
    }
}

function showPopup(popupData) {
  const existingPopup = document.getElementById('leakin-scanner-popup');
  if (existingPopup) existingPopup.remove();

  const popup = document.createElement('div');
  popup.id = 'leakin-scanner-popup'; // Unique ID
  // Styles moved to CSS would be better, but for self-contained script:
  Object.assign(popup.style, {
    position: 'fixed', top: '20px', right: '20px', zIndex: '2147483647',
    width: '480px', background: '#1e1e1e', color: '#e0e0e0', borderRadius: '8px',
    boxShadow: '0 5px 15px rgba(0,0,0,0.5)', padding: '20px',
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif',
    fontSize: '14px', fontWeight: '400', maxHeight: '90vh', display: 'flex', flexDirection: 'column'
  });

  const criticalCount = popupData.filter(f => f.riskLevel === 'CRITICAL').length;
  const highCount = popupData.filter(f => f.riskLevel === 'HIGH').length;

  popup.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
      <h3 style="margin: 0; font-size: 18px; color: #f0f0f0; font-weight: 500;">Leakin: Scan Results</h3>
      <span id="leakin-close-popup-btn" style="cursor: pointer; font-size: 22px; color: #aaa; line-height: 1;">&times;</span>
    </div>
    <p style="margin: 0 0 15px; font-size: 14px; color: #ccc;">
      Found <strong>${popupData.length}</strong> potential leak${popupData.length !== 1 ? 's' : ''}.
      ${criticalCount > 0 ? ` <span style="color: #ff6b6b; font-weight: bold;">${criticalCount} CRITICAL</span>.` : ''}
      ${highCount > 0 ? ` <span style="color: #ffa500; font-weight: bold;">${highCount} HIGH</span>.` : ''}
    </p>
    <div id="leakin-findings-container" style="flex-grow: 1; overflow-y: auto; margin-bottom: 15px; border: 1px solid #333; padding: 10px; border-radius: 4px; background: #2a2a2a;">
      ${popupData.map(item => `
        <div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #444;">
          <div><strong>Type:</strong> <span style="color: #87ceeb;">${item.pattern}</span> (<span style="color: ${item.riskLevel === 'CRITICAL' ? '#ff6b6b' : item.riskLevel === 'HIGH' ? '#ffa500' : '#90ee90'}; font-weight: bold;">${item.riskLevel}</span>)</div>
          <div style="margin-top: 4px;">
            <strong>Found in ${item.sources.length} location${item.sources.length > 1 ? 's' : ''}:</strong>
            <ul style="margin: 4px 0 0 15px; padding-left: 0; list-style-type: disclosure-closed;">
              ${item.sources.map(s => `<li style="color: #ccc; font-size: 0.9em;">${s.length > 100 ? s.substring(0,97) + "..." : s}</li>`).join('')}
            </ul>
          </div>
          <div style="margin-top: 4px;"><strong>Match:</strong> <code style="word-break: break-all; color: #f0e68c; background: #333; padding: 2px 4px; border-radius: 3px; font-size: 0.9em;">${(item.match || "").length > 150 ? (item.match || "").substring(0,147) + "..." : (item.match || "")}</code></div>
          ${item.description ? `<div style="margin-top: 4px; font-size: 0.9em; color: #bbb;"><strong>Note:</strong> ${item.description}</div>` : ''}
          ${item.originDomain ? `<div style="margin-top: 4px; font-size: 0.9em; color: #bbb;"><strong>Script Origin:</strong> ${item.originDomain}</div>` : ''}
          ${item.contextNote ? `<div style="margin-top: 4px; font-style: italic; color: #999; font-size: 0.9em;">${item.contextNote}</div>` : ''}
          ${item.decoded ? `<div style="margin-top: 5px;"><strong>Decoded JWT:</strong><pre style="margin: 5px 0; padding: 8px; background: #333; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; color: #f0e68c; font-size: 0.85em;">${JSON.stringify(item.decoded.payload, null, 2)}</pre></div>` : ''}
        </div>
      `).join('') || '<p style="text-align: center; color: #888;">No findings to display.</p>'}
    </div>
    <div style="display: flex; gap: 10px; margin-top: auto;">
      <button id="leakin-copy-llm-btn" class="leakin-btn" style="flex:1;">Copy for LLM</button>
      <button id="leakin-export-btn" class="leakin-btn" style="flex:1;">Export JSON</button>
      <button id="leakin-copy-json-btn" class="leakin-btn" style="flex:1;">Copy JSON</button>
    </div>
    <style>
      .leakin-btn { background: #4a4a4a; color: #f0f0f0; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500; transition: background 0.2s; }
      .leakin-btn:hover { background: #5a5a5a; }
      #leakin-findings-container::-webkit-scrollbar { width: 8px; }
      #leakin-findings-container::-webkit-scrollbar-track { background: #2a2a2a; }
      #leakin-findings-container::-webkit-scrollbar-thumb { background: #555; border-radius: 4px; }
      #leakin-findings-container::-webkit-scrollbar-thumb:hover { background: #666; }
    </style>
  `;
  document.body.appendChild(popup);

  document.getElementById('leakin-close-popup-btn')?.addEventListener('click', () => popup.remove());
  document.getElementById('leakin-copy-llm-btn')?.addEventListener('click', () => copyToClipboard(popupData));
  document.getElementById('leakin-export-btn')?.addEventListener('click', () => exportFindings(popupData));
  document.getElementById('leakin-copy-json-btn')?.addEventListener('click', () => copyFindingsToClipboard(popupData));

  popup.addEventListener('click', (e) => e.stopPropagation()); // Prevent clicks inside from closing (if body click listener added later)
}


// --- Initialization and Message Handling ---
let isContentScriptReady = false;
let queuedScanRequest = null;

// Initial execution when the content script loads on a page
executeBookmarklet(); // Run with default settings initially
isContentScriptReady = true;

// Process any queued request that came in before content script was fully ready
function processQueuedRequest() {
  if (queuedScanRequest) {
    console.log("Processing queued scan request.");
    executeBookmarklet(queuedScanRequest.settings);
    // We need to be careful about sendResponse here if the original listener already returned.
    // For simplicity, the popup's execute listener has a timeout and handles errors.
    // If a direct response is needed for the queued request, this logic would be more complex.
    queuedScanRequest = null;
  }
}

// Set ready and process queue (ensure this runs after initial executeBookmarklet)
Promise.resolve().then(() => {
    isContentScriptReady = true;
    console.log("Leakin content script is ready.");
    processQueuedRequest();
});


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "execute") {
    if (isContentScriptReady) {
      console.log("Executing scan from popup message with settings:", request.settings);
      executeBookmarklet(request.settings);
      sendResponse({status: "executed", findingsCount: findings.length, findings: findings});
    } else {
      console.log("Content script not ready, queuing scan request.");
      queuedScanRequest = request;
      // sendResponse({status: "queued"}); // Optional: inform popup it's queued
      // Or, more simply, let the popup timeout/retry or rely on its own check.
      // For now, we don't send an immediate response for queued, to keep popup logic simpler.
      // The popup's executeButton.disabled and scanStatus will handle user feedback.
    }
    return true; // Indicate that we will send a response asynchronously (eventually)
  }
  // Note: Export functionality might be better handled in popup.js using findings from the main scan,
  // or by requesting the current 'findings' array from content.js.
  // Direct file operations like creating blobs and links are UI interactions for the current page,
  // which might be unexpected if triggered from popup without user action on the page itself.
  // For now, keeping it as is, but consider UX implications.
  if (request.action === "export" && request.data) {
    exportFindings(request.data, request.filename);
    sendResponse({status: "exported"});
    return true;
  }
  return false; // Indicate async response not sent or message not handled
});

console.log("Leakin content script loaded and running.");
