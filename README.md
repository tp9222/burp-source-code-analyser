# Source Code Analyser — Burp Suite Extension

A passive Burp Suite extension that automatically scans HTML, JavaScript, JSON,
and text responses for **75 security vulnerabilities and weak coding practices**
as you browse. No active requests are ever sent — it works entirely by inspecting
traffic already flowing through Burp Proxy.

Click any finding to see the exact bad line of code, a linter-style context block
with a `^^^` pointer, a plain-English explanation of **why it is insecure** and
what attack it enables, a bad-vs-good code example, step-by-step remediation
guidance, and the mapped CWE / OWASP Top 10 reference.

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Burp Suite | Community or Pro 2020.1+ | Free edition works fine |
| Jython | 2.7.3 standalone JAR | One-time download |
| Java | 11 or later | Bundled with Burp Suite |

---

## Installation

### Step 1 — Download Jython (one-time only)

1. Go to **https://www.jython.org/download**
2. Download **Jython Standalone** — the file is named `jython-standalone-2.7.3.jar`
3. Save it somewhere permanent:
   - Windows: `C:\Tools\jython-standalone-2.7.3.jar`
   - macOS / Linux: `~/tools/jython-standalone-2.7.3.jar`

### Step 2 — Point Burp at Jython

1. Open **Burp Suite**
2. Go to **Extender** (or **Extensions** in newer versions) → **Options** tab
3. Scroll to **Python Environment**
4. Click **Select file...** and choose the Jython JAR from Step 1

### Step 3 — Load the Extension

1. Go to **Extender → Extensions** → click **Add**
2. Set **Extension type** to `Python`
3. Click **Select file...** and choose `SourceCodeAnalyser.py`
4. Click **Next**

You should see in the Output pane:
```
[SCA] Source Code Analyser loaded — 75 rules active.
Browse any page to start scanning.
```

A **"Source Code Analyser"** tab will appear in the main Burp toolbar.

### Step 4 — Configure Your Browser Proxy

**Easiest option — use Burp's built-in browser:**
Go to **Proxy → Intercept** → click **Open browser**. No further setup needed.

**Manual option — proxy your own browser:**

Burp's default listener is `127.0.0.1:8080`. Set your browser's HTTP and HTTPS
proxy to that address.

**Install Burp's CA certificate (required for HTTPS):**

1. With the browser proxied, navigate to `http://burpsuite`
2. Click **CA Certificate** to download `cacert.der`
3. Import it into your browser's trust store:
   - Chrome / Edge: Settings → Privacy → Manage certificates → Import
   - Firefox: Settings → Privacy → View Certificates → Import
   - macOS: Double-click the file → Keychain Access → set to Always Trust
   - Windows: Double-click the file → Install Certificate → Trusted Root CAs

### Step 5 — Start Scanning

1. Set **Proxy → Intercept** to **Intercept is off**
2. Browse the target application normally
3. Open the **Source Code Analyser** tab — findings appear in real time

### Quick Smoke Test

Paste this into your proxied browser to verify it is working:

```
data:text/html,<script>eval("1+1"); var x = 1;</script>
```

You should immediately see two findings:
- **eval() Usage** — Medium
- **var Declaration (Function-Scoped)** — Informational

---

## What It Detects (75 rules across 17 categories)

| Category | Count | Rules |
|---|:---:|---|
| API / Secret Keys | 4 | Hardcoded API Key, AWS Access Key, Generic Secret / Password, Private Key Material |
| Dangerous JS Sinks | 7 | eval(), document.write(), innerHTML, outerHTML, setTimeout with string, location.href, postMessage without origin check |
| Sensitive Data | 3 | Credit Card Number, Email Address Exposure, Internal IP Address |
| Insecure Storage | 2 | Sensitive data in localStorage, Sensitive data in sessionStorage |
| Debug / Dev Artifacts | 4 | console.log() in production, Exposed source map, TODO/FIXME comments, Commented-out secrets |
| Type Safety | 4 | Loose equality (==), var declarations, Implicit globals, Missing 'use strict' |
| Dangerous Functions | 6 | Function() constructor, execScript(), escape()/unescape(), with() statement, arguments.callee, delete on variable |
| Error Handling | 4 | Empty catch block, Log-only catch, Unhandled Promise, throw non-Error |
| Async / Concurrency | 2 | Synchronous XHR, await inside loop |
| DOM / Browser Pitfalls | 6 | javascript: URI, target=_blank without noopener, iframe without sandbox, External script without SRI, document.domain, window.name |
| JSONP | 1 | Unvalidated callback parameter |
| Injection Patterns | 5 | SQL concatenation, NoSQL operators, Shell command injection, Path traversal, ReDoS via dynamic RegExp |
| Code Quality | 10 | parseInt without radix, for…in on array, switch without default, Nested ternary, new Array/Object(), Octal literal, Chained assignment, Mutable export, Native prototype extension |
| Network / Fetch | 3 | fetch to HTTP, Disabled TLS verification, postMessage to wildcard origin |
| Cookies | 3 | Missing HttpOnly, Secure, SameSite flags |
| HTML Best Practices | 7 | Missing charset/viewport meta, Deprecated tags, CSRF-less POST forms, Missing CSP, img without alt, Exposed library version |
| Node.js | 4 | Hardcoded DB connection string, process.env secret fallback, Dynamic require(), JSON.stringify of sensitive object |

---

## Severity Levels

| Colour | Level | Meaning |
|---|---|---|
| Red | **High** | Exploit likely — fix immediately |
| Orange | **Medium** | Significant risk — investigate promptly |
| Blue | **Low** | Low risk / information disclosure |
| Grey | **Informational** | Best-practice concern — review recommended |

---

## Burp Scanner Integration

Findings are registered as passive scanner issues and appear in:
- **Target → Site map → Issues** panel
- **Scan reports** (HTML / XML export)
- The **Issues** count in the Target tab

Each Burp issue includes all occurrences with line numbers and context blocks in
the Issue Detail field, visible in the standard Burp issue viewer.


---

## Notes

- The extension is **passive only** — it never sends additional requests to the target.
- Deduplication is per `(URL, rule-name)` pair — each issue appears once per page.
- Tested with Burp Suite Community and Professional 2020–2024 and Jython 2.7.3.

