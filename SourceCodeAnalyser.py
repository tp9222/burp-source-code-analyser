# -*- coding: utf-8 -*-
# ============================================================
#  Burp Suite Extension -- Source Code Security Analyzer
#  Author  : Tejas N Pingulkar
#  Install : Extender -> Extensions -> Add -> Python -> select this file
# ============================================================

from burp import IBurpExtender, IScannerCheck, ITab, IScanIssue
from javax.swing import (
    JPanel, JScrollPane, JTable, JLabel, JTextField,
    JSplitPane, JTextArea, BorderFactory, JComboBox,
    JButton, SwingConstants, JTabbedPane, Box, BoxLayout
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import (
    BorderLayout, Color, Font, Dimension, FlowLayout, GridBagLayout,
    GridBagConstraints, Insets
)
from java.awt.event import ActionListener
from java.lang import Runnable
from javax.swing import SwingUtilities
import threading
from javax.swing.event import ListSelectionListener
from java.util import ArrayList
import re
import json
import traceback

# -- ANSI-free severity colours ------------------------------
SEVERITY_COLOR = {
    "High":           Color(220, 53,  69),
    "Medium":         Color(255, 153,  0),
    "Low":            Color( 23, 162, 184),
    "Informational":  Color(108, 117, 125),
}

# ------------------------------------------------------------
#  RULE DEFINITIONS
#  Each rule is a dict:
#   name, severity, confidence, pattern (regex), description, remediation
# ------------------------------------------------------------
RULES = [
    # -- API / Secret Keys ----------------------------------
    {
        "name": "Hardcoded API Key",
        "severity": "High",
        "confidence": "Firm",
        "pattern": r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?',
        "description": (
            "WHY INSECURE: An API key embedded directly in client-side source code is visible to every "
            "user who opens the browser DevTools or views the page source. Attackers can extract the key "
            "in seconds and make unlimited authenticated API calls under your identity -- incurring costs, "
            "leaking data, or performing destructive actions (deleting resources, sending emails, etc.). "
            "Client-side code is NOT confidential; treat anything in it as publicly known."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Never place API keys in HTML, JS, or any file served to a browser. "
            "Instead: (1) Store the key in a server-side environment variable (e.g. process.env.MAPS_KEY). "
            "(2) Create a thin server-side proxy endpoint that adds the key before forwarding the request. "
            "(3) If a key MUST reach the browser (e.g. Google Maps embed), restrict it by HTTP referrer "
            "and IP in the provider's console so it is useless if stolen."
        ),
        "applies_to": ["js", "html", "json"],
    },
    {
        "name": "AWS Access Key",
        "severity": "High",
        "confidence": "Certain",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "description": (
            "WHY INSECURE: AWS Access Key IDs beginning with 'AKIA' are long-term credentials that grant "
            "programmatic access to AWS services. If leaked in source code, an attacker gains full access "
            "to every AWS service permitted by the associated IAM policy -- S3 buckets, EC2 instances, "
            "Lambda functions, RDS databases, and more. Automated bots scan public repositories and Burp "
            "traffic specifically hunting for this pattern. Compromise can happen within minutes of "
            "the key appearing online."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Revoke the exposed key in the AWS IAM console immediately. "
            "(2) Audit CloudTrail logs for any unauthorized use since the key was created. "
            "(3) Use IAM Roles instead of long-term access keys wherever possible (EC2 instance roles, "
            "Lambda execution roles, ECS task roles). "
            "(4) For local development use AWS SSO or named profiles in ~/.aws/credentials (never committed). "
            "(5) Enable AWS Secrets Manager or Parameter Store for all remaining credential needs. "
            "(6) Enable GuardDuty to alert on credential abuse."
        ),
        "applies_to": ["js", "html", "json", "text"],
    },
    {
        "name": "Generic Secret / Password",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'(?i)(password|passwd|secret|token|auth_token|access_token)\s*[=:]\s*["\']([^"\']{6,})["\']',
        "description": (
            "WHY INSECURE: A variable or property named 'password', 'secret', or 'token' is assigned a "
            "string literal. Hardcoded credentials are permanently embedded in the codebase and in every "
            "deployment artifact (Docker image, build zip, CDN). They cannot be rotated without a code "
            "change and redeployment, and are typically committed to version control where they remain "
            "in git history forever even after deletion. If the credential is for a shared service "
            "(database, third-party API), every environment using the same codebase shares the same secret."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Remove the literal value from the source immediately. "
            "(2) Use environment variables (process.env.MY_SECRET) injected at deploy time. "
            "(3) Use a secrets manager such as HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, "
            "or GCP Secret Manager to retrieve credentials at runtime. "
            "(4) Scrub the old secret from git history using git-filter-repo or BFG Repo Cleaner, "
            "then rotate the credential since the history is still visible to anyone with a clone."
        ),
        "applies_to": ["js", "html", "json"],
    },
    {
        "name": "Private Key Material",
        "severity": "High",
        "confidence": "Certain",
        "pattern": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "description": (
            "WHY INSECURE: A PEM-encoded private key is present in a web-accessible file. Private keys "
            "are the most sensitive cryptographic material in a PKI system. Whoever holds a private key "
            "can: impersonate the server (breaking TLS), forge JWTs signed with that key, decrypt "
            "previously captured traffic (if the cipher lacks forward secrecy), or authenticate as the "
            "key owner to SSH servers. There is no partial compromise -- possession of the private key "
            "is equivalent to owning the identity it represents."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Treat the key as fully compromised -- revoke the corresponding "
            "certificate at your CA immediately. (2) Generate a new key pair in a secure location "
            "(HSM or a server that never touches source control). (3) Private keys must never be in "
            "web roots, source repositories, or client-facing responses. Store them in a secrets manager "
            "or on-disk with mode 600 outside the web root. (4) Audit access logs to determine if the "
            "key was already downloaded."
        ),
        "applies_to": ["js", "html", "text", "json"],
    },

    # -- Dangerous JS Sinks ---------------------------------
    {
        "name": "eval() Usage",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'\beval\s*\(',
        "description": (
            "WHY INSECURE: eval() compiles and executes an arbitrary JavaScript string at runtime in the "
            "current scope with full privileges. If any part of the string is derived from user input, "
            "URL parameters, postMessage data, or third-party content, an attacker can inject code that "
            "steals cookies, exfiltrates DOM content, makes authenticated requests, or installs a "
            "persistent XSS payload. eval() also defeats browser JIT optimisations, slowing execution. "
            "CSP 'unsafe-eval' must be enabled to permit it, which weakens your entire policy."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) For JSON data: use JSON.parse(). "
            "(2) For dynamic property access: use obj[propertyName] with a whitelist check. "
            "(3) For templating: use a proper template engine (Handlebars, Mustache). "
            "(4) For dynamic logic: refactor into a dispatch table (a plain object mapping keys to "
            "pre-defined functions). There is almost no legitimate use case for eval() in production code."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "document.write() Usage",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'\bdocument\.write\s*\(',
        "description": (
            "WHY INSECURE: document.write() inserts raw HTML directly into the document stream. If the "
            "argument contains any user-controlled data, an attacker can inject arbitrary HTML and script "
            "tags (XSS). Additionally, calling document.write() after the page has loaded completely "
            "erases the entire document. It blocks the HTML parser and is explicitly deprecated by the "
            "HTML Living Standard. Modern browsers already warn about or throttle it on slow connections."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use safe DOM APIs instead: "
            "element.textContent = data  (for plain text -- auto-escapes everything), "
            "element.appendChild(document.createTextNode(data))  (same effect), "
            "or element.insertAdjacentHTML('beforeend', sanitizedHtml)  (if HTML is needed, "
            "always sanitise with DOMPurify first). Never pass unsanitised data to any HTML-inserting API."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "innerHTML Assignment",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'\.innerHTML\s*=',
        "description": (
            "WHY INSECURE: Assigning to innerHTML parses the string as HTML and executes any embedded "
            "script content. It is the most common DOM-based XSS sink. Even 'harmless' injections like "
            "<img src=x onerror=alert(1)> execute JavaScript. The attack surface includes URL hash "
            "values, query parameters, localStorage values set by other pages, and postMessage data -- "
            "all of which can reach innerHTML without passing through the server."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "(1) For plain text: element.textContent = data  -- this NEVER executes scripts. "
            "(2) For trusted HTML from your own system: sanitise with DOMPurify before assignment: "
            "element.innerHTML = DOMPurify.sanitize(html). "
            "(3) Build DOM nodes programmatically with createElement / setAttribute / appendChild "
            "instead of concatenating HTML strings. "
            "(4) Use a framework (React, Vue, Angular) whose default output is escaped; avoid their "
            "escape-hatch APIs (dangerouslySetInnerHTML, v-html) unless strictly necessary."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "outerHTML Assignment",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'\.outerHTML\s*=',
        "description": (
            "WHY INSECURE: outerHTML replaces the entire element (including the element itself) with "
            "parsed HTML. This is the same XSS risk as innerHTML but also destroys the original element "
            "reference. Any user-controlled data flowing into outerHTML can inject and execute scripts. "
            "It is rarely needed in well-structured code, making its presence a red flag."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Replace the element using safe DOM methods: "
            "const newEl = document.createElement('div');  "
            "newEl.textContent = data;  "
            "el.parentNode.replaceChild(newEl, el);  "
            "If you need to replace with HTML structure, sanitise with DOMPurify first and use "
            "insertAdjacentHTML or a DOM builder."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "setTimeout / setInterval with String",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'set(Timeout|Interval)\s*\(\s*["\']',
        "description": (
            "WHY INSECURE: When the first argument to setTimeout() or setInterval() is a string, "
            "the JavaScript engine compiles and evaluates it exactly like eval(). This creates the "
            "same arbitrary code execution risk. The difference is that eval() is well-known and often "
            "blocked by linters and CSP, while the string-form of timers is a lesser-known equivalent "
            "that may bypass naive detection."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always pass a function reference, never a string: "
            "// BAD:  setTimeout('doSomething()', 1000); "
            "// GOOD: setTimeout(doSomething, 1000); "
            "// GOOD: setTimeout(function() { doSomething(); }, 1000); "
            "// GOOD: setTimeout(() => doSomething(), 1000); "
            "If you need to pass parameters, use a closure or bind(): "
            "setTimeout(doSomething.bind(null, arg), 1000);"
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "location.href Assignment",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'location\.href\s*=',
        "description": (
            "WHY INSECURE: Writing to location.href causes a browser navigation. If the value is derived "
            "from user input (URL parameters, form fields, postMessage) without validation, two attacks "
            "are possible: (1) Open Redirect -- attacker sends users to a phishing site via a trusted "
            "domain URL like example.com/redirect?to=evil.com. (2) javascript: URI injection -- "
            "setting location.href to 'javascript:alert(1)' executes arbitrary code in older browsers "
            "or contexts that do not block javascript: navigations."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Validate redirect targets against an explicit allowlist of safe paths. "
            "(2) Reject any value starting with 'javascript:', 'data:', or '//' that does not match your domain. "
            "(3) Use relative paths ('/dashboard') instead of absolute URLs wherever possible. "
            "(4) If the redirect target must come from user input, encode and validate it server-side "
            "before reflecting it back."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "postMessage Without Origin Check",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'addEventListener\s*\(\s*["\']message["\']',
        "description": (
            "WHY INSECURE: The window.postMessage API allows cross-origin communication. If a 'message' "
            "event listener processes the event data without checking event.origin, any page in the browser "
            "(opened as a popup, in an iframe, or navigated to by the user) can send forged messages. "
            "Attackers can craft a malicious page that posts data to trigger sensitive actions in your "
            "application -- changing user settings, initiating payments, or exfiltrating data."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always validate the sender's origin before acting on a message: "
            "window.addEventListener('message', function(event) { "
            "  if (event.origin !== 'https://trusted.example.com') return; "
            "  // now safe to process event.data "
            "}); "
            "Also validate and sanitise event.data before use -- do not assume a trusted origin "
            "means the data is safe (the trusted origin could itself be compromised)."
        ),
        "applies_to": ["js", "html"],
    },

    # -- Sensitive Data Patterns ----------------------------
    {
        "name": "Credit Card Number",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        "description": (
            "WHY INSECURE: A raw Primary Account Number (PAN) is present in the HTTP response. Under "
            "PCI-DSS, full card numbers must never be stored or transmitted in cleartext outside of a "
            "PCI-compliant tokenisation environment. Exposing them in a web response means any user, "
            "intermediary proxy, CDN, or network eavesdropper can capture the number. If this is "
            "test data, production environments must use different, non-real card numbers."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Never return full PANs to clients -- truncate to last 4 digits "
            "(e.g. **** **** **** 1234) for display. (2) Use a PCI-compliant payment processor "
            "(Stripe, Braintree) -- the card number never touches your server at all; the processor "
            "returns an opaque token. (3) If you must store card data, encrypt with AES-256 and store "
            "the key in an HSM, never in the application layer. (4) Run quarterly PCI-DSS scans."
        ),
        "applies_to": ["js", "html", "json", "text"],
    },
    {
        "name": "Email Address Exposure",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "description": (
            "WHY INSECURE: Email addresses in client-side responses are harvestable by automated scrapers "
            "and bots. Harvested emails are used for spam campaigns, credential stuffing (trying the email "
            "against known password breaches), phishing, and social engineering. Internal staff email "
            "addresses also reveal organisational structure and can be used for targeted spear-phishing."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Only return email addresses to authenticated users who have a "
            "legitimate need to see them. (2) For contact forms, use a server-side mail relay so the "
            "destination address never appears in the HTML. (3) If emails must be displayed, consider "
            "obfuscation (user [at] domain.com) or CSS-based tricks to deter scrapers -- though "
            "determined scrapers bypass these. The real fix is access control."
        ),
        "applies_to": ["js", "html", "json", "text"],
    },
    {
        "name": "Internal IP Address",
        "severity": "Low",
        "confidence": "Firm",
        "pattern": r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "description": (
            "WHY INSECURE: RFC-1918 private IP addresses in a public response reveal internal network "
            "topology. Attackers use this information to map your infrastructure, identify internal "
            "services, and pivot if they gain a foothold (e.g. via SSRF). It may also indicate that "
            "internal services are leaking through misconfigured reverse proxies, debug headers "
            "(X-Forwarded-For, X-Real-IP), or error messages."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Audit which component is injecting the internal IP (load balancer, "
            "app server, logging middleware) and strip it before the response leaves the internal network. "
            "(2) Configure reverse proxies to remove or replace internal IP headers. "
            "(3) Ensure error messages and stack traces are suppressed in production. "
            "(4) Use hostnames or service-mesh DNS names internally, not IPs, so accidental leakage "
            "reveals less context."
        ),
        "applies_to": ["js", "html", "json", "text"],
    },

    # -- Insecure Storage -----------------------------------
    {
        "name": "Sensitive Data in localStorage",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'localStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|password|secret|key|auth)[^"\']*["\']',
        "description": (
            "WHY INSECURE: localStorage is a persistent, synchronous key-value store accessible to ALL "
            "JavaScript running on the same origin -- including third-party analytics scripts, ad code, "
            "and browser extensions. If any XSS vulnerability exists anywhere on the origin, an attacker "
            "can read every localStorage value with a single line: localStorage.getItem('token'). "
            "Unlike HttpOnly cookies, there is no browser mechanism that prevents JS from reading "
            "localStorage. Data survives browser restarts, increasing the exposure window."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Store authentication tokens in HttpOnly, Secure, SameSite=Strict "
            "cookies set by the server. These cookies are automatically sent with requests and are "
            "completely inaccessible to JavaScript -- even if XSS occurs, the token cannot be stolen. "
            "If you cannot use cookies (e.g. a pure SPA calling a different-origin API), store the "
            "token only in a JavaScript variable (memory) so it is lost on page refresh, and use a "
            "short token lifetime with refresh tokens."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "Sensitive Data in sessionStorage",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'sessionStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|password|secret|key|auth)[^"\']*["\']',
        "description": (
            "WHY INSECURE: sessionStorage is cleared when the browser tab closes, making it slightly "
            "better than localStorage for token storage, but it shares the same fundamental weakness: "
            "it is fully readable by any JavaScript on the same origin. An XSS payload can still read "
            "sessionStorage.getItem('token') within the active session. Third-party scripts and browser "
            "extensions have equal access."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Same as localStorage -- prefer HttpOnly cookies for session tokens. "
            "If an in-memory approach is used (a module-scoped variable), ensure it is not accidentally "
            "exposed via window properties. For OAuth flows, the access token should live in memory and "
            "only the refresh token (if any) in a Secure HttpOnly cookie."
        ),
        "applies_to": ["js", "html"],
    },

    # -- Debug / Dev Artifacts ------------------------------
    {
        "name": "console.log() in Production",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'\bconsole\.(log|debug|info|warn|error)\s*\(',
        "description": (
            "WHY INSECURE: console.log statements left in production code can inadvertently print "
            "sensitive data to the browser console -- user objects, auth tokens, API responses, form "
            "values, or internal state. Any user can open DevTools and read the console. More critically, "
            "browser extensions and injected scripts can intercept and forward console output. "
            "Bulk logging also degrades performance on resource-constrained devices."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Use a build-time tool (Terser, UglifyJS, or a Babel plugin like "
            "babel-plugin-transform-remove-console) to strip all console calls in production builds. "
            "(2) Replace ad-hoc console.log with a structured logging library (e.g. loglevel, winston) "
            "that can be configured to suppress output below a threshold in production. "
            "(3) Add an ESLint rule (no-console) to prevent new console statements from being committed."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Exposed Source Map",
        "severity": "Low",
        "confidence": "Certain",
        "pattern": r'//[#@]\s*sourceMappingURL\s*=',
        "description": (
            "WHY INSECURE: A source map reference in a production JS file allows anyone to download "
            "your original, unminified source code -- including comments, variable names, business logic, "
            "algorithm implementations, and any secrets accidentally left in the code. Source maps turn "
            "minification from a security measure into a trivially bypassed inconvenience. Attackers "
            "specifically look for .map files to understand application internals for targeted attacks."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Disable source map generation entirely in production builds "
            "(set devtool: false in webpack, or sourceMap: false in other bundlers). "
            "(2) If source maps are needed for production error tracking (e.g. Sentry), generate them "
            "but do NOT deploy the .map files to the public web server -- upload them directly to your "
            "error tracking service. (3) Remove the sourceMappingURL comment from the minified output "
            "using a post-build script."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "TODO / FIXME Comment",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'(?i)//.*\b(todo|fixme|hack|xxx|bug)\b',
        "description": (
            "WHY INSECURE: Developer annotations like TODO, FIXME, HACK, and BUG in production code "
            "reveal incomplete security controls, known vulnerabilities, and workarounds. Examples seen "
            "in real applications: 'TODO: add auth check', 'FIXME: SQL injection possible here', "
            "'HACK: skip validation for now'. These comments provide a roadmap for attackers, "
            "directly identifying the weakest points in the application."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Resolve all security-relevant TODOs before deploying to production. "
            "(2) Track outstanding work in your issue tracker (Jira, GitHub Issues) rather than in "
            "source comments -- issue trackers are access-controlled, source code is not. "
            "(3) Add an ESLint rule or pre-commit hook (e.g. no-warning-comments) to prevent TODO "
            "comments from reaching the main branch. (4) At minimum, strip comments from minified "
            "output so they do not reach the browser."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "Commented-Out Code Block",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'(?s)/\*.*?(password|secret|token|key|credential).*?\*/',
        "description": (
            "WHY INSECURE: A block comment containing words like 'password', 'token', or 'key' suggests "
            "that sensitive logic or credential values were temporarily disabled rather than removed. "
            "Commented-out code is a common source of credential leaks -- developers disable a line "
            "containing a real password rather than deleting it. This code reaches the browser in "
            "unminified responses and is visible in DevTools."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Delete commented-out code -- it is preserved in version control if "
            "you ever need it back. Run a secrets scanner (truffleHog, git-secrets, detect-secrets) "
            "in CI to catch credentials in comments before they are committed. "
            "Minifiers strip comments in production, but the source is still exposed in development "
            "and staging environments."
        ),
        "applies_to": ["js", "html"],
    },

    # ======================================================
    #  WEAK CODING PRACTICES -- JavaScript
    # ======================================================

    # -- Type Safety ---------------------------------------
    {
        "name": "Loose Equality Operator (==)",
        "severity": "Low",
        "confidence": "Certain",
        "pattern": r'(?<![=!<>])==(?!=)',
        "description": (
            "WHY INSECURE: The loose equality operator (==) performs implicit type coercion before "
            "comparing, producing results that are deeply counterintuitive: 0 == '' is true, "
            "0 == '0' is true, '' == '0' is false, null == undefined is true, "
            "false == '0' is true. In security-sensitive comparisons (role checks, token validation, "
            "permission checks) a type-coercion bug can allow bypass: if (userRole == 0) might be "
            "true for both integer 0 and empty string '', granting access to unauthorised users."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always use strict equality (===) and strict inequality (!==). "
            "These compare both value AND type with no coercion. Enable the ESLint 'eqeqeq' rule "
            "to enforce this project-wide. The only valid use of == is checking for null/undefined "
            "simultaneously (x == null), but even then an explicit (x === null || x === undefined) "
            "is clearer."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "var Declaration (Function-Scoped)",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'\bvar\s+\w',
        "description": (
            "WHY INSECURE: Variables declared with 'var' are function-scoped and hoisted to the top of "
            "their enclosing function, meaning they exist before the line that declares them. This "
            "causes subtle bugs: loop variables leak out of for blocks, variables are accessible before "
            "assignment (returning undefined), and accidental redeclarations silently succeed. In "
            "security code (authentication, validation) these surprises can create exploitable logic "
            "errors. 'var' in global scope also pollutes the window object."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use 'const' for values that do not change (the majority of variables) "
            "and 'let' for values that are reassigned. Both are block-scoped, not hoisted in the "
            "same way, and cannot be redeclared in the same scope. Adopt the ESLint 'no-var' rule. "
            "Prefer const by default -- it signals intent and prevents accidental mutation."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Implicit Global Variable",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'(?<![.\w])(?<!var\s)(?<!let\s)(?<!const\s)(?<!function\s)(?<!\()([a-z_$][a-zA-Z0-9_$]{2,})\s*=\s*(?!.*(?:var|let|const|function))',
        "description": (
            "WHY INSECURE: Assigning to an undeclared variable in non-strict JavaScript creates a "
            "property on the global 'window' object. This pollutes the global namespace, can overwrite "
            "existing globals (including built-in browser APIs), and makes the variable readable and "
            "writable by any other script on the page. Attackers who can run any JavaScript "
            "(via XSS) can tamper with your implicit globals to subvert application logic."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Add 'use strict'; at the top of every script -- strict mode turns "
            "implicit global assignment into a ReferenceError, catching these bugs immediately. "
            "(2) Always declare variables with const or let before use. "
            "(3) Use ES modules, which are strict by default. "
            "(4) Enable the ESLint 'no-undef' rule."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Missing 'use strict'",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'^(?![\s\S]*["\']use strict["\'])',
        "description": (
            "WHY INSECURE: Without strict mode, JavaScript silently swallows many error conditions that "
            "indicate security-relevant bugs: implicit globals (assignment to undeclared variables), "
            "duplicate parameter names, writing to read-only properties, using 'with' statements, "
            "and using octal literals. Strict mode turns these silent failures into thrown errors, "
            "making bugs visible during development before they become production vulnerabilities."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add 'use strict'; as the very first statement in each script file "
            "or function. Better still, use ES modules (import/export syntax) which are always in "
            "strict mode automatically. Modern bundlers (webpack, Rollup, esbuild) operating on "
            "ES modules enforce strict mode throughout the bundle."
        ),
        "applies_to": ["js"],
    },

    # -- Dangerous Functions --------------------------------
    {
        "name": "Function() Constructor (Dynamic Code)",
        "severity": "High",
        "confidence": "Firm",
        "pattern": r'\bnew\s+Function\s*\(',
        "description": (
            "WHY INSECURE: The Function() constructor creates a new function from a string of code at "
            "runtime, exactly like eval(). The key difference is that it creates a new scope (not "
            "closure over local variables), which makes it slightly less dangerous than eval() but "
            "equally capable of executing arbitrary injected code. If the string argument contains "
            "any user-supplied data, it is a direct code injection vector. CSP unsafe-eval blocks it."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Refactor to eliminate runtime code generation. Use a dispatch table "
            "or strategy pattern instead: const actions = { 'greet': (name) => 'Hello ' + name }; "
            "actions[userInput]?.(arg);  -- this restricts execution to pre-defined functions only. "
            "If you genuinely need a scripting engine for user-defined logic, use a sandboxed "
            "interpreter (e.g. vm2, isolated-vm) rather than eval or Function()."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "execScript() Usage",
        "severity": "High",
        "confidence": "Certain",
        "pattern": r'\bexecScript\s*\(',
        "description": (
            "WHY INSECURE: execScript() is a non-standard Internet Explorer method that evaluates "
            "a string as VBScript or JScript, equivalent to eval(). It has been removed from all "
            "modern browsers but its presence suggests very old code that may have other security "
            "issues. Any code path that reaches execScript() with user-controlled data is a direct "
            "arbitrary code execution vulnerability."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Remove execScript() entirely -- it does not work in any modern "
            "browser. Rewrite the affected functionality using modern JavaScript APIs. If the goal "
            "was dynamic code execution, use a dispatch table or proper plugin architecture instead."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Deprecated escape() / unescape()",
        "severity": "Low",
        "confidence": "Certain",
        "pattern": r'\b(escape|unescape)\s*\(',
        "description": (
            "WHY INSECURE: The escape() and unescape() functions are deprecated since ES3 (1999). "
            "They handle non-ASCII characters incorrectly -- they encode each UTF-16 code unit "
            "separately, producing double-encoding for characters outside BMP. They do NOT encode "
            "+, @, *, and / which can cause issues in URL parameters. Using them for URL encoding "
            "is a bug, not just a style issue, and can lead to double-encoding or incomplete "
            "encoding allowing injection."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "For URL components: encodeURIComponent() / decodeURIComponent() "
            "(encodes everything except A-Z a-z 0-9 - _ . ! ~ * ' ( ) ). "
            "For full URLs: encodeURI() / decodeURI() "
            "(preserves URL structure characters like / ? # = &). "
            "For HTML: use textContent or a sanitiser -- do not escape HTML manually."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "with() Statement",
        "severity": "Medium",
        "confidence": "Certain",
        "pattern": r'\bwith\s*\(',
        "description": (
            "WHY INSECURE: The 'with' statement extends the scope chain with an object, making every "
            "property of that object visible as a local variable. This makes it impossible to determine "
            "at parse time which identifier refers to which variable -- a property added to the object "
            "at runtime can silently shadow a local variable, changing program behaviour. In security "
            "contexts, this can allow attacker-controlled objects to redirect property lookups to "
            "malicious values. 'with' is forbidden in strict mode."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Assign the target object to a short local variable: "
            "// BAD:  with (obj) { doSomething(x); } "
            "// GOOD: const x = obj.x; doSomething(x); "
            "This makes all variable references explicit and verifiable. "
            "Enable strict mode which will throw a SyntaxError if 'with' is used."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "arguments.callee Usage",
        "severity": "Low",
        "confidence": "Certain",
        "pattern": r'\barguments\.callee\b',
        "description": (
            "WHY INSECURE: arguments.callee refers to the currently executing function. It is "
            "disallowed in strict mode because it prevents V8 and other engines from inlining and "
            "optimising functions. More importantly, its presence in code often signals that the "
            "code pre-dates ES5 and may have other deprecated patterns. It is a SyntaxError in "
            "strict mode."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use a named function expression so the function can reference "
            "itself directly: "
            "// BAD:  var factorial = function(n) { return n <= 1 ? 1 : n * arguments.callee(n-1); }; "
            "// GOOD: var factorial = function fact(n) { return n <= 1 ? 1 : n * fact(n-1); }; "
            "The name 'fact' is only in scope inside the function, so it does not pollute outer scope."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "delete on Variable",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'\bdelete\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*;',
        "description": (
            "WHY INSECURE: Using 'delete' on a plain variable identifier (not an object property) "
            "silently returns false in non-strict mode and throws a SyntaxError in strict mode. "
            "Developers who write 'delete sensitiveVar' believing they are clearing the variable "
            "are mistaken -- the variable still exists and retains its value. This creates a false "
            "sense of security when trying to clear credentials from memory."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: To 'clear' a variable, assign null or undefined: sensitiveVar = null; "
            "To remove a property from an object: delete obj.sensitiveProperty; (correct usage). "
            "Note that for true in-memory secret clearing in JS there is no reliable mechanism -- "
            "the GC controls memory. For cryptographic keys, use the Web Crypto API which handles "
            "key material in non-extractable CryptoKey objects."
        ),
        "applies_to": ["js"],
    },

    # -- Error Handling ------------------------------------
    {
        "name": "Empty catch Block",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'catch\s*\([^)]*\)\s*\{\s*\}',
        "description": (
            "WHY INSECURE: An empty catch block silently discards all exceptions. In security-critical "
            "code this is extremely dangerous: authentication failures, authorisation denials, "
            "signature verification errors, and decryption failures are all thrown as exceptions. "
            "If the catch is empty, the code continues as if nothing went wrong -- potentially "
            "granting access, skipping validation, or using corrupted data. This is sometimes "
            "called the 'Pokemon exception handler' (gotta catch 'em all)."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always handle exceptions explicitly: "
            "try { verifySignature(token); } "
            "catch(err) { "
            "  logger.error('Signature verification failed', { error: err.message }); "
            "  return res.status(401).json({ error: 'Unauthorised' }); "
            "} "
            "At minimum, log the error with context. For security operations, a caught error "
            "should almost always result in a denial, not silent continuation."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "catch Block Only Logs Error",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'catch\s*\([^)]*\)\s*\{\s*console\.(log|warn|error)\s*\(',
        "description": (
            "WHY INSECURE: A catch block that only calls console.log may be logging and then falling "
            "through -- allowing code execution to continue past a failed operation. If the failed "
            "operation was a security check (token validation, permission check, payment processing), "
            "the application silently proceeds in an error state. Production logging via console is "
            "also insufficient -- it is not persistent, not monitored, and may expose error details "
            "to end users via DevTools."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: After logging, either re-throw the error, return an error response, "
            "or take an explicit recovery action. Use a structured logging library rather than "
            "console.log. Distinguish between errors that are recoverable (try an alternative path) "
            "and those that should abort the operation (auth failures must always abort)."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Unhandled Promise (.catch() Missing)",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'\.then\s*\([^)]+\)\s*(?!\.catch)',
        "description": (
            "WHY INSECURE: A Promise chain without a .catch() handler will produce an unhandled "
            "rejection. In Node.js, unhandled rejections can crash the process (since Node 15). "
            "In browsers, they are silently swallowed unless a global handler is registered. "
            "If the rejected operation was security-critical (login, payment, authorisation check), "
            "the application will proceed without knowing the operation failed, potentially "
            "allowing access it should have denied."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "(1) Append .catch(err => { /* handle */ }) to every Promise chain. "
            "(2) Prefer async/await with try/catch which makes control flow explicit: "
            "try { const result = await secureOperation(); } "
            "catch(err) { return handleError(err); } "
            "(3) Register a global fallback: process.on('unhandledRejection', handler) in Node.js, "
            "window.addEventListener('unhandledrejection', handler) in browsers -- but this is a "
            "last resort, not a substitute for per-operation handling."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "throw Non-Error Object",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'\bthrow\s+(?!new\s+\w*Error)["\'\d{]',
        "description": (
            "WHY INSECURE: Throwing a non-Error value (a string, number, or plain object) means the "
            "thrown value has no .stack property. Without a stack trace, debugging security incidents "
            "becomes significantly harder -- you cannot determine what code path caused the error or "
            "how control reached the throwing statement. Error monitoring systems (Sentry, Datadog) "
            "also expect Error instances and may not capture non-Error throws correctly."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always throw Error instances or subclasses: "
            "throw new Error('description');  // basic "
            "throw new TypeError('expected string, got ' + typeof x);  // specific "
            "class AuthError extends Error { constructor(msg) { super(msg); this.name='AuthError'; } } "
            "throw new AuthError('token expired');  // domain-specific "
            "This ensures .stack, .message, and .name are always available for debugging."
        ),
        "applies_to": ["js"],
    },

    # -- Async / Concurrency --------------------------------
    {
        "name": "Synchronous XMLHttpRequest",
        "severity": "High",
        "confidence": "Certain",
        "pattern": r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*[^,]+,\s*false\s*\)',
        "description": (
            "WHY INSECURE: Passing false as the third argument to xhr.open() makes the request "
            "synchronous, blocking the main thread until the server responds. This freezes the "
            "entire browser tab -- the UI is unresponsive, animations stop, and the user cannot "
            "interact with the page. On slow connections or slow servers this can last seconds. "
            "Browsers are actively deprecating sync XHR (already blocked in service workers and "
            "on the main thread in some contexts) and will eventually remove it entirely."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use asynchronous XHR (third argument = true) with callbacks, "
            "or better, use the Fetch API with async/await: "
            "const response = await fetch(url, { method: 'POST', body: data }); "
            "const result = await response.json(); "
            "This never blocks the main thread and is the modern standard for HTTP requests in browsers."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "await Inside Loop",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'for\s*\([^)]*\)\s*\{[^}]*\bawait\b',
        "description": (
            "WHY INSECURE: Using 'await' inside a for/for-of loop serialises all iterations -- each "
            "iteration waits for the previous one to complete before starting. For N operations, total "
            "time is the sum of all individual times rather than the maximum. This causes performance "
            "degradation that can make applications appear hung or trigger timeouts, which can be "
            "abused as a denial-of-service vector if the loop count is attacker-controlled."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Run independent async operations concurrently with Promise.all(): "
            "// BAD:  for (const id of ids) { await fetchUser(id); } "
            "// GOOD: await Promise.all(ids.map(id => fetchUser(id))); "
            "If the loop count is large or unbounded, add a concurrency limit using p-limit or "
            "similar to avoid overwhelming the server or running out of memory."
        ),
        "applies_to": ["js"],
    },

    # -- DOM / Browser Pitfalls ----------------------------
    {
        "name": "javascript: URI in href/src",
        "severity": "High",
        "confidence": "Certain",
        "pattern": r'(?i)(href|src|action)\s*=\s*["\']javascript\s*:',
        "description": (
            "WHY INSECURE: A 'javascript:' URI in an href, src, or form action executes arbitrary "
            "JavaScript when the user clicks the link, loads the resource, or submits the form. "
            "This is a classic XSS vector -- if the URI value is stored in a database and reflected "
            "in the page, an attacker can store a javascript: payload that executes in every "
            "visitor's browser. Modern CSP policies should block javascript: navigations, but "
            "not all applications have a strong CSP."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Never use javascript: URIs in HTML. Attach behaviour via event "
            "listeners in JavaScript instead: "
            "// BAD:  <a href=\"javascript:doSomething()\">Click</a> "
            "// GOOD: <a href=\"#\" id=\"myLink\">Click</a> "
            "          document.getElementById('myLink').addEventListener('click', doSomething); "
            "For form actions, always use a proper URL or a submit event handler."
        ),
        "applies_to": ["html", "js"],
    },
    {
        "name": "target=_blank Without rel=noopener",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'target\s*=\s*["\']_blank["\'](?![^>]*rel\s*=\s*["\'][^"\']*noopener)',
        "description": (
            "WHY INSECURE: Links with target='_blank' open a new tab. Without rel='noopener', the "
            "opened page gains a reference to the opener via window.opener and can navigate the "
            "original tab to a different URL -- a technique called reverse tabnapping. An attacker "
            "who controls the linked page (or injects a link to a malicious page) can redirect your "
            "users to a phishing page that appears to be your site. Modern browsers have partially "
            "mitigated this but older browsers are still vulnerable."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always add rel=\"noopener noreferrer\" to target='_blank' links: "
            "<a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\"> "
            "'noopener' prevents window.opener access. "
            "'noreferrer' additionally hides the Referer header (privacy benefit). "
            "Configure your linter or HTML validator to flag target='_blank' without these attributes."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "iframe Without sandbox Attribute",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'<iframe(?![^>]*sandbox)[^>]*>',
        "description": (
            "WHY INSECURE: An iframe without a 'sandbox' attribute grants the embedded content full "
            "browser privileges: it can run scripts, access cookies from the parent page's origin "
            "(if same-origin), submit forms, trigger top-level navigation, and open popups. "
            "If the embedded content is user-controlled, third-party, or potentially compromised, "
            "it can perform actions as if it were your page. Unsandboxed iframes are a common "
            "privilege escalation vector."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add the sandbox attribute and grant only the minimum permissions needed: "
            "<iframe src=\"...\" sandbox=\"allow-scripts allow-same-origin\"> "
            "Available tokens: allow-scripts, allow-same-origin, allow-forms, allow-popups, "
            "allow-top-navigation, allow-downloads. "
            "Start with an empty sandbox (no tokens) which disables everything, then add only "
            "what the embedded content genuinely requires."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "External Script Without SRI Hash",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'<script[^>]+src\s*=\s*["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'](?![^>]*integrity)',
        "description": (
            "WHY INSECURE: Loading a script from a CDN or third-party host without a Subresource "
            "Integrity (SRI) hash means you are trusting that the CDN will always serve the exact "
            "file you expect. CDNs can be compromised (supply-chain attack), misconfigured, or "
            "subject to BGP hijacking. An attacker who can serve a modified version of your "
            "third-party script can inject arbitrary code into every page of your application -- "
            "this is how the British Airways and Ticketmaster breaches worked."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Generate an SRI hash for each external resource and include it: "
            "<script src=\"https://cdn.example.com/lib.min.js\" "
            "  integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\" "
            "  crossorigin=\"anonymous\"></script> "
            "Generate hashes at: https://www.srihash.org/ or via: "
            "openssl dgst -sha384 -binary lib.min.js | openssl base64 -A"
        ),
        "applies_to": ["html"],
    },
    {
        "name": "document.domain Manipulation",
        "severity": "Medium",
        "confidence": "Certain",
        "pattern": r'\bdocument\.domain\s*=',
        "description": (
            "WHY INSECURE: Setting document.domain relaxes the same-origin policy by allowing "
            "sub-domains to share DOM access. For example, if both app.example.com and "
            "api.example.com set document.domain = 'example.com', they can access each other's "
            "DOMs. This greatly expands the attack surface -- a XSS on any sub-domain can now "
            "access the DOM of all other sub-domains that opted in. document.domain assignment "
            "is deprecated and will be blocked in future browser versions."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use window.postMessage() for cross-frame/cross-window "
            "communication between sub-domains. It provides controlled, message-based "
            "communication without relaxing the same-origin policy: "
            "// sender: frame.contentWindow.postMessage(data, 'https://api.example.com'); "
            "// receiver: validate event.origin, then process event.data"
        ),
        "applies_to": ["js"],
    },
    {
        "name": "window.name Data Storage",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'\bwindow\.name\s*=',
        "description": (
            "WHY INSECURE: window.name persists across page navigations within the same browser tab, "
            "even across different origins. If your page stores sensitive data in window.name and "
            "then navigates to or opens a third-party page, that third-party page can read "
            "window.name and steal your data. This is a less obvious data leakage channel that "
            "bypasses many security controls."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use sessionStorage for tab-scoped data that should not persist "
            "across navigations, or use postMessage for cross-frame communication. "
            "If window.name was used as a historical cross-domain communication hack, replace it "
            "with the postMessage API which is both safer and standardised."
        ),
        "applies_to": ["js"],
    },

    # -- JSONP / Callback Injection -------------------------
    {
        "name": "JSONP Callback Pattern",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'[?&]callback\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*',
        "description": (
            "WHY INSECURE: JSONP (JSON with Padding) works by injecting a <script> tag that calls "
            "a server-generated function wrapping the data. The 'callback' parameter controls the "
            "function name. If the server reflects the callback name without strict validation, "
            "an attacker can inject arbitrary JavaScript as the callback: "
            "callback=alert(document.cookie)// -- executing code in the victim's browser context. "
            "JSONP also bypasses CORS, leaking cross-origin data to any script that can make "
            "a GET request."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Migrate from JSONP to proper CORS-enabled JSON APIs: "
            "(1) Add appropriate Access-Control-Allow-Origin headers on the API server. "
            "(2) Use fetch() with CORS instead of JSONP script injection. "
            "If JSONP cannot be replaced immediately, strictly whitelist callback names against "
            "a regex like /^[a-zA-Z_][a-zA-Z0-9_]*$/ with a maximum length of 50 characters, "
            "and return a 400 error for any non-matching value."
        ),
        "applies_to": ["js", "html"],
    },

    # -- Injection Patterns --------------------------------
    {
        "name": "SQL Query String Concatenation",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["\'\s]+\s*\+',
        "description": (
            "WHY INSECURE: Building SQL queries by concatenating strings with user input is the "
            "classic SQL injection vulnerability (OWASP #1 for many years). An attacker who controls "
            "any part of the concatenated string can inject additional SQL syntax: "
            "' OR '1'='1 to bypass authentication, "
            "'; DROP TABLE users; -- to destroy data, "
            "' UNION SELECT password FROM users -- to exfiltrate data. "
            "SQL injection can lead to complete database compromise, data theft, authentication bypass, "
            "and in some configurations, OS command execution."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use parameterised queries (prepared statements) exclusively: "
            "// BAD:  db.query('SELECT * FROM users WHERE id = ' + userId); "
            "// GOOD: db.query('SELECT * FROM users WHERE id = ?', [userId]); "
            "With parameterised queries, user data is NEVER interpreted as SQL syntax -- it is "
            "always treated as a literal value. Use an ORM (Sequelize, TypeORM, Prisma) which "
            "uses parameterised queries by default. Never use string format/template literals "
            "to build SQL."
        ),
        "applies_to": ["js", "html"],
    },
    {
        "name": "NoSQL Injection Pattern",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'(?i)\$where\s*:|\.find\s*\(\s*\{[^}]*\$',
        "description": (
            "WHY INSECURE: MongoDB and similar NoSQL databases support operator keywords prefixed "
            "with $ (e.g. $where, $gt, $regex, $or). If user-supplied JSON is passed directly "
            "into a query without validation, an attacker can inject these operators: "
            "sending {\"password\": {\"$gt\": \"\"}} as the login password matches any non-empty "
            "password, bypassing authentication. $where executes arbitrary JavaScript server-side. "
            "NoSQL injection is less well-known than SQL injection but equally dangerous."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Never pass raw user input as a query object. "
            "(2) Explicitly extract and cast each expected field: "
            "const query = { username: String(req.body.username), password: String(req.body.password) }; "
            "(3) Use a schema validation library (Joi, Zod, Yup) to reject objects containing "
            "unexpected keys or $ operators before they reach the database layer. "
            "(4) Avoid $where entirely -- use the aggregation pipeline or indexed fields instead."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Shell Command Execution (Node.js)",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'(?i)(exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[^,)]*\+',
        "description": (
            "WHY INSECURE: Building shell commands by string concatenation and passing them to "
            "child_process.exec() or similar functions is OS command injection. An attacker who "
            "controls any part of the command string can inject shell metacharacters (;, |, &&, "
            "backticks, $()) to execute arbitrary commands on the server: list files, read "
            "credentials, download malware, or exfiltrate data. Unlike SQL injection, this runs "
            "with the full privileges of the Node.js process user."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use execFile() or spawn() with a fixed command and separate "
            "argument array -- these NEVER invoke a shell, so metacharacters are treated as literals: "
            "// BAD:  exec('convert ' + userFilename + ' output.png'); "
            "// GOOD: execFile('convert', [userFilename, 'output.png']); "
            "Validate and sanitise all inputs before they reach any exec call. "
            "If a shell is truly needed, use shell-quote to safely escape arguments."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Path Traversal Pattern",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'(?i)(readFile|createReadStream|sendFile|res\.download)\s*\([^)]*\+',
        "description": (
            "WHY INSECURE: Building file paths by concatenating user input allows path traversal "
            "attacks. An attacker submits '../../../etc/passwd' or similar sequences to break out "
            "of the intended directory and read arbitrary files on the filesystem -- private keys, "
            "configuration files containing database credentials, /etc/shadow, or application "
            "source code. This can lead to full server compromise."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "(1) Use path.basename() to strip directory components from user input. "
            "(2) Use path.resolve() to construct the final path, then verify it starts with "
            "the allowed base directory: "
            "const safePath = path.resolve(BASE_DIR, path.basename(userInput)); "
            "if (!safePath.startsWith(BASE_DIR)) return res.status(403).send('Forbidden'); "
            "(3) Use an allowlist of permitted filenames rather than deriving paths from input. "
            "(4) Serve user files through an abstraction layer, never directly from the filesystem."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Regex Denial of Service (ReDoS) Pattern",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'new\s+RegExp\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*',
        "description": (
            "WHY INSECURE: Constructing a RegExp from a variable means the pattern is not known at "
            "code review time. If the variable is user-controlled, an attacker can supply a "
            "catastrophically backtracking pattern (e.g. (a+)+ applied to 'aaaaab') that causes "
            "the regex engine to run for seconds or minutes on a short input -- a Denial of Service "
            "attack (ReDoS). Even without malicious patterns, dynamic regex construction with "
            "user data requires metacharacter escaping, which is frequently forgotten."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Use literal regex patterns /pattern/ wherever possible. "
            "(2) If a dynamic pattern is unavoidable, escape user input with a function like "
            "escapeRegExp: str.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&'). "
            "(3) Use a safe regex library (re2 for Node.js) which guarantees linear time execution "
            "and cannot be DoS'd. (4) Validate and limit the length of user inputs before "
            "constructing any regex from them."
        ),
        "applies_to": ["js"],
    },

    # -- Code Quality --------------------------------------
    {
        "name": "parseInt Without Radix",
        "severity": "Low",
        "confidence": "Certain",
        "pattern": r'\bparseInt\s*\(\s*[^,)]+\)',
        "description": (
            "WHY INSECURE: parseInt() without a radix argument infers the base from the string "
            "prefix. In ES5 and older engines, strings starting with '0' were treated as octal "
            "(base 8): parseInt('010') === 8. This is a well-known source of subtle bugs in "
            "number parsing -- file permission bits, date components, and port numbers can all "
            "start with 0. Even in modern engines where octal inference was removed for most "
            "cases, the intent of the code is ambiguous without an explicit radix."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always pass the radix as the second argument: "
            "parseInt('010', 10) === 10  (decimal) "
            "parseInt('0xff', 16) === 255  (hex) "
            "parseInt('010', 8) === 8  (explicit octal) "
            "Alternatively, use Number() for decimal conversion of non-integer strings, "
            "or the unary + operator (+str) which always uses decimal."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "for...in Loop on Array",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'for\s*\(\s*(var|let|const)\s+\w+\s+in\s+\w+\s*\)',
        "description": (
            "WHY INSECURE: The for...in loop iterates over ALL enumerable properties of an object, "
            "including inherited prototype properties. When used on an array, it also iterates over "
            "any properties added to Array.prototype by libraries (a common source of bugs when "
            "using older libraries or polyfills). The iteration order is not guaranteed to be "
            "numeric index order. Processing array elements in the wrong order or including "
            "prototype properties can produce incorrect results in security-sensitive data processing."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: For arrays, use: "
            "for...of loop:  for (const item of arr) { ... }  (iterates values in order) "
            "arr.forEach((item, i) => { ... })  (functional style) "
            "Classic for loop:  for (let i = 0; i < arr.length; i++) { ... } "
            "Reserve for...in for plain objects where you want to enumerate own properties, "
            "and add a hasOwnProperty check: if (obj.hasOwnProperty(key)) { ... }"
        ),
        "applies_to": ["js"],
    },
    {
        "name": "switch Without default Case",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'switch\s*\([^)]+\)\s*\{(?:[^{}]|\{[^{}]*\})*\}(?![\s\S]*\bdefault\b)',
        "description": (
            "WHY INSECURE: A switch statement without a default case silently ignores any value "
            "not matched by a case. In access control logic (switch on userRole or action), "
            "an unexpected value falls through without action -- potentially granting access "
            "or skipping a security check. Attackers who can influence the switch value may "
            "be able to reach an 'unhandled' state that the developer never considered."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always add a default case that either handles unexpected values "
            "explicitly or throws an error to make the unexpected state visible: "
            "default: throw new Error('Unexpected role: ' + role); "
            "or:  default: return res.status(403).send('Forbidden'); "
            "For security decisions, the safe default is always denial, not permission."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Nested Ternary Expression",
        "severity": "Informational",
        "confidence": "Firm",
        "pattern": r'\?[^:?{}()[\]]+\?[^:?{}()[\]]+:',
        "description": (
            "WHY INSECURE: Nested ternary expressions are extremely difficult to read correctly. "
            "The associativity rules mean that a ? b : c ? d : e groups as a ? b : (c ? d : e), "
            "which is often not what the developer intended. In permission checks or validation "
            "logic, a misread ternary can invert a condition, allowing access that should be denied "
            "or denying access that should be allowed. Code review is less effective on hard-to-read "
            "expressions."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Refactor nested ternaries into explicit if/else blocks or "
            "intermediate variables that make the logic clear: "
            "const isAdmin = role === 'admin'; "
            "const canEdit = isAdmin || role === 'editor'; "
            "const result = canEdit ? 'edit' : 'read-only'; "
            "Clear logic is reviewable logic -- security relies on code that is obviously correct."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "new Array() Instead of Literal",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'\bnew\s+Array\s*\(',
        "description": (
            "WHY INSECURE: new Array(n) has a confusing dual behaviour: with a single numeric "
            "argument it creates a sparse array of length n (empty slots, not undefined values), "
            "while with multiple arguments it creates an array of those values. This inconsistency "
            "causes bugs when the argument count is dynamic. Sparse arrays behave differently from "
            "dense arrays in many operations (forEach skips holes, JSON.stringify converts holes "
            "to null), leading to unexpected data processing results."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use array literals: const arr = [];  or  const arr = [a, b, c]; "
            "To create a pre-filled array of N elements: Array.from({ length: n }, () => value); "
            "or  new Array(n).fill(value); (explicit about filling). "
            "To create an array from arguments: Array.of(a, b, c)  (always creates element array)."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "new Object() Instead of Literal",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'\bnew\s+Object\s*\(\s*\)',
        "description": (
            "WHY INSECURE: new Object() can be shadowed or overridden if the Object identifier "
            "has been reassigned (possible in adversarial environments or via prototype pollution). "
            "Object literals {} are a primitive syntax construct that cannot be intercepted. "
            "new Object() is also more verbose and slower than {} in most engines."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use object literals: const obj = {};  or  const obj = { key: value }; "
            "For creating objects with a specific prototype: Object.create(proto); "
            "For objects with no prototype (safer for use as a map/dictionary, not vulnerable to "
            "prototype pollution): Object.create(null);"
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Octal Literal",
        "severity": "Low",
        "confidence": "Firm",
        "pattern": r'\b0[0-7]{1,10}\b',
        "description": (
            "WHY INSECURE: Legacy octal literals (0755, 0644) look like decimal numbers to anyone "
            "unfamiliar with the convention, causing integer values to be misread. 0755 octal = 493 "
            "decimal, not 755. In file permission settings (common in Node.js fs.chmod calls) this "
            "is particularly dangerous: developers who write 0755 expecting decimal permissions will "
            "set completely different permissions than intended, potentially making files world-writable "
            "or inaccessible. Octal literals are a SyntaxError in strict mode."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use ES6 explicit octal notation (0o prefix) which is unambiguous: "
            "0o755  (octal 755, decimal 493 -- typical executable permission) "
            "0o644  (octal 644, decimal 420 -- typical file permission) "
            "Or use decimal values directly if that is what you intend. "
            "Enable strict mode which makes legacy octal literals a SyntaxError."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Chained Assignment",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'\w+\s*=\s*\w+\s*=\s*(?!=)',
        "description": (
            "WHY INSECURE: Chained assignments like a = b = value work by evaluating right-to-left. "
            "If 'b' is not declared with let/const/var, it becomes an implicit global (in non-strict "
            "mode). For example: let x = y = 0 declares x locally but makes y global. "
            "This is a common accidental global creation pattern that many developers are unaware of. "
            "Global variables are attackable by other scripts on the page."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Declare each variable explicitly on its own line: "
            "const a = 0; "
            "const b = 0; "
            "This makes scope and declaration intent unambiguous. Use strict mode to turn "
            "accidental globals into ReferenceErrors."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Mutable Export (let/var export)",
        "severity": "Low",
        "confidence": "Firm",
        "pattern": r'\bexport\s+(let|var)\s+',
        "description": (
            "WHY INSECURE: Exporting a 'let' or 'var' binding creates a live binding -- importers "
            "see changes to the variable. This means the module's state can change unexpectedly "
            "from the importer's perspective, and if any code path can reassign the exported variable, "
            "it could replace a security-relevant value (e.g. a configuration flag, a singleton "
            "service instance) with a different value, creating hard-to-detect state tampering."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Export const values or export functions/classes. "
            "If state must be mutable, encapsulate it: "
            "// BAD:  export let isAuthenticated = false; "
            "// GOOD: export const auth = { isAuthenticated: false, login() { this.isAuthenticated = true; } }; "
            "This makes mutation explicit and traceable."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Prototype Extension of Native Object",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'(?:Array|Object|String|Number|Function|Boolean)\.prototype\.\w+\s*=',
        "description": (
            "WHY INSECURE: Adding properties to built-in prototypes (Array.prototype, Object.prototype) "
            "pollutes all instances of that type throughout the entire page -- including instances "
            "created by third-party libraries. This can break libraries that use for...in on arrays "
            "or objects, cause unexpected method availability, and create name collisions with future "
            "JavaScript standard methods. It is a vector for library-to-library interference and "
            "can be exploited as part of a prototype pollution attack chain."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "(1) Use utility functions: const doubled = myDouble(arr) instead of arr.myDouble(). "
            "(2) Use subclasses: class SafeArray extends Array { myDouble() { ... } } "
            "(3) Use Symbol-keyed properties if you must add to a prototype: "
            "const myMethod = Symbol('myMethod'); Array.prototype[myMethod] = function() { ... }; "
            "(this won't clash with string-keyed properties or future standards)."
        ),
        "applies_to": ["js"],
    },

    # -- Network / Fetch -----------------------------------
    {
        "name": "Fetch to HTTP Endpoint",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'fetch\s*\(\s*["\']http://',
        "description": (
            "WHY INSECURE: An HTTP (unencrypted) fetch() call transmits request and response data "
            "in plaintext over the network. Any network intermediary -- a coffee shop router, a "
            "corporate proxy, a malicious ISP -- can read the data (eavesdropping) or modify it "
            "(man-in-the-middle). If the request contains auth tokens, personal data, or any "
            "sensitive content, it is fully exposed. Modern browsers also block mixed content "
            "(HTTP requests from HTTPS pages) and will refuse this request."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Use HTTPS exclusively for all network requests: "
            "fetch('https://api.example.com/data')  -- TLS encrypts the entire connection. "
            "Enable HTTP Strict Transport Security (HSTS) on your server to prevent downgrade attacks: "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload "
            "Add your domain to the HSTS preload list at https://hstspreload.org/"
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Disabled SSL/TLS Verification",
        "severity": "High",
        "confidence": "Firm",
        "pattern": r'(?i)(rejectUnauthorized|verify)\s*[=:]\s*false',
        "description": (
            "WHY INSECURE: Setting rejectUnauthorized: false (Node.js) or verify=False (Python) "
            "disables all TLS certificate validation. The connection is encrypted but the identity "
            "of the server is NOT verified -- anyone can present any certificate and the client "
            "will accept it. This makes the connection trivially vulnerable to man-in-the-middle "
            "attack: an attacker intercepts the connection, presents a self-signed certificate, "
            "and reads or modifies all traffic. This is commonly added as a 'quick fix' for "
            "certificate errors and then forgotten in production."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Fix the underlying certificate issue instead of disabling verification: "
            "(1) Use a certificate from a trusted CA (Let's Encrypt is free). "
            "(2) For internal services, create a private CA and add its certificate to the trust store. "
            "(3) For development with self-signed certs, set the NODE_EXTRA_CA_CERTS env var to "
            "point to your CA cert file rather than disabling verification globally. "
            "Never disable TLS verification in production under any circumstances."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "postMessage to Wildcard Origin",
        "severity": "Medium",
        "confidence": "Certain",
        "pattern": r'\.postMessage\s*\([^,]+,\s*["\']?\*["\']?\s*\)',
        "description": (
            "WHY INSECURE: Calling postMessage(data, '*') sends the message to ALL windows "
            "regardless of their origin. If the data contains sensitive information (auth tokens, "
            "user data, application state), any page that has a reference to your window -- an "
            "embedded iframe, a popup you opened, or a page that opened yours -- can receive and "
            "read the message. The wildcard origin is intended only for public, non-sensitive data."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always specify the exact target origin: "
            "// BAD:  window.postMessage(sensitiveData, '*'); "
            "// GOOD: window.postMessage(sensitiveData, 'https://trusted.example.com'); "
            "The browser will only deliver the message if the recipient window's origin matches "
            "exactly. Use '*' only for data that you would be comfortable sending to any website."
        ),
        "applies_to": ["js"],
    },

    # -- Cookies & Storage --------------------------------
    {
        "name": "Cookie Without HttpOnly Flag",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'(?i)document\.cookie\s*=(?!.*\bhttponly\b)',
        "description": (
            "WHY INSECURE: A cookie set without the HttpOnly flag is accessible to JavaScript via "
            "document.cookie. This means that any XSS vulnerability anywhere on your site can "
            "immediately steal all non-HttpOnly cookies -- including session tokens, CSRF tokens, "
            "and user identifiers. The stolen cookies can be sent to an attacker's server and used "
            "to impersonate the victim. HttpOnly is a simple, zero-cost defence that completely "
            "prevents this specific theft vector."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Set session and authentication cookies server-side with the "
            "HttpOnly flag: "
            "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict "
            "HttpOnly cookies are never accessible to JavaScript -- not even your own code can "
            "read them via document.cookie. The browser handles sending them automatically "
            "with every same-origin request. If a cookie genuinely needs to be readable by JS "
            "(e.g. a user preference), it can omit HttpOnly, but never use this for tokens."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Cookie Without Secure Flag",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'(?i)document\.cookie\s*=(?!.*\bsecure\b)',
        "description": (
            "WHY INSECURE: A cookie without the Secure flag will be sent by the browser over both "
            "HTTP and HTTPS connections. If a user visits an HTTP version of your site (by typing "
            "the URL without https://, following an old link, or through a downgrade attack), the "
            "session cookie is transmitted in plaintext and can be intercepted by network attackers. "
            "This is particularly dangerous on public Wi-Fi networks."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add the Secure flag to all sensitive cookies: "
            "Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict "
            "The Secure flag instructs the browser to never send the cookie over an unencrypted "
            "connection. Combine with HSTS to prevent the browser from ever making HTTP requests "
            "to your domain in the first place."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "Cookie Without SameSite Attribute",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'(?i)document\.cookie\s*=(?!.*\bsamesite\b)',
        "description": (
            "WHY INSECURE: Without the SameSite attribute, cookies are sent with all cross-site "
            "requests -- including those triggered by a malicious third-party website. This enables "
            "Cross-Site Request Forgery (CSRF): an attacker's page makes a request to your API "
            "(e.g. transfer money, change email, delete account) and the browser automatically "
            "includes the victim's session cookie, authenticating the forged request. Modern "
            "browsers default to SameSite=Lax, but explicit configuration is more reliable "
            "and supports older browsers."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: "
            "SameSite=Strict: cookie is NEVER sent with cross-site requests (best security, "
            "may break some OAuth/SAML flows that redirect back to your site). "
            "SameSite=Lax: cookie is sent with safe top-level navigations (GET) but not with "
            "POST, iframe, or AJAX cross-site requests (good balance, browser default). "
            "SameSite=None; Secure: required for legitimate cross-site cookies (e.g. embedded "
            "widgets) -- must be combined with Secure flag."
        ),
        "applies_to": ["js"],
    },

    # -- HTML Best Practices -------------------------------
    {
        "name": "Missing meta charset Declaration",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'<html[^>]*>(?![\s\S]*<meta[^>]*charset)',
        "description": (
            "WHY INSECURE: Without an explicit charset declaration, the browser uses encoding "
            "sniffing to detect the page's character encoding. Attackers can craft specific byte "
            "sequences that cause the browser to misdetect the encoding (e.g. as UTF-7 or other "
            "extended encodings), which can allow XSS bypasses that would be blocked in UTF-8. "
            "The charset declaration must appear within the first 1024 bytes of the document."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add <meta charset=\"UTF-8\"> as the very first element inside "
            "<head>, before any other content including the <title>: "
            "<head><meta charset=\"UTF-8\"><title>My Page</title>...</head> "
            "Always serve HTML with Content-Type: text/html; charset=UTF-8 in the HTTP response "
            "header as well -- the HTTP header takes precedence over the meta tag."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Missing Viewport Meta Tag",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'<html[^>]*>(?![\s\S]*<meta[^>]*name=["\']viewport["\'])',
        "description": (
            "WHY INSECURE: Without a viewport meta tag, mobile browsers render the page at desktop "
            "width and then scale it down, making text tiny and touch targets too small. Users "
            "on mobile may be unable to read security warnings, consent notices, or interact "
            "accurately with security-sensitive UI elements (accept/deny buttons). Poor mobile "
            "UX also drives users to unofficial apps or workarounds that may not be secure."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add the standard viewport meta tag inside <head>: "
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> "
            "This ensures the page renders at the device's native width. Avoid "
            "user-scalable=no or maximum-scale=1 as these prevent users with accessibility "
            "needs from zooming in."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Deprecated HTML Tags",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'(?i)<\s*(font|center|marquee|blink|strike|tt|big|basefont|applet)\b',
        "description": (
            "WHY INSECURE: Deprecated presentational HTML tags (<font>, <center>, <marquee>, "
            "<applet>, etc.) were removed from the HTML Living Standard because they conflate "
            "content with presentation, are inconsistently implemented, and in the case of "
            "<applet> represent a severe security risk (Java applets are a historical major "
            "attack vector). Their presence indicates very old, unmaintained code that is "
            "likely to have other security issues."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Replace presentational tags with semantic HTML and CSS: "
            "<font color='red'> --> <span style='color: red'> or a CSS class "
            "<center> --> <div style='text-align: center'> or CSS "
            "<marquee> --> CSS animation "
            "<applet> --> Remove entirely; Java applets are dead and dangerous. "
            "Use semantic elements (<header>, <nav>, <main>, <article>, <section>) for structure."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Form Without CSRF Token",
        "severity": "Medium",
        "confidence": "Tentative",
        "pattern": r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>(?![\s\S]*?(?:csrf|_token|authenticity_token))',
        "description": (
            "WHY INSECURE: A POST form without a CSRF token can be submitted from any website "
            "using a hidden form and JavaScript: an attacker's page silently submits the form "
            "to your server, and the victim's browser automatically includes their session cookie. "
            "The server cannot distinguish the legitimate user's submission from the forged one. "
            "CSRF attacks can change passwords, transfer money, delete accounts, or perform "
            "any action the authenticated user could perform."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Include a CSRF token (a random, secret, session-tied value) "
            "as a hidden field in every state-changing form: "
            "<input type='hidden' name='_csrf' value='{{ csrfToken }}'> "
            "(2) Validate the token server-side on every POST/PUT/PATCH/DELETE request. "
            "(3) Use the SameSite=Strict cookie attribute as a complementary defence. "
            "(4) Most frameworks (Express+csurf, Django, Rails, Laravel) provide CSRF middleware "
            "out of the box -- use it."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Absence of Content-Security-Policy",
        "severity": "Low",
        "confidence": "Tentative",
        "pattern": r'<head[^>]*>(?![\s\S]*Content-Security-Policy)',
        "description": (
            "WHY INSECURE: Without a Content-Security-Policy (CSP), the browser allows scripts, "
            "styles, and resources to be loaded from any origin. An XSS attack that injects a "
            "<script src='https://evil.com/payload.js'> tag will execute freely. CSP is a "
            "second layer of defence -- even if XSS is achieved, CSP can prevent script "
            "execution or data exfiltration if properly configured. Without it, XSS attacks "
            "have unrestricted impact."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Deploy CSP via an HTTP header (preferred) or meta tag: "
            "Content-Security-Policy: default-src 'self'; script-src 'self'; "
            "  style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "  connect-src 'self'; frame-ancestors 'none'; "
            "Start with Content-Security-Policy-Report-Only to audit violations without "
            "breaking the page. Use a CSP evaluator (csp-evaluator.withgoogle.com) to "
            "check your policy strength. Eliminate 'unsafe-inline' and 'unsafe-eval' "
            "for maximum protection."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Image Without alt Attribute",
        "severity": "Informational",
        "confidence": "Certain",
        "pattern": r'<img(?![^>]*\balt\s*=)[^>]*>',
        "description": (
            "WHY INSECURE: Missing alt attributes on images violate WCAG 2.1 accessibility "
            "guidelines (Criterion 1.1.1 -- Non-text Content). Screen readers announce images "
            "without alt as the full filename or URL, which is confusing or meaningless to "
            "visually impaired users. Beyond accessibility, failing WCAG compliance can expose "
            "organisations to legal liability in many jurisdictions (ADA in the US, EN 301 549 "
            "in the EU, Equality Act in the UK)."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Add descriptive alt text to all meaningful images: "
            "<img src='login-icon.png' alt='Login'> "
            "For purely decorative images that add no information, use an empty alt attribute "
            "to tell screen readers to skip it: "
            "<img src='decorative-border.png' alt=''> "
            "Never use the filename or 'image' as the alt value."
        ),
        "applies_to": ["html"],
    },
    {
        "name": "Exposed Version Number in Script src",
        "severity": "Low",
        "confidence": "Firm",
        "pattern": r'<script[^>]+src=["\'][^"\']*[-._](\d+\.\d+[\d.]*)[^"\']*["\']',
        "description": (
            "WHY INSECURE: Version numbers in script src attributes reveal exactly which library "
            "version is deployed. Attackers can look up known CVEs for that specific version in "
            "NVD (nvd.nist.gov) or Snyk and immediately target known, unpatched vulnerabilities. "
            "This reduces the attacker's reconnaissance time from hours to seconds. "
            "Even if the library is up to date, version exposure helps attackers track when "
            "you fall behind on updates."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Bundle and serve third-party libraries from your own domain "
            "without version numbers in the path. (2) Use integrity hashes (SRI) instead of "
            "version numbers to verify file content. (3) Enable security headers (X-Frame-Options, "
            "CSP) that reduce the exploitability of library vulnerabilities. "
            "(4) Subscribe to security advisories for all dependencies and update promptly."
        ),
        "applies_to": ["html"],
    },

    # -- Node.js / Server-Side JS --------------------------
    {
        "name": "Hardcoded Database Connection String",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'(?i)(mongodb|mysql|postgres|redis|mssql):\/\/[^@\s"\']+:[^@\s"\']+@',
        "description": (
            "WHY INSECURE: A database URL containing a username and password is present in the "
            "source code. This credential grants direct access to your database, bypassing all "
            "application-layer access controls. Anyone who can read the source (including all "
            "developers, CI/CD systems, and anyone with access to the code repository) has the "
            "database password. If the repository is ever made public (accidentally or by breach), "
            "the database is immediately compromised."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: (1) Move the connection string to an environment variable: "
            "const client = new MongoClient(process.env.MONGODB_URI); "
            "(2) Use a secrets manager (AWS Secrets Manager, Vault) to inject credentials at "
            "runtime without storing them anywhere in the codebase or environment. "
            "(3) Purge the credential from git history (git-filter-repo). "
            "(4) Rotate the database password immediately. "
            "(5) Use short-lived, role-based database credentials via IAM authentication "
            "where supported."
        ),
        "applies_to": ["js", "json"],
    },
    {
        "name": "process.env Fallback to Plaintext Secret",
        "severity": "Medium",
        "confidence": "Firm",
        "pattern": r'process\.env\.\w+\s*\|\|\s*["\'][^"\']{6,}["\']',
        "description": (
            "WHY INSECURE: Using process.env.SECRET || 'hardcoded-fallback' defeats the entire "
            "purpose of externalising secrets. The hardcoded fallback will be used in any "
            "environment where the env var is not set -- including developer machines, CI "
            "pipelines, staging environments, or a misconfigured production deployment. "
            "The secret is still in the source code and still at risk from source code exposure."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Require the environment variable explicitly and fail loudly: "
            "const secret = process.env.MY_SECRET; "
            "if (!secret) throw new Error('MY_SECRET environment variable is not set'); "
            "This ensures the application will NOT start without the proper configuration, "
            "making misconfiguration immediately visible rather than silently insecure. "
            "Use a config validation library (convict, envalid) to validate all required "
            "env vars at startup."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "require() with Dynamic User Input",
        "severity": "High",
        "confidence": "Tentative",
        "pattern": r'\brequire\s*\(\s*[^"\'`][^)]*\)',
        "description": (
            "WHY INSECURE: Passing a variable to require() means the module path is determined "
            "at runtime. If any part of that path is derived from user input, an attacker can "
            "load arbitrary Node.js modules including built-in dangerous modules (child_process, "
            "fs) or traverse to sensitive files. Even without user control, dynamic require() "
            "prevents static analysis tools from identifying what is loaded and makes the "
            "dependency graph opaque."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Always use string literals in require(): "
            "const fs = require('fs');  // static, analysable "
            "If dynamic module loading is genuinely necessary (plugin architecture), use an "
            "explicit allowlist: "
            "const ALLOWED = ['plugin-a', 'plugin-b']; "
            "if (!ALLOWED.includes(name)) throw new Error('Unknown plugin'); "
            "const plugin = require('./plugins/' + name); "
            "This bounds the attack surface to known, vetted modules."
        ),
        "applies_to": ["js"],
    },
    {
        "name": "JSON.stringify of Circular or Sensitive Object",
        "severity": "Informational",
        "confidence": "Tentative",
        "pattern": r'JSON\.stringify\s*\(\s*(req|request|user|session|ctx)\b',
        "description": (
            "WHY INSECURE: Serialising entire request, user, or session objects can inadvertently "
            "include sensitive fields that were never intended for serialisation: password hashes, "
            "internal IDs, session secrets, database connection objects, or private keys. "
            "These may appear in API responses, logs, or error messages. Once logged, sensitive "
            "data is difficult to purge and may be shipped to third-party log aggregators."
        ),
        "remediation": (
            "SECURE ALTERNATIVE: Serialise only the specific, known-safe fields you need: "
            "// BAD:  JSON.stringify(user) -- includes passwordHash, salt, etc. "
            "// GOOD: JSON.stringify({ id: user.id, name: user.name, role: user.role }) "
            "Use a serialiser with an explicit allowlist or implement a toJSON() method on "
            "your model classes that returns only safe, public fields. "
            "For logging, use a log sanitiser that redacts fields matching patterns like "
            "'password', 'token', 'secret', 'key'."
        ),
        "applies_to": ["js"],
    },
]


# ------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------
# MAX body size to scan (bytes). Minified JS can be multi-MB; cap to keep regex fast.
MAX_BODY_BYTES   = 400 * 1024   # 400 KB
# Max occurrences stored per rule per URL
MAX_OCCURRENCES  = 25
# Max occurrences rendered in detail pane
MAX_DETAIL_OCCS  = 10


def _get_type_hint(response):
    """Return 'js', 'html', 'json', or 'text' based on Content-Type."""
    try:
        ct = ""
        for h in response.getHeaders():
            if "content-type" in str(h).lower():
                ct = str(h).lower()
                break
        if "javascript" in ct or "ecmascript" in ct:
            return "js"
        if "html" in ct:
            return "html"
        if "json" in ct:
            return "json"
        return "text"
    except Exception:
        return "text"


def _build_line_index(body):
    """
    Pre-compute start offsets of every line. O(n) once.
    All subsequent line-number lookups become O(log n).
    """
    try:
        starts = [0]
        idx = body.find('\n')
        while idx != -1:
            starts.append(idx + 1)
            idx = body.find('\n', idx + 1)
        return starts
    except Exception:
        return [0]


def _line_number_fast(line_starts, offset):
    """Binary-search line_starts to get the 1-based line number for offset."""
    try:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1
    except Exception:
        return 1


def _context_block_fast(lines, line_no, matched_text, context_lines=2):
    """
    Render a linter-style context block from the pre-split lines list.
    Does NOT re-split the body -- called once per match using shared list.
    """
    try:
        idx   = line_no - 1
        start = max(0, idx - context_lines)
        end   = min(len(lines), idx + context_lines + 1)
        out   = []
        for i in range(start, end):
            prefix = "{:>5} | ".format(i + 1)
            text   = lines[i]
            if len(text) > 200:          # truncate minified lines
                text = text[:197] + "..."
            out.append(prefix + text)
            if i == idx:
                col = lines[i].find(matched_text[:40])
                col = max(col, 0)
                out.append(" " * (len(prefix) + col) + "^" * min(len(matched_text), 50))
        return "\n".join(out)
    except Exception:
        return "  (context unavailable)"


def _all_matches_fast(pattern, body, line_starts, lines):
    """
    Find all occurrences using the pre-built index; cap at MAX_OCCURRENCES.
    context_str is built once here at scan time, never again in the UI thread.
    """
    seen_keys = set()
    results   = []
    try:
        for m in re.finditer(pattern, body):
            if len(results) >= MAX_OCCURRENCES:
                break
            matched_text = m.group(0)
            line_no      = _line_number_fast(line_starts, m.start())
            key = (line_no, matched_text[:60])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            results.append({
                "line_no":      line_no,
                "matched_text": matched_text,
                "context_str":  _context_block_fast(lines, line_no, matched_text),
            })
    except Exception:
        pass   # bad regex pattern -- skip silently
    return results


# ------------------------------------------------------------
#  Custom Scan Issue  (Burp Scanner integration)
# ------------------------------------------------------------
class SourceCodeIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, severity,
                 confidence, description, remediation, occurrences):
        self._httpService  = httpService
        self._url          = url
        self._httpMessages = httpMessages
        self._name         = "[SCA] " + name
        self._severity     = severity
        self._confidence   = confidence
        self._description  = description
        self._remediation  = remediation
        self._occurrences  = occurrences   # list of occurrence dicts

    def getUrl(self):           return self._url
    def getIssueName(self):     return self._name
    def getIssueType(self):     return 0x08000000
    def getSeverity(self):      return self._severity
    def getConfidence(self):    return self._confidence
    def getIssueBackground(self):      return self._description
    def getRemediationBackground(self): return self._remediation
    def getHttpMessages(self):  return self._httpMessages
    def getHttpService(self):   return self._httpService

    def getIssueDetail(self):
        try:
            parts = ["<b>Found {} occurrence(s)</b><br><br>".format(len(self._occurrences))]
            for i, occ in enumerate(self._occurrences[:5], 1):   # cap at 5 in Burp pane
                parts.append(
                    "<b>Occurrence {}  --  Line {}</b><br>"
                    "<b>Matched code:</b> <code>{}</code><br>"
                    "<pre>{}</pre><hr>".format(
                        i, occ["line_no"],
                        occ["matched_text"].replace("<", "&lt;").replace(">", "&gt;"),
                        occ["context_str"].replace("<", "&lt;").replace(">", "&gt;"),
                    )
                )
            return "".join(parts)
        except Exception:
            return "<b>Error rendering issue detail.</b>"

    def getRemediationDetail(self): return None


# ------------------------------------------------------------
#  Table model
# ------------------------------------------------------------
class IssueTableModel(DefaultTableModel):
    COLS = ["#", "Sev", "Conf", "Issue", "Line(s)", "What's Wrong", "URL"]

    def __init__(self):
        DefaultTableModel.__init__(self, self.COLS, 0)
        self._issues = []

    def getColumnCount(self):       return len(self.COLS)
    def getColumnName(self, i):     return self.COLS[i]
    def isCellEditable(self, r, c): return False

    def add_finding(self, finding):
        """finding = dict with all enriched data."""
        try:
            row_num = self.getRowCount() + 1
            # "Line(s)" column -- show first line, +N more if multiple
            occs = finding["occurrences"]
            if len(occs) == 1:
                lines_cell = "L{}".format(occs[0]["line_no"])
            else:
                lines_cell = "L{} (+{})".format(occs[0]["line_no"], len(occs) - 1)
            # "What's Wrong" column -- the exact bad token, trimmed
            bad_code = occs[0]["matched_text"].strip()
            if len(bad_code) > 60:
                bad_code = bad_code[:57] + "..."

            self.addRow([
                row_num,
                finding["severity"],
                finding["confidence"],
                finding["name"],
                lines_cell,
                bad_code,
                finding["url"],
            ])
            self._issues.append(finding)
            return row_num - 1
        except Exception:
            pass   # never crash the EDT on a bad finding dict

    def get_finding(self, row):
        if 0 <= row < len(self._issues):
            return self._issues[row]
        return None

    def clear(self):
        self._issues = []
        while self.getRowCount() > 0:
            self.removeRow(0)


# ------------------------------------------------------------
#  Cell renderers
# ------------------------------------------------------------
class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected,
                                      hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            fg = SEVERITY_COLOR.get(str(value), Color(0, 0, 0))
            c.setForeground(fg)
            c.setFont(c.getFont().deriveFont(Font.BOLD))
        return c


class BadCodeRenderer(DefaultTableCellRenderer):
    """Renders the 'What's Wrong' column in monospace red."""
    def getTableCellRendererComponent(self, table, value, isSelected,
                                      hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column)
        if not isSelected:
            c.setForeground(Color(180, 40, 40))
            c.setFont(Font("Consolas", Font.PLAIN, 11))
        return c


# ------------------------------------------------------------
#  Main UI Panel
# ------------------------------------------------------------
class SourceCodeAnalyzerTab(JPanel):
    def __init__(self, callbacks):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._total  = 0
        self._counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        self._all_data = []
        self._build_ui()

    # --------------------------------------------------------
    def _build_ui(self):
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(Color(245, 246, 250))

        # -- Header bar --------------------------------------
        header = JPanel(BorderLayout())
        header.setBackground(Color(22, 22, 35))
        header.setBorder(BorderFactory.createEmptyBorder(10, 16, 10, 16))

        title = JLabel("Source Code Analyzer")
        title.setFont(Font("Consolas", Font.BOLD, 17))
        title.setForeground(Color(0, 210, 150))
        header.add(title, BorderLayout.WEST)

        self._stat_lbl = JLabel("")
        self._stat_lbl.setFont(Font("Consolas", Font.PLAIN, 12))
        self._stat_lbl.setForeground(Color(180, 180, 180))
        header.add(self._stat_lbl, BorderLayout.EAST)
        self.add(header, BorderLayout.NORTH)

        # -- Filter / toolbar --------------------------------
        filter_bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))
        filter_bar.setBackground(Color(238, 240, 248))
        filter_bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(205, 207, 220)))

        filter_bar.add(JLabel("Severity:"))
        self._sev_filter = JComboBox(["All", "High", "Medium", "Low", "Informational"])
        self._sev_filter.addActionListener(FilterListener(self))
        filter_bar.add(self._sev_filter)

        filter_bar.add(JLabel("  Search:"))
        self._search_field = JTextField(22)
        filter_bar.add(self._search_field)

        apply_btn = JButton("Filter")
        apply_btn.addActionListener(FilterListener(self))
        filter_bar.add(apply_btn)

        clear_btn = JButton("Clear All")
        clear_btn.addActionListener(ClearListener(self))
        filter_bar.add(clear_btn)

        # -- Main vertical split  (table  |  detail) ---------
        v_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        v_split.setResizeWeight(0.45)
        v_split.setBorder(None)

        # -- Findings table -----------------------------------
        self._model = IssueTableModel()
        self._table = JTable(self._model)
        self._table.setRowHeight(22)
        self._table.setShowHorizontalLines(True)
        self._table.setGridColor(Color(220, 222, 232))
        self._table.getTableHeader().setFont(Font("Consolas", Font.BOLD, 12))
        self._table.setFont(Font("Consolas", Font.PLAIN, 12))
        self._table.setSelectionBackground(Color(60, 90, 160))
        self._table.setSelectionForeground(Color(255, 255, 255))

        col_widths = [35, 75, 75, 250, 75, 340, 280]
        for i, w in enumerate(col_widths):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._table.getColumnModel().getColumn(1).setCellRenderer(SeverityRenderer())
        self._table.getColumnModel().getColumn(5).setCellRenderer(BadCodeRenderer())

        self._table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self))
        v_split.setTopComponent(JScrollPane(self._table))

        # -- Detail panel (horizontal split inside) -----------
        h_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        h_split.setResizeWeight(0.55)
        h_split.setBorder(None)

        # LEFT: code view with all occurrences
        self._code_area = JTextArea()
        self._code_area.setEditable(False)
        self._code_area.setFont(Font("Consolas", Font.PLAIN, 12))
        self._code_area.setBackground(Color(18, 20, 30))
        self._code_area.setForeground(Color(220, 220, 220))
        self._code_area.setCaretColor(Color(220, 220, 220))
        code_scroll = JScrollPane(self._code_area)
        code_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(60, 60, 90)), "  Code -- What's Wrong"))
        h_split.setLeftComponent(code_scroll)

        # RIGHT: explanation panel
        self._info_area = JTextArea()
        self._info_area.setEditable(False)
        self._info_area.setFont(Font("Consolas", Font.PLAIN, 12))
        self._info_area.setLineWrap(True)
        self._info_area.setWrapStyleWord(True)
        self._info_area.setBackground(Color(248, 249, 252))
        self._info_area.setForeground(Color(30, 30, 50))
        info_scroll = JScrollPane(self._info_area)
        info_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(Color(200, 205, 220)), "  Issue Explanation & Fix"))
        h_split.setRightComponent(info_scroll)

        v_split.setBottomComponent(h_split)

        content = JPanel(BorderLayout())
        content.add(filter_bar, BorderLayout.NORTH)
        content.add(v_split, BorderLayout.CENTER)
        self.add(content, BorderLayout.CENTER)

    # -- Public API -------------------------------------------
    def add_finding(self, finding):
        """
        Called from the Burp scanner thread -- NEVER touch Swing directly here.
        All model/UI mutations are posted to the EDT via invokeLater.
        """
        tab = self
        class _Adder(Runnable):
            def run(self):
                try:
                    sev = finding["severity"]
                    tab._counts[sev] = tab._counts.get(sev, 0) + 1
                    tab._total += 1
                    tab._all_data.append(finding)
                    tab._model.add_finding(finding)
                    tab._update_stats()
                except Exception:
                    pass   # never crash the EDT
        SwingUtilities.invokeLater(_Adder())

    def show_detail(self, row_idx):
        """
        Called on the EDT (table selection).
        String building runs on a daemon thread; only the final setText()
        calls are posted back to the EDT, so the UI never freezes.
        """
        finding = self._model.get_finding(row_idx)
        if not finding:
            return

        # Snapshot everything we need -- safe to read on EDT
        occs        = list(finding.get("occurrences", []))
        total       = len(occs)
        name        = finding.get("name", "")
        url         = finding.get("url", "")
        severity    = finding.get("severity", "")
        confidence  = finding.get("confidence", "")
        description = finding.get("description", "")
        remediation = finding.get("remediation", "")
        bad_ex      = finding.get("bad_example", "")
        good_ex     = finding.get("good_example", "")
        refs        = finding.get("refs", ["See OWASP / CWE for details"])
        code_area   = self._code_area
        info_area   = self._info_area

        def _build_and_set():
            try:
                # ---- code pane ----
                shown = occs[:MAX_DETAIL_OCCS]
                code_lines = [
                    "=== {} -- {} occurrence{} {} ===".format(
                        name, total, "s" if total != 1 else "",
                        "(showing {})".format(len(shown)) if total > MAX_DETAIL_OCCS else ""),
                    "URL : {}".format(url),
                    "",
                ]
                for idx, occ in enumerate(shown, 1):
                    code_lines.append(
                        "-- Occurrence {}/{} -- Line {} ----".format(
                            idx, total, occ.get("line_no", "?")))
                    code_lines.append("")
                    code_lines.append("  Matched : {}".format(
                        occ.get("matched_text", "")[:200]))
                    code_lines.append("")
                    code_lines.append("  Context :")
                    code_lines.append(occ.get("context_str", ""))
                    code_lines.append("")
                if total > MAX_DETAIL_OCCS:
                    code_lines.append(
                        "  ... {} more occurrence(s) not shown.".format(
                            total - MAX_DETAIL_OCCS))
                code_text = "\n".join(code_lines)

                # ---- info pane ----
                sep_eq   = "=" * 60
                sep_dash = "-" * 60
                example_block = ""
                if bad_ex or good_ex:
                    example_block = (
                        "\n\n--- BAD (what was found) ---\n{}"
                        "\n\n--- GOOD (what to use instead) ---\n{}"
                    ).format(bad_ex, good_ex)

                info_text = (
                    "ISSUE\n{sep_eq}\n{name}\n\n"
                    "SEVERITY   : {severity}\n"
                    "CONFIDENCE : {confidence}\n"
                    "OCCURRENCES: {total}\n\n"
                    "WHAT IS WRONG\n{sep_dash}\n{description}"
                    "{example_block}\n\n"
                    "HOW TO FIX IT\n{sep_dash}\n{remediation}\n\n"
                    "REFERENCES\n{sep_dash}\n{refs}"
                ).format(
                    sep_eq=sep_eq, sep_dash=sep_dash,
                    name=name, severity=severity, confidence=confidence,
                    total=total, description=description,
                    example_block=example_block, remediation=remediation,
                    refs="\n".join(refs),
                )

                # Post back to EDT
                ct = code_text
                it = info_text
                class _Updater(Runnable):
                    def run(self):
                        try:
                            code_area.setText(ct)
                            code_area.setCaretPosition(0)
                            info_area.setText(it)
                            info_area.setCaretPosition(0)
                        except Exception:
                            pass   # never crash the EDT
                SwingUtilities.invokeLater(_Updater())

            except Exception:
                err_msg = traceback.format_exc()
                err_ct  = err_msg
                err_it  = "Error rendering detail:\n" + err_msg
                class _ErrUpdater(Runnable):
                    def run(self):
                        try:
                            code_area.setText(err_ct)
                            code_area.setCaretPosition(0)
                            info_area.setText(err_it)
                            info_area.setCaretPosition(0)
                        except Exception:
                            pass
                SwingUtilities.invokeLater(_ErrUpdater())

        t = threading.Thread(target=_build_and_set)
        t.setDaemon(True)
        t.start()

    def apply_filter(self):
        try:
            sev   = str(self._sev_filter.getSelectedItem())
            query = str(self._search_field.getText()).lower().strip()
            self._model.clear()
            for f in self._all_data:
                if sev != "All" and f["severity"] != sev:
                    continue
                if query:
                    haystack = (f["name"] + f["url"] + f["description"]).lower()
                    if query not in haystack:
                        continue
                self._model.add_finding(f)
        except Exception:
            pass   # filter errors must not clear findings

    def clear_all(self):
        try:
            self._all_data = []
            self._model.clear()
            self._total  = 0
            self._counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            self._code_area.setText("")
            self._info_area.setText("")
            self._update_stats()
        except Exception:
            pass

    def _update_stats(self):
        try:
            parts = []
            for sev in ("High", "Medium", "Low", "Informational"):
                n = self._counts.get(sev, 0)
                if n:
                    parts.append("{}:{}".format(sev[0], n))
            self._stat_lbl.setText(
                "Findings: {}   |   {}  ".format(self._total, "  ".join(parts)))
        except Exception:
            pass



# -- Listeners -----------------------------------------------
class FilterListener(ActionListener):
    def __init__(self, tab): self._tab = tab
    def actionPerformed(self, e):
        try:
            self._tab.apply_filter()
        except Exception:
            pass

class ClearListener(ActionListener):
    def __init__(self, tab): self._tab = tab
    def actionPerformed(self, e):
        try:
            self._tab.clear_all()
        except Exception:
            pass

class TableSelectionListener(ListSelectionListener):
    def __init__(self, tab): self._tab = tab
    def valueChanged(self, e):
        try:
            if not e.getValueIsAdjusting():
                row = self._tab._table.getSelectedRow()
                if row >= 0:
                    self._tab.show_detail(row)
        except Exception:
            pass   # never crash the EDT on selection events


# ------------------------------------------------------------
#  Reference map  (CWE / OWASP per rule name)
# ------------------------------------------------------------
RULE_REFS = {
    "eval() Usage":                    ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code", "OWASP A03:2021 - Injection"],
    "document.write() Usage":          ["CWE-79: XSS", "OWASP A03:2021 - Injection"],
    "innerHTML Assignment":            ["CWE-79: XSS", "OWASP A03:2021 - Injection"],
    "outerHTML Assignment":            ["CWE-79: XSS", "OWASP A03:2021 - Injection"],
    "Function() Constructor":          ["CWE-95: Dynamic Code Evaluation", "OWASP A03:2021 - Injection"],
    "execScript() Usage":              ["CWE-95", "OWASP A03:2021 - Injection"],
    "javascript: URI in href/src":     ["CWE-79: XSS", "OWASP A03:2021 - Injection"],
    "Hardcoded API Key":               ["CWE-798: Use of Hard-coded Credentials", "OWASP A07:2021 - Identification Failures"],
    "AWS Access Key":                  ["CWE-798", "OWASP A07:2021 - Identification Failures"],
    "Generic Secret / Password":       ["CWE-259: Hard-coded Password", "OWASP A07:2021"],
    "Private Key Material":            ["CWE-321: Use of Hard-coded Cryptographic Key"],
    "Hardcoded Database Connection":   ["CWE-798", "OWASP A07:2021"],
    "Disabled SSL/TLS Verification":   ["CWE-295: Improper Certificate Validation", "OWASP A02:2021 - Cryptographic Failures"],
    "Weak Hash Algorithm (MD5/SHA1)":  ["CWE-327: Use of Broken Algorithm", "OWASP A02:2021"],
    "Math.random() for Security":      ["CWE-338: Use of Cryptographically Weak PRNG"],
    "SQL Query String Concatenation":  ["CWE-89: SQL Injection", "OWASP A03:2021"],
    "NoSQL Injection Pattern":         ["CWE-943: NoSQL Injection", "OWASP A03:2021"],
    "Shell Command Execution":         ["CWE-78: OS Command Injection", "OWASP A03:2021"],
    "Path Traversal Pattern":          ["CWE-22: Path Traversal", "OWASP A01:2021"],
    "Regex Denial of Service":         ["CWE-400: Uncontrolled Resource Consumption"],
    "Prototype Pollution Sink":        ["CWE-1321: Prototype Pollution"],
    "Prototype Extension of Native":   ["CWE-1321"],
    "Wildcard CORS Origin":            ["CWE-942: Permissive Cross-domain Policy", "OWASP A05:2021"],
    "postMessage to Wildcard Origin":  ["CWE-942"],
    "postMessage Without Origin Check":["CWE-942"],
    "Sensitive Data in localStorage":  ["CWE-922: Insecure Storage of Sensitive Info", "OWASP A02:2021"],
    "Sensitive Data in sessionStorage":["CWE-922"],
    "Cookie Without HttpOnly Flag":    ["CWE-1004: Sensitive Cookie Without HttpOnly", "OWASP A05:2021"],
    "Cookie Without Secure Flag":      ["CWE-614: Sensitive Cookie over HTTP", "OWASP A02:2021"],
    "Cookie Without SameSite":         ["CWE-352: CSRF", "OWASP A01:2021"],
    "Form Without CSRF Token":         ["CWE-352: CSRF", "OWASP A01:2021"],
    "Synchronous XMLHttpRequest":      ["CWE-400: Uncontrolled Resource Consumption"],
    "External Script Without SRI":     ["CWE-829: Inclusion of Functionality from Untrusted Source"],
    "Exposed Source Map":              ["CWE-540: Information Exposure Through Source Code"],
    "target=_blank Without noopener":  ["CWE-1022: Open Redirect / Tab-napping"],
    "iframe Without sandbox":          ["CWE-693: Protection Mechanism Failure"],
    "Credit Card Number":              ["CWE-312: Cleartext Storage of Sensitive Info", "PCI-DSS Req. 3"],
    "Internal IP Address":             ["CWE-200: Information Exposure"],
    "Email Address Exposure":          ["CWE-200: Information Exposure"],
}

# ------------------------------------------------------------
#  Bad/Good code examples per rule
# ------------------------------------------------------------
RULE_EXAMPLES = {
    "eval() Usage": {
        "bad":  "eval(userInput);   // executes arbitrary code",
        "good": "JSON.parse(userInput);  // safe for data parsing",
    },
    "innerHTML Assignment": {
        "bad":  "element.innerHTML = userInput;",
        "good": "element.textContent = userInput;\n// or: element.innerHTML = DOMPurify.sanitize(userInput);",
    },
    "document.write() Usage": {
        "bad":  "document.write('<p>' + data + '</p>');",
        "good": "const p = document.createElement('p');\np.textContent = data;\ndocument.body.appendChild(p);",
    },
    "Loose Equality Operator (==)": {
        "bad":  "if (x == 0) { ... }   // 0 == '' == false == null",
        "good": "if (x === 0) { ... }  // strict -- no type coercion",
    },
    "var Declaration (Function-Scoped)": {
        "bad":  "var count = 0;  // function-scoped, hoisted",
        "good": "const count = 0;  // block-scoped, not hoisted",
    },
    "Empty catch Block": {
        "bad":  "try { riskyOp(); } catch(e) {}",
        "good": "try { riskyOp(); } catch(e) { console.error('riskyOp failed:', e); throw e; }",
    },
    "Hardcoded API Key": {
        "bad":  "const apiKey = 'AIzaSyAbcDef1234567890XYZ';",
        "good": "const apiKey = process.env.MAPS_API_KEY;  // server-side only",
    },
    "Disabled SSL/TLS Verification": {
        "bad":  "https.request({ rejectUnauthorized: false, ... })",
        "good": "// Fix the certificate; never disable verification in production",
    },
    "Synchronous XMLHttpRequest": {
        "bad":  "xhr.open('GET', url, false);  // 3rd arg = sync, blocks UI",
        "good": "xhr.open('GET', url, true);   // async\nxhr.onload = () => { ... };",
    },
    "target=_blank Without rel=noopener": {
        "bad":  '<a href="https://example.com" target="_blank">link</a>',
        "good": '<a href="https://example.com" target="_blank" rel="noopener noreferrer">link</a>',
    },
    "Cookie Without HttpOnly Flag": {
        "bad":  "document.cookie = 'session=abc123';",
        "good": "// Set server-side: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict",
    },
    "SQL Query String Concatenation": {
        "bad":  "db.query('SELECT * FROM users WHERE id = ' + userId);",
        "good": "db.query('SELECT * FROM users WHERE id = ?', [userId]);",
    },
    "parseInt Without Radix": {
        "bad":  "parseInt('010')  // might return 8 (octal) in old engines",
        "good": "parseInt('010', 10)  // always decimal -> 10",
    },
    "Math.random() for Security": {
        "bad":  "const token = Math.random().toString(36);",
        "good": "const arr = new Uint8Array(16);\nwindow.crypto.getRandomValues(arr);\nconst token = Array.from(arr, b => b.toString(16)).join('');",
    },
    "postMessage to Wildcard Origin": {
        "bad":  "window.postMessage(sensitiveData, '*');",
        "good": "window.postMessage(sensitiveData, 'https://trusted.example.com');",
    },
    "Form Without CSRF Token": {
        "bad":  '<form method="POST" action="/transfer">...</form>',
        "good": '<form method="POST" action="/transfer">\n  <input type="hidden" name="_csrf" value="{{ csrfToken }}">\n  ...\n</form>',
    },
    "External Script Without SRI Hash": {
        "bad":  '<script src="https://cdn.example.com/lib.js"></script>',
        "good": '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-<hash>"\n  crossorigin="anonymous"></script>',
    },
}


# ------------------------------------------------------------
#  Passive Scanner Check
# ------------------------------------------------------------
class SourceCodeScannerCheck(IScannerCheck):
    def __init__(self, callbacks, helpers, tab):
        self._callbacks = callbacks
        self._helpers   = helpers
        self._tab       = tab
        self._seen      = set()   # (url, rule_name) -- one Burp issue per pair

    def doPassiveScan(self, baseRequestResponse):
        try:
            response  = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
            type_hint = _get_type_hint(response)

            # ---- Decode body with size cap to keep regex fast ----
            raw = baseRequestResponse.getResponse()
            offset = response.getBodyOffset()
            body_bytes = raw[offset : offset + MAX_BODY_BYTES]
            try:
                body = body_bytes.tostring().decode("utf-8", errors="replace")
            except Exception:
                body = str(body_bytes)

            if not body.strip():
                return None

            url = str(self._helpers.analyzeRequest(baseRequestResponse).getUrl())

            # ---- Build line index ONCE for this body ----
            line_starts = _build_line_index(body)
            lines       = body.splitlines()

            burp_issues = []

            for rule in RULES:
                # Per-rule isolation: one bad rule never stops the rest
                try:
                    if type_hint not in rule["applies_to"]:
                        continue

                    key = (url, rule["name"])
                    if key in self._seen:
                        continue

                    # Use fast helpers -- index built once above
                    matches = _all_matches_fast(rule["pattern"], body, line_starts, lines)
                    if not matches:
                        continue

                    self._seen.add(key)

                    # context_str already built inside _all_matches_fast
                    occurrences = matches   # already the right shape

                    # Look up optional extras
                    ex   = RULE_EXAMPLES.get(rule["name"], {})
                    refs = RULE_REFS.get(rule["name"], [])

                    finding = {
                        "name":        rule["name"],
                        "severity":    rule["severity"],
                        "confidence":  rule["confidence"],
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                        "url":         url,
                        "occurrences": occurrences,
                        "bad_example": ex.get("bad",  ""),
                        "good_example":ex.get("good", ""),
                        "refs":        refs if refs else ["See OWASP Top 10 / CWE for details"],
                    }

                    # add_finding is thread-safe (posts to EDT via invokeLater)
                    self._tab.add_finding(finding)

                    # Build the Burp Scanner issue
                    burp_issues.append(SourceCodeIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse],
                        rule["name"],
                        rule["severity"],
                        rule["confidence"],
                        rule["description"],
                        rule["remediation"],
                        occurrences,
                    ))

                except Exception:
                    # Log the rule name so the developer knows which rule failed
                    self._callbacks.printError(
                        "[SCA] Rule '{}' error:\n{}".format(
                            rule.get("name", "unknown"), traceback.format_exc()
                        )
                    )
                    continue   # skip this rule, keep scanning with the rest

            return burp_issues if burp_issues else None

        except Exception:
            self._callbacks.printError(
                "[SCA] doPassiveScan fatal error:\n" + traceback.format_exc()
            )
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existing, newIssue):
        try:
            if existing.getIssueName() == newIssue.getIssueName() \
                    and str(existing.getUrl()) == str(newIssue.getUrl()):
                return -1
            return 0
        except Exception:
            return 0   # safe default: treat as non-duplicate


# ------------------------------------------------------------
#  Extension Entry Point
# ------------------------------------------------------------
class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        try:
            self._callbacks = callbacks
            self._helpers   = callbacks.getHelpers()

            callbacks.setExtensionName("Source Code Analyser")

            self._tab = SourceCodeAnalyzerTab(callbacks)

            self._scanner = SourceCodeScannerCheck(callbacks, self._helpers, self._tab)
            callbacks.registerScannerCheck(self._scanner)

            callbacks.addSuiteTab(self)

            callbacks.printOutput(
                "[SCA] Source Code Analyser loaded -- {} rules active.\n"
                "Browse any page to start scanning.".format(len(RULES))
            )
        except Exception:
            try:
                callbacks.printError(
                    "[SCA] Failed to load extension:\n" + traceback.format_exc()
                )
            except Exception:
                pass   # if even printError fails, nothing more we can do

    def getTabCaption(self):  return "Source Code Analyzer"
    def getUiComponent(self): return self._tab
