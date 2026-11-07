// Built-in rules. Deliberately small and honest: a pattern match is Tentative,
// and only a rule that traces input to the sink claims `dataflow`.
//
// A rule is data. Adding one never touches the engine, the controller or a skill.

/**
 * Expressions that introduce untrusted input (the taint sources of M1).
 *
 * The first alternative is Express. The next two are the Web `Request` that
 * Next.js, Hono, Remix and every edge runtime hand a route handler — scanning a
 * real Next.js application, nothing in it matched the Express shapes, so every
 * `taint: true` rule sat silent over a codebase full of request data.
 *
 * What is still out of reach: input that arrives as a function argument from
 * another module. No regular expression crosses a call boundary, and that is
 * recorded as a blind spot rather than implied by a zero.
 */
export const SOURCE_RE =
  /\b(?:req|request)\.(?:body|query|params|headers|cookies)\b|\b(?:req|request)\.(?:json|text|formData)\s*\(|\bsearchParams\s*\.\s*get\s*\(|\bformData\s*\.\s*get\s*\(|\bprocess\.argv\b|\bctx\.request\b/;

/**
 * A call to a model, in whichever SDK's vocabulary.
 *
 * Kept in one place and exported, because the engine needs to know whether it
 * recognised ANY model call in a repository that clearly makes them. Scanning a
 * real AI application — 169 files, eleven model calls through the Vercel AI SDK
 * — produced zero M14 findings and a ledger that said nothing, because every
 * shape here was an OpenAI or Google one. A blind spot reported as a clean
 * result is the exact failure this tool is built to refuse.
 *
 * Under-claim rather than over-claim: `.invoke(` would catch LangChain and half
 * the generic code in the world with it, so it is deliberately absent. A shape
 * we do not recognise becomes a line in the coverage ledger, which is the
 * honest outcome.
 */
export const MODEL_CALL =
  /\.(?:messages|chat\.completions|completions|responses)\s*\.\s*create\s*\(|\bgenerateContent\s*\(|\b(?:streamText|generateText|streamObject|generateObject)\s*\(/;

/** Importing one of these is the signal that a file talks to a model at all. */
export const MODEL_SDK_IMPORT =
  /(?:from\s*|require\s*\(\s*)['"](?:openai|ai|cohere-ai|ollama|groq-sdk|replicate|llamaindex|langchain|@anthropic-ai\/[\w.-]+|@google\/[\w.-]*gen[\w.-]*|@ai-sdk\/[\w.-]+|@langchain\/[\w.-]+|@mistralai\/[\w.-]+)['"]/;

const js = /\.(?:js|mjs|cjs|jsx|ts|tsx)$/i;
const cfg = /\.(?:json|ya?ml|env|ini|conf|toml)$|(?:^|\/)\.env/i;
const docker = /(?:^|\/)Dockerfile[^/]*$/i;

export const RULES = [
  {
    id: 'sql-injection',
    files: js,
    // a raw query whose argument interpolates or concatenates
    match: /\b(?:db|knex|conn|client|sequelize|pool)\s*\.\s*(?:raw|query|execute)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M1', 'M6', 'M8'],
    rule: {
      name: 'SQL injection',
      background:
        'User-controlled input reaches a SQL query without parameterization, so an attacker can change the shape of the query rather than only its values.',
      remediation:
        'Bind every user value as a parameter. Identifiers that cannot be bound (table and column names, sort direction) must come from an allowlist.',
      classification: { cwe: ['CWE-89'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-05'], asvs: ['v5.0.0-1.2.5'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/89.html'],
    },
  },
  {
    id: 'command-injection',
    files: js,
    match: /\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawnSync?)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)|shell\s*:\s*true/,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M1', 'M6'],
    rule: {
      name: 'OS command injection',
      background: 'Untrusted input is interpolated into a shell command, letting an attacker append commands of their own.',
      remediation: 'Pass arguments as an array with shell disabled. Never build a command string from input.',
      classification: { cwe: ['CWE-78'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-12'], asvs: ['v5.0.0-1.2.3'], api: [] },
      typical_severity: 'Critical',
      references: ['https://cwe.mitre.org/data/definitions/78.html'],
    },
  },
  {
    id: 'code-injection',
    files: js,
    match: /\beval\s*\(|\bnew\s+Function\s*\(/,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'LOW',
    modules: ['M1'],
    rule: {
      name: 'Code injection',
      background: 'Input evaluated as code gives an attacker execution in the application process.',
      remediation: 'Remove eval and new Function. Parse data with a parser, dispatch behaviour from a lookup table.',
      classification: { cwe: ['CWE-94'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-11'], asvs: ['v5.0.0-1.2.4'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/94.html'],
    },
  },
  {
    id: 'path-traversal',
    files: js,
    match: /\bpath\s*\.\s*(?:join|resolve)\s*\([^)]*\b(?:req|request)\./,
    taint: false, // the source is already inside the match
    method: 'dataflow',
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M1'],
    rule: {
      name: 'Path traversal',
      background:
        'A user-supplied name is joined to a base directory. join does not stop ../ from escaping, so the result can be any file the process can read.',
      remediation: 'Resolve the path, then verify it still starts with the base directory. Reject anything else.',
      classification: { cwe: ['CWE-22'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-01'], asvs: ['v5.0.0-5.1.1'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/22.html'],
    },
  },
  {
    id: 'ssrf',
    files: js,
    // The client list is the whole rule. NodeGoat fetches with `needle.get()` and
    // this matched nothing, so a textbook SSRF — `needle.get(req.query.url + ...)`
    // — was invisible while forty dependency CVEs were reported. Any name here is
    // a guess about which library someone chose; an unlisted one is a silent miss,
    // which is why `sec modules` has to run against code we did not write.
    match: /\b(?:https?|axios|fetch|got|request|needle|superagent|undici|ky|node-fetch|urllib|phin|wreck)\s*\.?\s*(?:get|post|put|patch|head|del|delete|request|fetch)?\s*\(\s*(?!['"`])[A-Za-z_$][\w$.]*\b/,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M1', 'M7'],
    rule: {
      name: 'Server-side request forgery',
      background:
        'The server fetches a URL the caller controls, so an attacker can reach internal services and cloud metadata endpoints the caller cannot.',
      remediation: 'Allowlist the hosts that may be fetched, resolve and re-check after each redirect, and do not follow redirects by default.',
      classification: { cwe: ['CWE-918'], owasp: ['A01:2025'], wstg: ['WSTG-v42-INPV-19'], asvs: ['v5.0.0-4.2.2'], api: ['API7:2023'] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/918.html'],
    },
  },
  {
    id: 'open-redirect',
    files: js,
    match: /\bres(?:ponse)?\s*\.\s*redirect\s*\(\s*(?!['"`])/,
    taint: true,
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    modules: ['M1'],
    rule: {
      name: 'Open redirect',
      background: 'A redirect target taken from input lets an attacker send users from a trusted origin to one they control.',
      remediation: 'Allowlist redirect targets, or accept only a relative path.',
      classification: { cwe: ['CWE-601'], owasp: ['A01:2025'], wstg: ['WSTG-v42-CLNT-04'], asvs: ['v5.0.0-3.2.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/601.html'],
    },
  },
  {
    id: 'xss-sink',
    files: js,
    match: /\.innerHTML\s*=|dangerouslySetInnerHTML|\bdocument\s*\.\s*write\s*\(|v-html\s*=/,
    taint: true,
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    modules: ['M1', 'M9'],
    rule: {
      name: 'Cross-site scripting sink',
      background: 'Untrusted input rendered as HTML executes in the victim browser with the origin of the application.',
      remediation: 'Render as text. Where HTML is required, sanitize with a maintained library and apply a strict CSP.',
      classification: { cwe: ['CWE-79'], owasp: ['A05:2025'], wstg: ['WSTG-v42-INPV-01'], asvs: ['v5.0.0-1.3.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/79.html'],
    },
  },
  {
    id: 'unsafe-deserialization',
    files: js,
    match: /\byaml\s*\.\s*load\s*\((?![^)]*safe)|\bnode-serialize\b|\bunserialize\s*\(/,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'LOW',
    modules: ['M1'],
    rule: {
      name: 'Unsafe deserialization',
      background: 'Deserializing untrusted data can construct arbitrary objects and reach code execution.',
      remediation: 'Use the safe loader, and validate against a schema before use.',
      classification: { cwe: ['CWE-502'], owasp: ['A08:2025'], wstg: ['WSTG-v42-INPV-11'], asvs: ['v5.0.0-1.5.2'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/502.html'],
    },
  },
  {
    id: 'weak-randomness',
    files: js,
    match: /Math\s*\.\s*random\s*\(\s*\)/,
    near: /token|secret|password|nonce|salt|session|reset|otp|key|id\b/i,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    modules: ['M4', 'M12'],
    rule: {
      name: 'Insufficiently random value',
      background: 'Math.random is not cryptographically secure. Values built from it are predictable, so tokens can be guessed.',
      remediation: 'Use crypto.randomUUID() or crypto.randomBytes() for anything security-relevant.',
      classification: { cwe: ['CWE-330'], owasp: ['A04:2025'], wstg: ['WSTG-v42-CRYP-04'], asvs: ['v5.0.0-11.3.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/330.html'],
    },
  },
  {
    id: 'weak-password-hash',
    files: js,
    match: /createHash\s*\(\s*['"](?:md5|sha1|sha256)['"]\s*\)/,
    near: /password|passwd|pwd|credential/i,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M12'],
    rule: {
      name: 'Password stored without a key derivation function',
      background:
        'A general-purpose hash is fast by design, so an attacker with the database can try billions of candidates per second. MD5 and SHA-1 are additionally broken.',
      remediation: 'Use argon2id, scrypt or bcrypt with a per-user salt and a tuned work factor.',
      classification: { cwe: ['CWE-916'], owasp: ['A04:2025'], wstg: ['WSTG-v42-CRYP-04'], asvs: ['v5.0.0-11.4.1'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/916.html'],
    },
  },
  {
    id: 'broken-crypto-algorithm',
    files: js,
    match: /\b(?:createCipheriv?\s*\(\s*['"](?:des|des-ede3|rc4|aes-\d+-ecb)['"]|['"]ECB['"])/i,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'LOW',
    modules: ['M12'],
    rule: {
      name: 'Broken or risky cryptographic algorithm',
      background: 'DES, RC4 and ECB mode do not provide the confidentiality the code assumes; ECB leaks structure in the plaintext.',
      remediation: 'Use an AEAD construction such as AES-256-GCM or ChaCha20-Poly1305.',
      classification: { cwe: ['CWE-327'], owasp: ['A04:2025'], wstg: ['WSTG-v42-CRYP-04'], asvs: ['v5.0.0-11.1.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/327.html'],
    },
  },
  {
    id: 'hardcoded-credential',
    files: /./,
    // The value must look like a secret. `apiKey: 'Direct API key'` is a label in a
    // UI, and reporting it Critical is how a tool teaches people to ignore it.
    // A real credential has no spaces in it; a caption almost always does.
    match: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*['"][^'"\n\s]{8,}['"]/i,
    taint: false,
    method: 'pattern',
    severity: 'Critical', impact: 'HIGH', likelihood: 'HIGH',
    modules: ['M3'],
    secret: true,
    rule: {
      name: 'Hardcoded credential',
      background:
        'A credential in the repository is available to everyone with read access, to every fork, and in the history for as long as the repository exists.',
      remediation: 'Move it to a secrets manager and rotate it. Treat the committed value as compromised even after removal.',
      classification: { cwe: ['CWE-798'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-02'], asvs: ['v5.0.0-14.2.1'], api: [] },
      typical_severity: 'Critical',
      references: ['https://cwe.mitre.org/data/definitions/798.html'],
    },
  },
  {
    id: 'permissive-cors',
    files: /./,
    match: /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"]\*['"]/i,
    taint: false,
    method: 'config',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    modules: ['M3', 'M9'],
    rule: {
      name: 'Permissive CORS policy',
      background: 'A wildcard origin lets any site read responses, and with credentials it exposes authenticated data cross-origin.',
      remediation: 'Allowlist the origins that need access. Never combine a wildcard with credentials.',
      classification: { cwe: ['CWE-942'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CLNT-07'], asvs: ['v5.0.0-3.4.1'], api: ['API8:2023'] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/942.html'],
    },
  },
  {
    id: 'debug-enabled',
    files: cfg.source ? /\.(?:js|mjs|cjs|ts|json|ya?ml|env|ini|conf|toml)$/i : cfg,
    match: /\b(?:DEBUG|debug)\s*[:=]\s*(?:true|1|['"]true['"])/,
    taint: false,
    method: 'config',
    severity: 'Low', impact: 'LOW', likelihood: 'MEDIUM',
    modules: ['M3', 'M13'],
    rule: {
      name: 'Debug mode enabled',
      background: 'Debug output exposes stack traces, configuration and internal paths that help an attacker map the system.',
      remediation: 'Disable debug outside development, and return a generic error to the client.',
      classification: { cwe: ['CWE-489'], owasp: ['A02:2025'], wstg: ['WSTG-v42-CONF-02'], asvs: ['v5.0.0-13.4.1'], api: [] },
      typical_severity: 'Low',
      references: ['https://cwe.mitre.org/data/definitions/489.html'],
    },
  },
  {
    id: 'container-runs-as-root',
    finding_class: 'hardening',
    files: docker,
    match: /^\s*USER\s+root\s*$/im,
    taint: false,
    method: 'config',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'LOW',
    modules: ['M10'],
    rule: {
      name: 'Container runs as root',
      background: 'A process running as root turns a container escape or a write primitive into full control of the container, and sometimes the host.',
      remediation: 'Create an unprivileged user and switch to it before the entrypoint.',
      classification: { cwe: ['CWE-250'], owasp: ['A02:2025'], wstg: [], asvs: ['v5.0.0-13.1.1'], api: [] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/250.html'],
    },
  },
  {
    id: 'unpinned-base-image',
    finding_class: 'hardening',
    files: docker,
    match: /^\s*FROM\s+\S+:latest\s*$|^\s*FROM\s+[^\s:@]+\s*$/im,
    taint: false,
    method: 'config',
    severity: 'Low', impact: 'LOW', likelihood: 'MEDIUM',
    modules: ['M10', 'M2'],
    rule: {
      name: 'Unpinned base image',
      background: 'An unpinned base image means the build is not reproducible and can change under you, which is a supply-chain risk.',
      remediation: 'Pin the base image by digest, and update it deliberately.',
      classification: { cwe: ['CWE-1104'], owasp: ['A03:2025'], wstg: [], asvs: ['v5.0.0-15.1.1'], api: [] },
      typical_severity: 'Low',
      references: ['https://owasp.org/Top10/2025/'],
    },
  },

  // --- M14: AI/LLM and agent security.
  //
  // An application that calls a model has three surfaces the other modules do not
  // describe. The prompt is an insertion point. The completion is an UNTRUSTED
  // SOURCE, however much the developer trusts the vendor. And a tool handler is a
  // sink that the model's own output reaches.
  //
  // Scored against the OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10),
  // published 2024-11-18 by the OWASP GenAI Security Project.
  {
    id: 'prompt-injection',
    files: js,
    // Not "a model is called with request data in scope" — that is most of the
    // feature, and flagging it reported the deliberately-correct handler in mock/
    // at High. The defect is request data landing in the INSTRUCTIONS: a system
    // prompt or instruction string built by interpolation. Untrusted text carried
    // in a user-role message is where it belongs.
    match: /(?:\bsystem|\binstructions?|\bsystemPrompt|\bsystem_prompt)\s*[:=]\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/i,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M14', 'M6'],
    rule: {
      name: 'Untrusted input reaches a model prompt',
      background:
        'A model cannot tell a developer instruction from text that arrived in a request. Where request data is folded into a prompt, whoever controls that data can redirect what the model does, including which tools it calls and what it discloses. Retrieved documents and web pages are untrusted input too.',
      remediation:
        'Keep untrusted text in a separate role from instructions and never concatenate it into the system prompt. Constrain what the model may do after reading it: least-privilege tools, an allowlist of actions, and a human decision before anything irreversible. Escaping is not a defence.',
      classification: {
        cwe: ['CWE-1427'], owasp: ['A03:2025'], wstg: [], asvs: [], api: [],
        owasp_llm: ['LLM01:2025'],
      },
      typical_severity: 'High',
      references: ['https://genai.owasp.org/llm-top-10/', 'https://cwe.mitre.org/data/definitions/1427.html'],
    },
  },
  {
    id: 'llm-output-to-sink',
    files: js,
    // The dangerous half: a model's words reaching something that acts on them.
    match: /\b(?:eval|exec|execSync|execFile|spawn|Function)\s*\(|\.innerHTML\s*=|\bdangerouslySetInnerHTML\b|\b(?:db|conn|client|pool)\s*\.\s*(?:raw|query|execute)\s*\(/,
    near: /\bcompletion|\bchoices\s*\[|message\.content|\.content\s*\[|response\.text|\bllmOutput\b|\bmodelResponse\b|\b(?:generateText|streamText|generateObject|streamObject)\b/i,
    taint: false,
    method: 'pattern',
    severity: 'Critical', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M14', 'M1'],
    rule: {
      name: 'Model output reaches an execution or rendering sink',
      background:
        'A completion is untrusted input. Passing it to eval, a shell, a query or innerHTML turns prompt injection into code execution or stored XSS, and the attacker never needs access to the code that does it.',
      remediation:
        'Treat a completion exactly as you would a request body: validate it against a schema, and never execute, interpolate or render it unescaped. Where the model must choose an action, map its answer onto a fixed allowlist rather than running what it returns.',
      classification: {
        cwe: ['CWE-94'], owasp: ['A03:2025'], wstg: [], asvs: [], api: [],
        owasp_llm: ['LLM05:2025'],
      },
      typical_severity: 'Critical',
      references: ['https://genai.owasp.org/llm-top-10/'],
    },
  },
  {
    id: 'secret-in-prompt',
    files: js,
    match: /(?:prompt|system|instructions?|content)\s*[:=]\s*[`'"][^`'"]{0,400}\$\{[^}]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M14', 'M3'],
    secret: true,
    rule: {
      name: 'Credential interpolated into a prompt',
      background:
        'Anything placed in a prompt can come back out of the model, in a completion, in a log, in a trace, or in a vendor-side retention window. A secret in a prompt should be treated as disclosed.',
      remediation:
        'Keep credentials out of prompts entirely. Where the model needs an action that requires one, put the credential in the tool handler and give the model only the name of the action.',
      classification: {
        cwe: ['CWE-200'], owasp: ['A02:2025'], wstg: [], asvs: [], api: [],
        owasp_llm: ['LLM02:2025'],
      },
      typical_severity: 'High',
      references: ['https://genai.owasp.org/llm-top-10/'],
    },
  },
  {
    id: 'excessive-agent-authority',
    files: js,
    // A tool the model can call, whose handler runs a shell.
    match: /\b(?:exec|execSync|spawn|spawnSync)\s*\(|shell\s*:\s*true/,
    // `tool` without a word boundary, so `handleTool` and `toolHandler` both count.
    near: /tool|\bfunction_call\b|\bfunctionDeclarations\b|\b(?:input_schema|parameters)\s*:/i,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M14', 'M5'],
    rule: {
      name: 'Agent tool runs a shell',
      background:
        'A tool is called with arguments the model chose, and the model can be steered by anything it has read. A shell in a tool handler makes the blast radius of a prompt injection the whole machine.',
      remediation:
        'Give each tool the narrowest capability that does the job, pass arguments as an array rather than a command string, and require a human decision before anything destructive or outward-facing.',
      classification: {
        cwe: ['CWE-250'], owasp: ['A01:2025'], wstg: [], asvs: [], api: [],
        owasp_llm: ['LLM06:2025'],
      },
      typical_severity: 'High',
      references: ['https://genai.owasp.org/llm-top-10/'],
    },
  },
  {
    id: 'unbounded-model-consumption',
    files: js,
    match: MODEL_CALL,
    // The finding is the absence: no ceiling anywhere in the enclosing function.
    not_near: /max_tokens|maxTokens|maxOutputTokens|max_output_tokens|\btimeout\b|AbortSignal/i,
    taint: false,
    method: 'pattern',
    finding_class: 'hardening',
    severity: 'Low', impact: 'LOW', likelihood: 'MEDIUM',
    modules: ['M14'],
    rule: {
      name: 'Model call with no output or time ceiling',
      background:
        'Without a token or time limit, one request can cost an unbounded amount of money and hold a connection open for as long as the model keeps writing. It is a billing and availability concern rather than a way in.',
      remediation: 'Set an explicit max_tokens and a request timeout, and rate-limit per caller.',
      classification: {
        cwe: ['CWE-770'], owasp: ['A04:2025'], wstg: [], asvs: [], api: [],
        owasp_llm: ['LLM10:2025'],
      },
      typical_severity: 'Low',
      references: ['https://genai.owasp.org/llm-top-10/'],
    },
  },

  // --- Found by scanning OWASP Juice Shop, which annotates its own planted
  // --- defects. Twenty-seven marked lines; we recognised two. Each rule below
  // --- closes one of the misses and had to generalise past this one corpus to
  // --- be worth writing.

  {
    id: 'bypass-framework-escaping',
    files: js,
    // Angular's escape hatch, with anything but a literal going through it.
    match: /\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*(?!['"`])/,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'MEDIUM', likelihood: 'HIGH',
    modules: ['M9', 'M1'],
    subtype: 'framework-escaping-bypassed',
    rule: {
      name: 'Framework escaping deliberately bypassed',
      background:
        'Angular escapes interpolated values by default, which is why XSS is rare in it. `bypassSecurityTrustHtml` and its siblings exist to switch that off for a value the developer knows is safe. Called on anything that reaches the page from a request or a database row, it hands the attacker the DOM.',
      remediation:
        'Render the value as text and let the framework escape it. Where markup really is required, sanitize with the framework sanitizer rather than bypassing it, and keep the bypass to a literal.',
      classification: {
        cwe: ['CWE-79'], owasp: ['A05:2025'], wstg: ['WSTG-v42-CLNT-01'],
        asvs: ['v5.0.0-1.3.1'], api: [],
      },
      typical_severity: 'High',
      references: ['https://angular.dev/best-practices/security'],
    },
  },
  {
    id: 'nosql-operator-injection',
    files: js,
    // A query filter whose value is a request field verbatim. In Mongo and NeDB
    // a JSON body can make that value an operator object — `{"$ne": null}` —
    // and the filter stops meaning what it reads like.
    // Only a lookup key. `{ username: req.body.username }` is a payload in far
    // more code than it is a filter, and firing on it named NoSQL injection over
    // an ordinary Sequelize profile update.
    match: /\{\s*['"]?(?:_id|id|_ids|userId|UserId|user_id|ownerId|email|token|sessionId)['"]?\s*:\s*(?:req|request)\.(?:body|query|params)\.[\w.]+\s*\}/,
    near: /\.\s*(?:find|findOne|update|updateOne|updateMany|remove|delete|deleteOne|deleteMany|count)\s*\(/,
    // Sequelize wraps its filter in `where:` and binds values, so the same shape
    // there is a different defect with a different fix. Firing on it named the
    // wrong cause, which is worse than staying quiet: it sends someone to
    // sanitize a value when the actual bug is that the row id came from the body.
    not_near: /\bsequelize\b|\bwhere\s*:/i,
    taint: true,
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M6', 'M8', 'M1'],
    subtype: 'nosql-operator',
    rule: {
      name: 'NoSQL query takes an operator from the request',
      background:
        'The filter reads as an equality test, and a JSON body can replace the value with an operator object so that it matches every row instead of one. Parameterization does not apply here: the value *is* the query language.',
      remediation:
        'Coerce the value to the type you expect before it reaches the filter — `String(req.body.id)` — or validate it against a schema that rejects objects.',
      classification: {
        cwe: ['CWE-943'], owasp: ['A02:2025'], wstg: ['WSTG-v42-INPV-05'],
        asvs: ['v5.0.0-1.3.1'], api: ['API8:2023'],
      },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/943.html'],
    },
  },
  {
    id: 'commented-out-authorization',
    files: js,
    // A route registration that carried a guard, commented out and left in place.
    match: /^\s*(?:\/\/|\*)\s*(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use|all)\s*\([^)]*\b(?:isAuthorized|requireAuth|requiresAuth|authenticate|authorize|ensureLoggedIn|requireRole|requireAdmin|checkAuth|denyAll)\b/,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'HIGH',
    modules: ['M5', 'M7'],
    subtype: 'guard-commented-out',
    rule: {
      name: 'Authorization on this route is commented out',
      background:
        'The guard is still in the file, one character from being live, so the route reads as protected to anyone skimming it and to most tools. The neighbouring routes keep theirs, which is what makes this a gap rather than a design.',
      remediation:
        'Restore the guard, or delete the line and record why this route is public. A commented-out control is the worst of both: no protection and no record of the decision.',
      classification: {
        cwe: ['CWE-862'], owasp: ['A01:2025'], wstg: ['WSTG-v42-ATHZ-02'],
        asvs: ['v5.0.0-8.1.1'], api: ['API5:2023'],
      },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/862.html'],
    },
  },
  {
    id: 'rate-limit-keyed-on-client-header',
    files: js,
    match: /\bkeyGenerator\b/,
    near: /X-Forwarded-For|x-forwarded-for|headers\s*\[|req\.headers|\.get\s*\(\s*['"]x-/i,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'HIGH',
    modules: ['M4', 'M7'],
    subtype: 'rate-limit-key-spoofable',
    rule: {
      name: 'Rate limit keyed on a header the client controls',
      background:
        'The limiter counts per key, and the key comes from a request header. An attacker sends a different value each time and the limit never applies — which matters most on the endpoints a limiter is put in front of: login, password reset, OTP.',
      remediation:
        'Key on the connecting address. Where the app really is behind a proxy, configure `trust proxy` so the framework resolves the client address itself, rather than reading the header in application code.',
      classification: {
        cwe: ['CWE-807'], owasp: ['A07:2025'], wstg: ['WSTG-v42-ATHN-03'],
        asvs: ['v5.0.0-2.2.1'], api: ['API4:2023'],
      },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/807.html'],
    },
  },
  {
    id: 'directory-listing-enabled',
    files: js,
    match: /\bserveIndex\s*\(|\bautoIndex\s*:\s*true|\bdirectoryListing\s*:\s*true/,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'HIGH',
    modules: ['M3', 'M10', 'M13'],
    subtype: 'directory-listing',
    rule: {
      name: 'Directory listing is served',
      background:
        'The contents of a directory are browsable over HTTP. Nothing is exploited by reading a file list, which is why this survives review — and it is how an attacker finds the backup, the log and the export that were never meant to be linked.',
      remediation:
        'Turn listing off and serve only the paths the application means to expose. If browsing is a feature, put it behind the same authorization as the files it lists.',
      classification: {
        cwe: ['CWE-548'], owasp: ['A05:2025'], wstg: ['WSTG-v42-CONF-04'],
        asvs: ['v5.0.0-14.3.3'], api: ['API8:2023'],
      },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/548.html'],
    },
  },
  {
    id: 'exposed-operational-endpoint',
    files: js,
    match: /\b(?:app|router)\s*\.\s*(?:get|use|all)\s*\(\s*['"`]\/(?:metrics|debug|actuator|env|heapdump|trace|admin\/stats)\b/,
    not_near: /\b(?:isAuthorized|requireAuth|requiresAuth|authenticate|authorize|ensureLoggedIn|requireRole|requireAdmin|checkAuth|basicAuth)\b/,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'HIGH',
    modules: ['M3', 'M7', 'M13'],
    subtype: 'operational-endpoint-public',
    rule: {
      name: 'Operational endpoint served without authorization',
      background:
        'Metrics, debug and environment endpoints are built for operators and describe the system in detail: route names, dependency versions, traffic volumes, sometimes configuration. Registered next to the public routes with no guard, they are a map of the application handed to anyone who asks.',
      remediation:
        'Bind these to an internal interface, or require authorization on them explicitly. Do not rely on the path being unguessable.',
      classification: {
        cwe: ['CWE-200'], owasp: ['A05:2025'], wstg: ['WSTG-v42-CONF-05'],
        asvs: ['v5.0.0-14.3.3'], api: ['API8:2023'],
      },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/200.html'],
    },
  },
  {
    id: 'allowlist-matched-by-substring',
    files: js,
    // `url.includes(allowed)` is true for `https://evil.test/?x=https://good.test`.
    match: /\b\w*(?:url|uri|target|redirect|origin|referer|host|domain)\w*\s*\.\s*(?:includes|indexOf|startsWith|search|match)\s*\(/i,
    near: /allow(?:ed|list)?|whitelist|permitted|trusted|safeList/i,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'HIGH',
    modules: ['M1', 'M9', 'M7'],
    subtype: 'allowlist-substring-match',
    rule: {
      name: 'Allowlist compared by substring',
      background:
        'The check asks whether the allowed value appears anywhere in the URL, so an attacker puts it anywhere in a URL they control — in a query string, a fragment, a subdomain or a userinfo part — and the comparison passes. The allowlist looks right in review and enforces nothing.',
      remediation:
        'Parse the URL and compare the parsed origin for equality against the allowed set. Never decide a security question with a substring test on a URL.',
      classification: {
        cwe: ['CWE-697'], owasp: ['A01:2025'], wstg: ['WSTG-v42-CLNT-04'],
        asvs: ['v5.0.0-3.2.1'], api: ['API7:2023'],
      },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/697.html'],
    },
  },
  {
    id: 'tool-bound-stated-only-in-prose',
    files: js,
    // The schema says "maximum 10" in a sentence the model reads and the
    // validator does not. Whatever the model returns is what the handler acts on.
    match: /\.\s*describe\s*\(\s*['"`][^'"`]*\b(?:maximum|minimum|at most|at least|no more than|not exceed|up to)\b/i,
    not_near: /\.\s*(?:max|min|lte|gte|lt|gt|int|positive|nonnegative|enum|regex|length|step)\s*\(/,
    taint: false,
    method: 'pattern',
    severity: 'High', impact: 'HIGH', likelihood: 'MEDIUM',
    modules: ['M14', 'M5'],
    subtype: 'tool-bound-unenforced',
    rule: {
      name: 'Tool argument bounded only by its description',
      background:
        'The schema states a limit in prose and does not encode it. Prose is an instruction to the model, and a model can be argued out of an instruction by anything it has read — that is what prompt injection is. The handler then acts on the number it was given, so the limit held only while nobody attacked it.',
      remediation:
        'Encode the bound in the schema (`z.number().max(10)`), and check it again in the handler before the privileged action. The description is documentation, never a control.',
      classification: {
        cwe: ['CWE-20'], owasp: ['A04:2025'], wstg: [], asvs: ['v5.0.0-1.3.1'], api: [],
        owasp_llm: ['LLM06:2025'],
      },
      typical_severity: 'High',
      references: ['https://genai.owasp.org/llm-top-10/'],
    },
  },

  // --- Found by scanning OWASP NodeGoat, which documents both.

  {
    id: 'template-autoescape-disabled',
    files: js,
    match: /\bautoescap(?:e|ing)\s*[:=]\s*(?:false|False|0)\b|\{%\s*autoescape\s+off\s*%\}/,
    taint: false,
    method: 'config',
    severity: 'High', impact: 'HIGH', likelihood: 'HIGH',
    modules: ['M9', 'M6'],
    rule: {
      name: 'Template auto-escaping disabled',
      background:
        "The template engine escapes output by default; this switches that off for every template in the application at once. Any value rendered from then on is rendered as markup, so one stored field becomes script running in every viewer's browser. The defect is one line of configuration with the whole view layer as its blast radius, which is why reviewing handlers one at a time never finds it.",
      remediation:
        'Leave auto-escaping on and opt out per value, where markup is genuinely intended and the value is known to be safe. Escape for the context the value lands in: encoding for HTML and then using the result inside a URL or an attribute is still an injection.',
      classification: { cwe: ['CWE-79'], owasp: ['A03:2025'], wstg: ['WSTG-v42-CLNT-01'], asvs: ['v5.0.0-1.3.1'], api: [] },
      typical_severity: 'High',
      references: ['https://cwe.mitre.org/data/definitions/79.html'],
    },
  },
  {
    id: 'redos-nested-quantifier',
    files: js,
    // A quantified group that is itself quantified: /([0-9]+)+/
    match: /\/[^/\n]*\([^)\n]*[+*][^)\n]*\)\s*[+*][^/\n]*\//,
    taint: false,
    method: 'pattern',
    severity: 'Medium', impact: 'MEDIUM', likelihood: 'MEDIUM',
    modules: ['M6'],
    rule: {
      name: 'Regular expression open to catastrophic backtracking',
      background:
        'A quantifier applied to an already-quantified group makes the engine try exponentially many ways to match a near-miss. One short crafted input holds a CPU until it finishes, and on a single-threaded runtime that is the whole service — from a request that looks ordinary in the logs.',
      remediation:
        'Remove the outer quantifier, or rewrite so each position has exactly one way to match. Where a regular expression must run on untrusted input, bound the input length and prefer a parser.',
      classification: { cwe: ['CWE-1333'], owasp: ['A04:2025'], wstg: ['WSTG-v42-BUSL-09'], asvs: ['v5.0.0-4.3.2'], api: ['API4:2023'] },
      typical_severity: 'Medium',
      references: ['https://cwe.mitre.org/data/definitions/1333.html'],
    },
  },
];
