/**
 * Semgrep Demo App - Intentionally Vulnerable Node.js Server
 * DO NOT deploy this in production. This contains deliberate security flaws.
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY 1: Hardcoded API key / secret
// Semgrep rule: javascript.lang.security.audit.detect-hardcoded-secrets
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
const API_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const STRIPE_KEY = "sk_live_abc123def456ghi789jkl012";

/**
 * VULNERABILITY 2: Cross-Site Scripting (XSS)
 * Semgrep rule: javascript.express.security.audit.xss.direct-response-write
 */
app.get("/greet", (req, res) => {
  const name = req.query.name;
  // BAD: Reflecting user input directly into HTML response without sanitization
  res.send("<html><body><h1>Hello, " + name + "!</h1></body></html>");
});

app.get("/search", (req, res) => {
  const query = req.query.q;
  // BAD: Another XSS variant — user input in HTML
  const html = `
    <html>
      <body>
        <h2>Search results for: ${query}</h2>
        <p>No results found.</p>
      </body>
    </html>
  `;
  res.send(html);
});

/**
 * VULNERABILITY 3: eval() with user input — Code Injection
 * Semgrep rule: javascript.lang.security.audit.detect-eval-with-expression
 */
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;
  // BAD: eval() on user-supplied input — arbitrary code execution
  const result = eval(expression);
  res.json({ result: result });
});

app.post("/dynamic-exec", (req, res) => {
  const code = req.body.code;
  // BAD: Another eval variant
  const output = eval("(" + code + ")");
  res.json({ output: output });
});

/**
 * VULNERABILITY 4: Path Traversal / Local File Inclusion
 * Semgrep rule: javascript.express.security.audit.path-traversal
 */
app.get("/files/:filename", (req, res) => {
  const filename = req.params.filename;
  // BAD: User-controlled path joined directly — allows ../../etc/passwd
  const filePath = path.join(__dirname, "uploads", filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      return res.status(404).json({ error: "File not found" });
    }
    res.send(data);
  });
});

app.get("/download", (req, res) => {
  const file = req.query.file;
  // BAD: Directly using user input in file path with no validation
  fs.readFile(file, (err, data) => {
    if (err) {
      return res.status(404).json({ error: "File not found" });
    }
    res.send(data);
  });
});

/**
 * BONUS: Insecure CORS configuration
 */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

/**
 * BONUS: No rate limiting, no helmet, no CSRF protection
 */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API Key: ${API_KEY}`); // BAD: Logging secrets
});
