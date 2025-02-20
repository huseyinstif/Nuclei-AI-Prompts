
# Nuclei AI Prompts

  

Welcome to **nucleiprompts.com**, a collection of AI-powered security prompts for **Nuclei**, designed for penetration testers and security researchers.

  

🔗 **Visit the website:** [nucleiprompts.com](http://nucleiprompts.com)

  

## 📌 Categories & Prompts

  

### 🛠 XSS (Cross-Site Scripting)

```plaintext

1. Detect Basic XSS → Find common XSS patterns in response bodies.

2. Reflected XSS Detection → Identify reflected XSS vulnerabilities via GET parameters.

3. DOM-Based XSS Detection → Find DOM-based XSS vulnerabilities where user input is reflected inside JavaScript execution.

4. Stored XSS Finder → Identify stored XSS vulnerabilities where malicious scripts persist in the application.

```

  

### 💾 SQL Injection

```plaintext

1. Blind SQL Injection → Use time-based techniques to find blind SQL injection.

2. Error-Based SQL Injection → Check for error messages revealing SQL queries.

3. Union-Based SQL Injection Detection → Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data.

4. Boolean-Based Blind SQL Injection → Identify SQL injection vulnerabilities using boolean-based conditions.

```

  

### 🖥 Remote Code Execution (RCE)

```plaintext

1. Basic RCE Detection → Find potential remote command execution in input fields.

2. Command Injection Detection → Identify potential command injection vulnerabilities in input fields.

3. RCE via File Upload → Detect RCE vulnerabilities through insecure file upload mechanisms.

```

  

### 📂 Directory Traversal

```plaintext

1. Directory Traversal Exploit → Detect sensitive files exposed via traversal attacks.

2. Detect ../ Directory Traversal → Identify directory traversal vulnerabilities allowing access to sensitive files.

3. Absolute Path Traversal → Find vulnerabilities where absolute file paths can be exploited for unauthorized access.

```

  

### 🔓 Authentication Bypass

```plaintext

1. Weak Login Bypass → Identify login pages vulnerable to authentication bypass.

2. JWT Token Tampering Detection → Identify authentication bypass vulnerabilities due to weak JWT token implementations.

3. Weak API Key Exposure → Detect weak or publicly exposed API keys leading to authentication bypass.

```

  

### 🌐 Server-Side Request Forgery (SSRF)

```plaintext

1. Detect SSRF → Find SSRF vulnerabilities allowing remote server requests.

2. Open Redirect via SSRF → Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers.

3. Internal Port Scanning via SSRF → Detect internal port scanning vulnerabilities using SSRF payloads.

```

  

### ⚙️ Security Misconfiguration

```plaintext

1. Find Security Misconfigurations → Scan for default credentials, exposed directories, and insecure headers.

2. Check for Default Credentials → Scan for applications running with default credentials left unchanged.

3. Insecure HTTP Headers Detection → Identify missing security headers such as CSP, X-Frame-Options, and HSTS.

```

  

### 🔀 Race Condition

```plaintext

1. Detect Race Condition Issues → Identify vulnerabilities where multiple parallel processes can manipulate shared resources.

```

  

### 📡 XML External Entity (XXE)

```plaintext

1. Detect XXE Vulnerabilities → Identify XML External Entity attacks in web applications accepting XML input.

```

  

### 📁 File Inclusion (LFI/RFI)

```plaintext

1. LFI/RFI Detection → Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms.

```

  

### 📥 HTTP Request Smuggling

```plaintext

1. HTTP Smuggling Detection → Find HTTP request smuggling vulnerabilities by testing different content-length and transfer encoding headers.

```

  

### 🔎 Additional Prompts from SQL File

```plaintext

1. JWT Token Analysis → Check for weak JWT implementations and misconfigurations.

2. Command Injection Scan → Identify user input fields allowing shell command execution.

3. Broken Access Control Detection → Detect improper user authorization and privilege escalation vulnerabilities.

4. Detect XXE Vulnerabilities → Identify XML External Entity attacks in web applications accepting XML input.

5. Open Redirect via SSRF → Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers.

6. LFI/RFI Detection → Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms.

7. Internal Port Scanning via SSRF → Detect internal port scanning vulnerabilities using SSRF payloads.

```

  

## 🚀 Contributing

We welcome contributions! If you have new security prompts or improvements, feel free to submit a pull request.

  

🔗 **Visit the website:** [nucleiprompts.com](http://nucleiprompts.com)

  

📌 **GitHub Repo:** [github.com/nucleiprompts.com](https://github.com/huseyinstif/Nuclei-AI-Prompts)

## Contact

For any inquiries or further information, you can reach out to me through:

- [LinkedIn](https://www.linkedin.com/in/huseyintintas/)
- [Twitter](https://twitter.com/1337stif)