# Phase 4: Vulnerability Detection Implementation Plan

## Overview

This document outlines the vulnerabilities to be added to Sentinel based on analysis from "Secure Coding in C and C++" (2nd Edition) by Robert Seacord. These vulnerabilities are DAST-detectable and will enhance Sentinel's security scanning capabilities.

## Current State

Sentinel currently detects:
- ✅ Missing Security Headers (X-Frame-Options, CSP, etc.)
- ✅ Unsafe Cookies (Secure, HttpOnly, SameSite)
- ✅ CORS Misconfiguration
- 🔄 Reflected XSS (basic)
- 🔄 CSRF (basic)
- 🔄 IDOR (basic)

## Secure Coding Principles (From Textbook)

All implementation in Phase 4 must adhere to the secure coding principles outlined in "Secure Coding in C and C++" (2nd Edition) by Robert Seacord. These principles guide how we design, implement, and test vulnerability detection.

### 1. Input Validation (Chapter 9, Section 9.5)

**Principle**: All data crossing trust boundaries must be validated.

**Application to Sentinel**:
- Test with diverse input types: strings, integers, special characters, Unicode
- Test boundary conditions: empty strings, maximum length, null bytes
- Test encoding variations: URL encoding, HTML encoding, Unicode normalization
- Expand payload library with input validation bypass techniques
- Verify that applications properly validate all user inputs

**Implementation Guidelines**:
- Include payloads that test various data types and formats
- Test for encoding/escaping bypasses (e.g., `%00`, `%0a`, `%0d`)
- Test boundary conditions (empty, max length, overflow)
- Test special characters that might break parsing logic

### 2. Tainted Data (Chapter 2, Section 2.3)

**Principle**: User input is "tainted" until validated and sanitized.

**Application to Sentinel**:
- Trace how user input flows through the application
- Test all input points: URL parameters, POST body, headers, cookies
- Verify that tainted data doesn't reach sensitive operations (SQL queries, command execution, file operations)
- Check for proper sanitization at trust boundaries

**Implementation Guidelines**:
- Test all parameters discovered during crawling
- Track input parameters and analyze how they appear in responses
- Verify that user input is properly sanitized before use
- Test for cases where tainted data bypasses validation

### 3. Sanitization (Chapter 9, Section 9.5)

**Principle**: Data sanitization and input validation are complementary but distinct.

**Application to Sentinel**:
- Test for encoding/escaping bypasses
- Verify proper output encoding (HTML, URL, JavaScript)
- Test various encoding schemes: URL, HTML entities, Unicode, Base64
- Check for double-encoding vulnerabilities

**Implementation Guidelines**:
- Test payloads with various encoding schemes
- Test for encoding bypasses (e.g., `%252e` for `..`, `%00` for null byte)
- Verify that output is properly encoded to prevent injection
- Test for cases where sanitization is incomplete or incorrect

### 4. Defense in Depth (Chapter 9)

**Principle**: Multiple layers of security controls provide better protection than a single control.

**Application to Sentinel**:
- Check multiple security mechanisms: headers, cookies, input validation, output encoding
- Verify that security controls work together, not in isolation
- Test that removing one control doesn't completely compromise security
- Ensure that failures in one layer don't bypass all security

**Implementation Guidelines**:
- Test multiple security controls simultaneously
- Verify that security headers, input validation, and output encoding work together
- Test for cases where one security control fails but others still protect
- Ensure comprehensive security coverage across all layers

### 5. Trust Boundaries (Chapter 9)

**Principle**: Data crossing trust boundaries needs validation and sanitization.

**Application to Sentinel**:
- Identify trust boundaries: user input → application → database, file system, external services
- Test all injection points: parameters, headers, cookies, request body
- Verify that data is validated at each trust boundary
- Test for cases where trust boundaries are not properly enforced

**Implementation Guidelines**:
- Test all input points that cross trust boundaries
- Verify that data is validated before crossing boundaries
- Test for cases where boundaries are bypassed or not enforced
- Ensure that sensitive operations (SQL, commands, file access) validate input

### 6. Error Handling (Chapter 9, Section 9.5)

**Principle**: Errors should not reveal sensitive information or system internals.

**Application to Sentinel**:
- Detect verbose error messages that reveal system information
- Check for stack traces, file paths, internal IPs, database errors
- Verify that errors are handled gracefully without information disclosure
- Test for cases where errors reveal sensitive data

**Implementation Guidelines**:
- Analyze error responses for information disclosure
- Check for stack traces, file paths, version information
- Verify that errors don't reveal system internals
- Test for cases where error handling is insufficient

### 7. Least Privilege (Chapter 9)

**Principle**: Applications should operate with the minimum privileges necessary.

**Application to Sentinel**:
- Test for privilege escalation vulnerabilities
- Verify that access controls are properly enforced
- Test for cases where users can access resources beyond their privileges
- Check for insecure direct object references (IDOR)

**Implementation Guidelines**:
- Test access control on all endpoints
- Verify that users can only access authorized resources
- Test for horizontal and vertical privilege escalation
- Ensure that authorization checks are performed consistently

### 8. Fail Securely (Chapter 9)

**Principle**: When security controls fail, the system should fail in a secure state.

**Application to Sentinel**:
- Test for cases where security controls fail open
- Verify that failures don't bypass security mechanisms
- Test for race conditions that might bypass security checks
- Check for cases where exceptions bypass security controls

**Implementation Guidelines**:
- Test error conditions and exception handling
- Verify that security controls are not bypassed on failure
- Test for race conditions and timing issues
- Ensure that failures maintain security state

### 9. Secure by Default (Chapter 9)

**Principle**: Default configurations should be secure, requiring explicit action to reduce security.

**Application to Sentinel**:
- Check for insecure default configurations
- Verify that security features are enabled by default
- Test for cases where defaults are insecure
- Check for missing security headers, weak encryption, etc.

**Implementation Guidelines**:
- Test default configurations for security issues
- Verify that security features are enabled by default
- Test for cases where defaults compromise security
- Ensure that secure defaults are enforced

### 10. Complete Mediation (Chapter 9)

**Principle**: Every access to every resource must be checked for authorization.

**Application to Sentinel**:
- Test that all endpoints enforce authorization
- Verify that access controls are not bypassed
- Test for cases where authorization checks are missing or incomplete
- Check for direct object references without authorization

**Implementation Guidelines**:
- Test authorization on all discovered endpoints
- Verify that access controls are consistently enforced
- Test for cases where authorization can be bypassed
- Ensure that all resources require proper authorization

## Implementation Priority

**Important Note**: The vulnerabilities in Phase 4.2+ (SQL injection, command injection, IDOR, etc.) require foundational capabilities that Sentinel currently lacks: session management, response pattern analysis, timing analysis, and baseline comparison. These must be built in Phase 4.0 before attempting authenticated vulnerability detection.

### Phase 4.0: Foundation (Prerequisites) - **REQUIRED FIRST**

**Timeline**: 4-6 weeks (semester-long effort)

**Why This Phase is Critical**:
Many high-impact vulnerabilities (SQL injection, command injection, IDOR) require:
- **Authentication state** - Most injection vulnerabilities are behind login walls
- **Response analysis** - Need to detect SQL errors, command output, timing anomalies
- **Session management** - Must maintain authenticated sessions across requests
- **Baseline comparison** - Compare normal vs. malicious payload responses

Without these foundations, Sentinel can only detect unauthenticated, header-level vulnerabilities.

#### 1. Session Management Module

**Priority**: Critical (Blocking)
**Difficulty**: Moderate
**Timeline**: 2-3 weeks

**Requirements**:
- Login flow support (form-based, API-based, OAuth)
- Cookie/token persistence across requests
- Session state management
- Multi-user support (for IDOR testing)

**Implementation**:

```cpp
// src/core/session_manager.h
class SessionManager {
public:
    struct Credentials {
        std::string username;
        std::string password;
        std::string login_url;
        std::string login_method;  // "form", "api", "oauth"
        std::map<std::string, std::string> form_fields;  // For form-based login
    };

    bool authenticate(const Credentials& creds);
    void maintain_session(HttpRequest& req);  // Add cookies/tokens to request
    bool is_authenticated() const;
    void logout();

private:
    std::string session_id_;
    std::map<std::string, std::string> cookies_;
    std::string auth_token_;
    bool authenticated_;
};
```

**Files to Create**:
- `src/core/session_manager.h`
- `src/core/session_manager.cpp`
- `config/auth_config.yaml` - Login credentials and flow configuration

**Configuration Example**:
```yaml
# config/auth_config.yaml
authentication:
  login_url: "https://example.com/login"
  method: "form"  # or "api", "oauth"
  form_fields:
    username_field: "username"
    password_field: "password"
  credentials:
    username: "test_user"
    password: "test_password"
  session_cookie: "sessionid"
  csrf_token_field: "csrfmiddlewaretoken"
```

---

#### 2. Response Pattern Analysis Engine

**Priority**: Critical (Blocking)
**Difficulty**: Moderate
**Timeline**: 1-2 weeks

**Requirements**:
- SQL error pattern matching (MySQL, PostgreSQL, SQL Server, Oracle)
- Command output detection (usernames, file listings, system info)
- File system error detection (path traversal indicators)
- Framework error detection (stack traces, debug info)

**Implementation**:

```cpp
// src/core/response_analyzer.h
class ResponseAnalyzer {
public:
    struct AnalysisResult {
        bool sql_error_detected;
        std::string sql_database_type;  // "mysql", "postgresql", "sqlserver", "oracle"
        bool command_output_detected;
        bool file_content_detected;
        bool stack_trace_detected;
        std::vector<std::string> detected_patterns;
    };

    AnalysisResult analyze(const HttpResponse& response);

private:
    // SQL error patterns
    std::vector<std::regex> sql_error_patterns_;

    // Command output patterns
    std::vector<std::regex> command_output_patterns_;

    // File system error patterns
    std::vector<std::regex> filesystem_error_patterns_;

    void initialize_patterns();
};
```

**SQL Error Patterns**:
```cpp
// MySQL
std::regex("mysql_fetch|mysql_num_rows|Warning: mysql_|You have an error in your SQL syntax",
           std::regex_constants::icase);

// PostgreSQL
std::regex("PostgreSQL query failed|pg_query\\(\\)|pg_exec\\(\\)|ERROR.*PostgreSQL",
           std::regex_constants::icase);

// SQL Server
std::regex("Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|SQLServer JDBC Driver",
           std::regex_constants::icase);

// Oracle
std::regex("ORA-[0-9]+|quoted string not properly terminated|Oracle error",
           std::regex_constants::icase);
```

**Command Output Patterns**:
```cpp
// Username detection
std::regex("uid=[0-9]+\\([a-zA-Z0-9_]+\\)|username: [a-zA-Z0-9_]+",
           std::regex_constants::icase);

// File listing patterns
std::regex("total [0-9]+|drwx|Directory of|Index of",
           std::regex_constants::icase);

// System info
std::regex("Linux|Windows|Darwin|kernel version",
           std::regex_constants::icase);
```

**Files to Create**:
- `src/core/response_analyzer.h`
- `src/core/response_analyzer.cpp`
- `config/response_patterns.yaml` - Configurable patterns

---

#### 3. Timing Analysis Module

**Priority**: High (Required for blind SQL injection)
**Difficulty**: Moderate
**Timeline**: 1 week

**Requirements**:
- Baseline response time measurement
- Timing anomaly detection (blind SQL injection, command injection)
- Statistical analysis (account for network variance)

**Implementation**:

```cpp
// src/core/timing_analyzer.h
class TimingAnalyzer {
public:
    struct TimingResult {
        double baseline_time;      // Normal response time
        double payload_time;        // Response time with payload
        double time_difference;     // Difference
        bool timing_anomaly;        // True if significant delay detected
        double confidence;          // Confidence in detection (0.0-1.0)
    };

    void establish_baseline(const HttpResponse& baseline_response);
    TimingResult analyze(const HttpResponse& payload_response);

    // For blind SQL injection: SLEEP(5) should cause ~5 second delay
    bool detect_blind_sql_injection(const TimingResult& result, double expected_delay = 5.0);

    // For command injection: sleep 10 should cause ~10 second delay
    bool detect_blind_command_injection(const TimingResult& result, double expected_delay = 10.0);

private:
    double baseline_time_;
    double network_variance_;  // Account for network jitter
    static constexpr double TIMING_THRESHOLD = 0.8;  // 80% of expected delay
};
```

**Usage**:
```cpp
// Establish baseline
HttpResponse baseline = client.perform(normal_request);
timing_analyzer.establish_baseline(baseline);

// Test with time-based payload
HttpResponse payload_response = client.perform(malicious_request);
auto result = timing_analyzer.analyze(payload_response);

if (timing_analyzer.detect_blind_sql_injection(result, 5.0)) {
    // Likely blind SQL injection with SLEEP(5)
}
```

**Files to Create**:
- `src/core/timing_analyzer.h`
- `src/core/timing_analyzer.cpp`

---

#### 4. Baseline Comparison Framework

**Priority**: High (Required for accurate detection)
**Difficulty**: Easy
**Timeline**: 1 week

**Requirements**:
- Compare normal vs. malicious payload responses
- Detect differences in: status codes, response length, content, timing
- Reduce false positives by requiring significant differences

**Implementation**:

```cpp
// src/core/baseline_comparator.h
class BaselineComparator {
public:
    struct ComparisonResult {
        bool status_code_changed;
        bool response_length_changed;
        size_t length_difference;
        bool content_changed;
        bool error_message_appeared;
        bool timing_anomaly;
        double similarity_score;  // 0.0 = completely different, 1.0 = identical
    };

    ComparisonResult compare(
        const HttpResponse& baseline,
        const HttpResponse& test_response
    );

    // Determine if differences indicate vulnerability
    bool indicates_vulnerability(const ComparisonResult& result);

private:
    double compute_similarity(const std::string& s1, const std::string& s2);
};
```

**Usage**:
```cpp
// Get baseline response
HttpRequest normal_req = create_request("normal_value");
HttpResponse baseline = client.perform(normal_req);

// Test with malicious payload
HttpRequest malicious_req = create_request("' OR '1'='1");
HttpResponse test = client.perform(malicious_req);

// Compare
auto comparison = comparator.compare(baseline, test);
if (comparator.indicates_vulnerability(comparison)) {
    // Likely vulnerability detected
}
```

**Files to Create**:
- `src/core/baseline_comparator.h`
- `src/core/baseline_comparator.cpp`

---

### Phase 4.1: Unauthenticated Vulnerabilities (Feasible Now)

**Timeline**: 2-3 weeks

These vulnerabilities can be detected without authentication or session management. Focus on expanding Sentinel's capabilities for public-facing endpoints.

**Note**: SQL Injection, Command Injection, and Path Traversal have been moved to Phase 4.2 because they require Phase 4.0 foundation (session management, response analysis, timing analysis).

#### 1. Information Disclosure Detection
**Priority**: Critical
**Difficulty**: Easy
**CWE**: CWE-89
**OWASP**: A03:2021 - Injection

**Detection Method**:
- Send SQL injection payloads to all input parameters
- Analyze responses for SQL error messages
- Check response timing for blind SQL injection

**Payloads to Test**:
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
1' AND '1'='1
1' AND '1'='2
' OR 1=1#
' OR 1=1--
' OR 'a'='a
' OR 'a'='a'--
```

**Error Patterns**: Handled by ResponseAnalyzer from Phase 4.0

**Implementation**:
- Add `checkSQLInjection()` function to `VulnEngine`
- **Use SessionManager** to maintain authenticated session
- **Use ResponseAnalyzer** to detect SQL error messages
- **Use TimingAnalyzer** for blind SQL injection (SLEEP payloads)
- **Use BaselineComparator** to compare normal vs. malicious responses
- Test all parameters (GET, POST, headers, cookies) in authenticated context

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic (uses Phase 4.0 modules)
- `config/payloads.yaml` - Add SQL injection payloads

---

#### 2. Command Injection Detection
**Priority**: Critical
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-78
**OWASP**: A03:2021 - Injection
**Requires**: Session Management, Response Pattern Analysis, Timing Analysis, Baseline Comparison

**Detection Method**:
- **Requires authenticated session** - Most command injection is behind login
- Send OS command payloads to input parameters
- **Use ResponseAnalyzer** to detect command output (usernames, file listings)
- **Use TimingAnalyzer** for blind command injection (sleep commands)
- **Use BaselineComparator** to detect response differences

**Payloads to Test**:
```bash
; ls
| whoami
$(id)
`id`
& ping -c 10 127.0.0.1
&& sleep 10
|| sleep 10
; sleep 10
| sleep 10
```

**Evidence Patterns**: Handled by ResponseAnalyzer and TimingAnalyzer from Phase 4.0

**Implementation**:
- Add `checkCommandInjection()` function to `VulnEngine`
- **Use SessionManager** to maintain authenticated session
- **Use ResponseAnalyzer** to detect command output patterns
- **Use TimingAnalyzer** for blind command injection (sleep 10 payloads)
- **Use BaselineComparator** to compare normal vs. malicious responses

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic (uses Phase 4.0 modules)
- `config/payloads.yaml` - Add command injection payloads

---

#### 3. Path Traversal Detection
**Priority**: High
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-22
**OWASP**: A01:2021 - Broken Access Control
**Requires**: Session Management (often), Response Pattern Analysis, Baseline Comparison

**Detection Method**:
- **May require authenticated session** - File access often behind login
- Send path traversal payloads in file-related parameters
- **Use ResponseAnalyzer** to detect file contents (passwd, hosts, etc.)
- **Use BaselineComparator** to detect response differences

**Payloads to Test**:
```bash
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2F..%2F..%2Fetc%2fpasswd
```

**Target Files**:
- `/etc/passwd` (Linux/Unix)
- `/etc/shadow` (Linux)
- `/windows/system32/drivers/etc/hosts` (Windows)
- `C:\\Windows\\System32\\config\\sam` (Windows)
- Application config files

**Evidence Patterns**:
- File contents in response (user lists, config data)
- Error messages revealing file paths
- Different response structure indicating file access

**Implementation**:
- Add `checkPathTraversal()` function to `VulnEngine`
- Test file-related parameters (filename, path, file, etc.)
- Detect known file content patterns

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- `config/payloads.yaml` - Add path traversal payloads

---

#### 4. Information Disclosure Detection
**Priority**: High
**Difficulty**: Easy
**CWE**: CWE-209, CWE-532
**OWASP**: A01:2021 - Broken Access Control

**Detection Method**:
- Analyze responses for stack traces, error messages, debug info
- Search for sensitive patterns (file paths, internal IPs, versions)
- Check for verbose error messages

**Patterns to Detect**:
- Stack traces: `at java.lang.`, `at org.apache.`, `Traceback (most recent call last)`
- File paths: `/var/www/`, `C:\\Users\\`, `/home/`, `D:\\`
- Internal IPs: `192.168.`, `10.`, `172.16.`, `127.0.0.1`
- Framework versions: `Django/`, `Rails/`, `PHP/`, `ASP.NET/`
- Database errors: SQL error messages (covered in SQL injection)
- Debug info: `DEBUG`, `TRACE`, `development mode`

**Implementation**:
- Add `checkInformationDisclosure()` function to `VulnEngine`
- Use regex patterns to detect sensitive information
- Analyze response headers for version info
- Check response body for stack traces

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- Create regex patterns file or inline patterns

---

### Phase 4.2: Authenticated Vulnerabilities (Requires Phase 4.0 Foundation)

**Timeline**: 6-8 weeks (after Phase 4.0 completion)

**Prerequisites**: Phase 4.0 must be completed first. These vulnerabilities require:
- Session management (authentication)
- Response pattern analysis (SQL errors, command output)
- Timing analysis (blind injection)
- Baseline comparison (detect anomalies)

#### 1. SQL Injection Detection
**Priority**: Critical
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-89
**OWASP**: A03:2021 - Injection
**Requires**: Session Management, Response Pattern Analysis, Timing Analysis, Baseline Comparison

**Detection Method**:
- **Requires authenticated session** - Most SQL injection is behind login
- Send SQL injection payloads to all input parameters
- Use ResponseAnalyzer to detect SQL error messages
- Use TimingAnalyzer for blind SQL injection detection
- Use BaselineComparator to detect response differences

**Payloads to Test**:
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
1' AND '1'='1
1' AND '1'='2
' OR 1=1#
' OR 1=1--
' OR 'a'='a
' OR 'a'='a'--
```

**Error Patterns**: Handled by ResponseAnalyzer from Phase 4.0

**Implementation**:
- Add `checkSQLInjection()` function to `VulnEngine`
- **Use SessionManager** to maintain authenticated session
- **Use ResponseAnalyzer** to detect SQL error messages
- **Use TimingAnalyzer** for blind SQL injection (SLEEP payloads)
- **Use BaselineComparator** to compare normal vs. malicious responses
- Test all parameters (GET, POST, headers, cookies) in authenticated context

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic (uses Phase 4.0 modules)
- `config/payloads.yaml` - Add SQL injection payloads

---

#### 2. Command Injection Detection
**Priority**: Critical
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-78
**OWASP**: A03:2021 - Injection
**Requires**: Session Management, Response Pattern Analysis, Timing Analysis, Baseline Comparison

**Detection Method**:
- **Requires authenticated session** - Most command injection is behind login
- Send OS command payloads to input parameters
- **Use ResponseAnalyzer** to detect command output (usernames, file listings)
- **Use TimingAnalyzer** for blind command injection (sleep commands)
- **Use BaselineComparator** to detect response differences

**Payloads to Test**:
```bash
; ls
|| whoami
$(id)
`id`
& ping -c 10 127.0.0.1
&& sleep 10
||| sleep 10
; sleep 10
|| sleep 10
```

**Evidence Patterns**: Handled by ResponseAnalyzer and TimingAnalyzer from Phase 4.0

**Implementation**:
- Add `checkCommandInjection()` function to `VulnEngine`
- **Use SessionManager** to maintain authenticated session
- **Use ResponseAnalyzer** to detect command output patterns
- **Use TimingAnalyzer** for blind command injection (sleep 10 payloads)
- **Use BaselineComparator** to compare normal vs. malicious responses

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic (uses Phase 4.0 modules)
- `config/payloads.yaml` - Add command injection payloads

---

#### 3. Path Traversal Detection
**Priority**: High
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-22
**OWASP**: A01:2021 - Broken Access Control
**Requires**: Session Management (often), Response Pattern Analysis, Baseline Comparison

**Detection Method**:
- **May require authenticated session** - File access often behind login
- Send path traversal payloads in file-related parameters
- **Use ResponseAnalyzer** to detect file contents (passwd, hosts, etc.)
- **Use BaselineComparator** to detect response differences

**Payloads to Test**:
```bash
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2F..%2F..%2Fetc%2fpasswd
```

**Target Files**:
- `/etc/passwd` (Linux/Unix)
- `/etc/shadow` (Linux)
- `/windows/system32/drivers/etc/hosts` (Windows)
- `C:\\Windows\\System32\\config\\sam` (Windows)
- Application config files

**Evidence Patterns**: Handled by ResponseAnalyzer from Phase 4.0

**Implementation**:
- Add `checkPathTraversal()` function to `VulnEngine`
- **Use SessionManager** if authentication required
- **Use ResponseAnalyzer** to detect file contents
- **Use BaselineComparator** to compare normal vs. malicious responses
- Test file-related parameters (filename, path, file, etc.)

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic (uses Phase 4.0 modules)
- `config/payloads.yaml` - Add path traversal payloads

---

#### 4. Server-Side Request Forgery (SSRF)
**Priority**: Critical
**Difficulty**: Moderate
**CWE**: CWE-918
**OWASP**: A10:2021 - Server-Side Request Forgery

**Detection Method**:
- Send requests to internal IPs and localhost
- Analyze response timing and content
- Check for out-of-band requests (DNS, HTTP callbacks)

**Payloads to Test**:
```bash
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/
http://192.168.1.1
http://10.0.0.1
http://[::1]
file:///etc/passwd
gopher://127.0.0.1:6379
```

**Evidence Patterns**:
- Internal service responses (metadata, configs)
- Response timing anomalies
- Out-of-band HTTP callbacks
- DNS lookups to controlled domains

**Implementation**:
- Add `checkSSRF()` function to `VulnEngine`
- Test URL parameters (url, redirect, endpoint, etc.)
- Implement out-of-band detection (optional, advanced)
- Measure response times

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- `config/payloads.yaml` - Add SSRF payloads

---

#### 5. XML External Entity (XXE)
**Priority**: High
**Difficulty**: Moderate
**CWE**: CWE-611
**OWASP**: A05:2021 - Security Misconfiguration

**Detection Method**:
- Send XML payloads with external entity references
- Check for file contents or out-of-band requests
- Test for denial of service (billion laughs attack)

**Payloads to Test**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<foo>&xxe;</foo>
```

**Evidence Patterns**:
- File contents in response
- Out-of-band HTTP requests
- Error messages revealing XXE processing

**Implementation**:
- Add `checkXXE()` function to `VulnEngine`
- Detect XML content in requests
- Test XML endpoints and parameters
- Implement out-of-band detection (optional)

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- `config/payloads.yaml` - Add XXE payloads

---

#### 6. Server-Side Template Injection (SSTI)
**Priority**: High
**Difficulty**: Moderate
**CWE**: CWE-94
**OWASP**: A03:2021 - Injection

**Detection Method**:
- Send template injection payloads
- Analyze response for evaluated expressions
- Test different template engines

**Payloads to Test**:
```python
# Jinja2
{{7*7}}
{{config}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Freemarker
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity
#set($x=$class.forName("java.lang.Runtime").getRuntime().exec("id"))
```

**Evidence Patterns**:
- Mathematical expressions evaluated (49 for 7*7)
- Template syntax errors
- Command execution results

**Implementation**:
- Add `checkSSTI()` function to `VulnEngine`
- Test with mathematical expressions first
- Detect template engine based on errors
- Test engine-specific payloads

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- `config/payloads.yaml` - Add SSTI payloads

---

#### 7. Sensitive Data Exposure
**Priority**: High
**Difficulty**: Moderate
**CWE**: CWE-312, CWE-798
**OWASP**: A02:2021 - Cryptographic Failures

**Detection Method**:
- Search responses for sensitive data patterns
- Check for hardcoded credentials
- Detect weak encryption indicators

**Patterns to Detect**:
- Credit cards: `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`
- SSN: `\b\d{3}-\d{2}-\d{4}\b`
- API keys: `api[_-]?key[=:]\s*['"]?[a-zA-Z0-9]{20,}`
- JWT tokens: `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.`
- Passwords: `password[=:]\s*['"]?[^'"]+`
- Private keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`

**Implementation**:
- Add `checkSensitiveDataExposure()` function to `VulnEngine`
- Use regex patterns to detect sensitive data
- Analyze response body and headers
- Check for weak encryption (MD5, SHA1 in hashes)

**Files to Modify**:
- `src/core/vuln_engine.h` - Add function declaration
- `src/core/vuln_engine.cpp` - Implement detection logic
- Create regex patterns file

---

#### 8. Enhanced IDOR Detection
**Priority**: High
**Difficulty**: Moderate (requires Phase 4.0 foundation)
**CWE**: CWE-639
**OWASP**: A01:2021 - Broken Access Control
**Requires**: Session Management (critical), Baseline Comparison

**Detection Method**:
- **Requires authenticated session** - IDOR testing needs user context
- Test parameter enumeration (user IDs, object IDs)
- **Use SessionManager** to test with different user accounts
- **Use BaselineComparator** to detect unauthorized access
- Check for horizontal and vertical privilege escalation

**Implementation**:
- Enhance existing `checkIDOR()` function
- **Use SessionManager** to maintain multiple user sessions
- Test with different user IDs to detect unauthorized access
- **Use BaselineComparator** to compare authorized vs. unauthorized responses

---

### Phase 4.3: Moderate Impact (May Require Phase 4.0)

#### 9. LDAP Injection
**Priority**: Medium
**Difficulty**: Easy
**CWE**: CWE-90
**OWASP**: A03:2021 - Injection

**Detection Method**:
- Send LDAP injection payloads
- Analyze response for LDAP error messages

**Payloads to Test**:
```ldap
*)(&
)(|(&
*))%00
*()|&
```

**Implementation**:
- Add `checkLDAPInjection()` function to `VulnEngine`
- Similar to SQL injection detection
- Look for LDAP error messages

---

#### 10. XPath Injection
**Priority**: Medium
**Difficulty**: Easy
**CWE**: CWE-643
**OWASP**: A03:2021 - Injection

**Detection Method**:
- Send XPath injection payloads
- Analyze response for XPath error messages

**Payloads to Test**:
```xpath
' or '1'='1
' or 1=1 or ''='
' or '1'='1' or 'a'='a
```

**Implementation**:
- Add `checkXPathInjection()` function to `VulnEngine`
- Similar to SQL injection detection
- Look for XPath error messages

---

#### 11. Open Redirect
**Priority**: Medium
**Difficulty**: Easy
**CWE**: CWE-601
**OWASP**: A01:2021 - Broken Access Control

**Detection Method**:
- Test redirect parameters with external domains
- Check for 3xx redirects to external URLs

**Payloads to Test**:
```bash
redirect=http://evil.com
url=https://attacker.com
next=http://malicious.com
goto=http://evil.com
return=http://attacker.com
```

**Implementation**:
- Add `checkOpenRedirect()` function to `VulnEngine`
- Test redirect-related parameters
- Follow redirects and check destination
- Already in `ci_policy.yml` but not implemented

---

#### 12. Directory Listing
**Priority**: Medium
**Difficulty**: Easy
**CWE**: CWE-548
**OWASP**: A05:2021 - Security Misconfiguration

**Detection Method**:
- Request directories without index files
- Check for HTML directory listings

**Implementation**:
- Add `checkDirectoryListing()` function to `VulnEngine`
- Request common directory paths
- Detect HTML directory listing patterns

---

#### 13. Weak Session Management
**Priority**: Medium
**Difficulty**: Moderate
**CWE**: CWE-613, CWE-330
**OWASP**: A07:2021 - Identification and Authentication Failures
**Requires**: Session Management (to analyze sessions)

**Detection Method**:
- **Requires SessionManager** to collect and analyze session tokens
- Analyze session cookies for weak tokens
- Check for predictable session IDs (sequential, time-based)
- Verify session expiration

**Implementation**:
- Add `checkWeakSessionManagement()` function to `VulnEngine`
- Analyze session cookie values
- Check for sequential patterns
- Verify expiration attributes

---

#### 14. Insecure File Upload
**Priority**: Medium
**Difficulty**: Moderate
**CWE**: CWE-434, CWE-73
**OWASP**: A03:2021 - Injection

**Detection Method**:
- Test file upload endpoints
- Try uploading executable file types
- Test path traversal in filenames

**Implementation**:
- Add `checkInsecureFileUpload()` function to `VulnEngine`
- Detect file upload endpoints
- Test various file types
- Check for path traversal in filenames

---

### Phase 4.4: Enhancements to Existing Checks

#### 15. Enhanced XSS Detection
**Current**: Basic reflection detection
**Enhancement**: Better payloads, encoding bypasses

**Improvements**:
- Add more XSS payloads (event handlers, SVG, etc.)
- Test encoding bypasses (URL, HTML, Unicode)
- Detect stored XSS (requires state tracking)
- Test DOM-based XSS (requires JavaScript analysis)

---

#### 16. Enhanced CSRF Detection
**Current**: Basic detection
**Enhancement**: Token validation, SameSite checks

**Improvements**:
- Verify CSRF token presence
- Check token validation
- Verify SameSite cookie attribute
- Test state-changing operations

---

#### 17. Enhanced IDOR Detection
**Current**: Basic detection
**Enhancement**: Better enumeration, parameter manipulation

**Improvements**:
- Test parameter enumeration (user IDs, object IDs)
- Check for horizontal privilege escalation
- Test for vertical privilege escalation
- Verify access control on all endpoints

---

#### 18. HTTP Method Vulnerabilities
**Priority**: Low
**Difficulty**: Easy
**CWE**: CWE-650
**OWASP**: A05:2021 - Security Misconfiguration

**Detection Method**:
- Test dangerous HTTP methods (PUT, DELETE, TRACE, OPTIONS, PATCH)
- Check for TRACE method (reflects request)

**Implementation**:
- Add `checkHTTPMethodVulnerabilities()` function to `VulnEngine`
- Test various HTTP methods
- Check TRACE for request reflection

---

## Implementation Structure

**Important**: All implementation must follow the secure coding principles outlined above. Each vulnerability detection function should:
- Test all trust boundaries (parameters, headers, cookies, body)
- Use diverse input types and encoding schemes
- Verify proper validation and sanitization
- Check for defense in depth
- Handle errors securely without information disclosure

### File Organization

```
src/core/
  vuln_engine.h          - Add function declarations
  vuln_engine.cpp        - Implement detection functions

config/
  payloads.yaml          - Add payloads for each vulnerability type
  error_patterns.yaml    - Regex patterns for error detection (optional)

tests/
  test_vuln_engine.cpp    - Add tests for new detection functions
```

### Function Signature Pattern

```cpp
void VulnEngine::checkVulnerabilityType(
    const CrawlResult& result,
    std::vector<Finding>& findings
) {
    // 1. Extract parameters from result
    // 2. Test each parameter with payloads
    // 3. Analyze responses for evidence
    // 4. Create Finding objects if detected
    // 5. Add to findings vector
}
```

### Finding Structure

```cpp
Finding f;
f.id = "finding_" + std::to_string(findings.size() + 1);
f.url = result.url;
f.category = "vulnerability_type";
f.method = result.method;
f.severity = "high"; // or "medium", "low", "critical"
f.confidence = 0.95; // 0.0 to 1.0
f.evidence = {
    {"parameter", "tested_parameter_name"},
    {"payload", "tested_payload"},
    {"evidence", "what_was_detected"}
};
findings.push_back(std::move(f));
```

## Testing Requirements

For each new vulnerability detection:

1. **Unit Tests**: Test detection logic with known vulnerable responses
2. **Integration Tests**: Test against demo server endpoints
3. **False Positive Tests**: Ensure legitimate responses don't trigger
4. **Performance Tests**: Ensure detection doesn't significantly slow scans

## Accuracy Testing and Optimization

### Overview

To ensure Sentinel provides reliable, actionable security findings, we must systematically test for accuracy, measure performance metrics, and continuously optimize to reduce both false positives and false negatives.

### Accuracy Metrics

For each vulnerability detection, we track:

1. **True Positives (TP)**: Correctly identified vulnerabilities
2. **False Positives (FP)**: Incorrectly flagged as vulnerable (safe code flagged)
3. **True Negatives (TN)**: Correctly identified as safe
4. **False Negatives (FN)**: Missed vulnerabilities (vulnerable code not detected)

**Key Metrics**:
- **Precision** = TP / (TP + FP) - How many flagged issues are actually vulnerabilities?
- **Recall** = TP / (TP + FN) - How many vulnerabilities did we catch?
- **F1 Score** = 2 × (Precision × Recall) / (Precision + Recall) - Balanced metric
- **Accuracy** = (TP + TN) / (TP + TN + FP + FN) - Overall correctness

**Target Goals**:
- Precision: ≥ 90% (minimize false positives)
- Recall: ≥ 85% (minimize false negatives)
- F1 Score: ≥ 87% (balanced performance)

### Testing Methodology

#### 1. Benchmark Applications

Use known vulnerable applications for testing:

**Web Application Security Testing Targets**:
- **DVWA (Damn Vulnerable Web Application)**: https://github.com/digininja/DVWA
  - Contains SQL injection, XSS, command injection, file upload, etc.
  - Known vulnerabilities with documented locations

- **WebGoat**: https://github.com/WebGoat/WebGoat
  - OWASP-maintained vulnerable application
  - Comprehensive vulnerability coverage

- **VulnHub VMs**: https://www.vulnhub.com/
  - Real-world vulnerable systems
  - Various difficulty levels

- **OWASP Juice Shop**: https://github.com/juice-shop/juice-shop
  - Modern vulnerable web application
  - REST API vulnerabilities

**Custom Test Fixtures**:
- Create controlled test endpoints in `apps/demo_server/`
- Known vulnerable patterns for each vulnerability type
- Known safe patterns that should not trigger

#### 2. Test Case Structure

For each vulnerability type, create test cases:

```yaml
# Example: test_cases/sql_injection.yaml
test_cases:
  - name: "Basic SQL Injection - MySQL"
    endpoint: "/api/users"
    method: "GET"
    parameters:
      id: "1' OR '1'='1"
    expected_result: "vulnerable"
    expected_evidence: "mysql_fetch"
    confidence: 0.95

  - name: "SQL Injection - False Positive Check"
    endpoint: "/api/search"
    method: "GET"
    parameters:
      query: "user's guide"
    expected_result: "safe"
    expected_evidence: null
    confidence: 0.0

  - name: "Blind SQL Injection"
    endpoint: "/api/products"
    method: "GET"
    parameters:
      id: "1' AND SLEEP(5)--"
    expected_result: "vulnerable"
    expected_evidence: "timing_anomaly"
    confidence: 0.85
```

#### 3. Automated Testing Framework

Create a testing framework that:

```cpp
// tests/test_accuracy.cpp
class AccuracyTest {
public:
    struct TestResult {
        std::string test_name;
        bool expected_vulnerable;
        bool detected_vulnerable;
        double confidence;
        std::string evidence;
    };

    void runTestSuite(const std::string& vulnerability_type);
    void generateReport(const std::vector<TestResult>& results);
    void calculateMetrics(const std::vector<TestResult>& results);
};
```

**Test Execution**:
1. Load test cases from YAML/JSON files
2. Run Sentinel against test endpoints
3. Compare results with expected outcomes
4. Calculate precision, recall, F1 score
5. Generate detailed accuracy report

#### 4. Continuous Testing

**Pre-Commit Testing**:
- Run accuracy tests before each commit
- Fail CI if precision/recall drops below thresholds
- Track metrics over time

**Regression Testing**:
- Maintain test suite of known vulnerabilities
- Ensure new changes don't break existing detection
- Track false positive/negative rates over time

### False Positive Reduction Strategies

False positives waste developer time and reduce trust in the tool.

#### 1. Evidence Validation

**Require Multiple Indicators**:
- Don't rely on single evidence pattern
- Require combination of: payload reflection + error message + timing anomaly
- Increase confidence threshold for single-indicator findings

**Example**:
```cpp
// Good: Multiple evidence indicators
if (sql_error_detected && payload_reflected && timing_anomaly) {
    confidence = 0.95;
} else if (sql_error_detected && payload_reflected) {
    confidence = 0.75;  // Lower confidence
} else if (sql_error_detected) {
    confidence = 0.50;  // Much lower confidence
    // Consider not reporting unless severity is high
}
```

#### 2. Context-Aware Detection

**Understand Application Context**:
- Distinguish between user content and application errors
- Recognize legitimate uses of special characters (e.g., "user's guide" is not SQL injection)
- Check if error messages are from the application or the database

**Example**:
```cpp
// Check if SQL error is from application framework or actual database
if (response_contains("SQLException") &&
    response_contains("at com.example") &&
    !response_contains("mysql_fetch")) {
    // Likely application error handling, not SQL injection
    confidence = 0.30;
}
```

#### 3. Whitelist Known Safe Patterns

**Maintain Whitelist**:
- Common safe patterns that trigger false positives
- Legitimate uses of special characters
- Known false positive patterns from testing

**Example**:
```cpp
// Whitelist common false positives
std::vector<std::string> safe_patterns = {
    "user's guide",      // Apostrophe in content
    "O'Brien",          // Name with apostrophe
    "C++",              // Programming language reference
    "file:///",         // Legitimate file protocol
};
```

#### 4. Confidence Scoring

**Multi-Factor Confidence**:
- Base confidence on multiple factors
- Lower confidence for ambiguous findings
- Only report high-confidence findings by default

**Confidence Factors**:
- Error message clarity (0.0 - 0.3)
- Payload reflection (0.0 - 0.2)
- Timing anomaly (0.0 - 0.2)
- Response structure change (0.0 - 0.1)
- Multiple indicators (0.0 - 0.2)

#### 5. Manual Review Flagging

**Flag Low-Confidence Findings**:
- Mark findings with confidence < 0.70 as "needs review"
- Provide detailed evidence for manual verification
- Allow users to mark false positives for learning

### False Negative Reduction Strategies

False negatives leave vulnerabilities undetected, creating security risks.

#### 1. Comprehensive Payload Library

**Diverse Payloads**:
- Multiple payloads for each vulnerability type
- Different encoding schemes
- Various bypass techniques
- Framework-specific payloads

**Example**:
```yaml
sql_injection_payloads:
  basic:
    - "' OR '1'='1"
    - "' OR '1'='1' --"
    - "' OR '1'='1' /*"
  encoded:
    - "%27%20OR%20%271%27%3D%271"
    - "%27%20OR%20%271%27%3D%271%27%20--"
  time_based:
    - "1' AND SLEEP(5)--"
    - "1'; WAITFOR DELAY '00:00:05'--"
  union_based:
    - "' UNION SELECT NULL--"
    - "' UNION SELECT NULL,NULL--"
```

#### 2. Multiple Detection Methods

**Layered Detection**:
- Error-based detection (error messages)
- Time-based detection (timing anomalies)
- Boolean-based detection (response differences)
- Union-based detection (data extraction)

**Example**:
```cpp
void checkSQLInjection(const CrawlResult& result, std::vector<Finding>& findings) {
    // Try multiple detection methods
    if (checkErrorBasedSQL(result, findings)) return;
    if (checkTimeBasedSQL(result, findings)) return;
    if (checkBooleanBasedSQL(result, findings)) return;
    if (checkUnionBasedSQL(result, findings)) return;
}
```

#### 3. Response Analysis

**Deep Response Analysis**:
- Compare responses with and without payloads
- Detect subtle differences (response length, structure, timing)
- Analyze response headers for anomalies
- Check for out-of-band indicators

#### 4. Parameter Enumeration

**Test All Input Points**:
- URL parameters (GET)
- POST body parameters
- HTTP headers
- Cookies
- JSON/XML body fields
- File upload fields

**Example**:
```cpp
// Test all discovered parameters
for (const auto& param : result.params) {
    testSQLInjection(result.url, param.first, param.second, findings);
}
for (const auto& header : result.headers) {
    if (isUserControlled(header.first)) {
        testSQLInjection(result.url, header.first, header.second, findings);
    }
}
```

#### 5. Continuous Learning

**Learn from Missed Vulnerabilities**:
- Track vulnerabilities found by other tools but missed by Sentinel
- Analyze why they were missed
- Update payloads and detection logic
- Maintain database of missed vulnerabilities

### Optimization Strategies

#### 1. Performance Optimization

**Efficient Detection**:
- Cache compiled regex patterns
- Reuse HTTP connections
- Parallelize independent tests
- Skip redundant tests

**Example**:
```cpp
// Cache compiled regex patterns
static std::regex sql_error_pattern = std::regex(
    "mysql_fetch|PostgreSQL|SQL Server|ORA-",
    std::regex_constants::icase
);

// Reuse HTTP client
HttpClient client;
for (const auto& payload : payloads) {
    auto response = client.get(url + "?id=" + payload);
    // Analyze response
}
```

#### 2. Smart Test Ordering

**Prioritize High-Value Tests**:
- Test common vulnerabilities first
- Test high-severity issues first
- Skip tests if prerequisites fail
- Early exit on high-confidence findings

**Example**:
```cpp
// Test in order of likelihood and severity
if (testSQLInjection(result, findings)) {
    // High confidence finding, can skip other injection tests
    return;
}
if (testCommandInjection(result, findings)) {
    return;
}
// Continue with other tests...
```

#### 3. Adaptive Testing

**Adjust Based on Application**:
- Detect application framework
- Use framework-specific payloads
- Skip irrelevant tests
- Focus on likely vulnerabilities

**Example**:
```cpp
// Detect framework
Framework framework = detectFramework(response);
if (framework == Framework::PHP) {
    testPHPInjection(result, findings);
} else if (framework == Framework::JAVA) {
    testJavaInjection(result, findings);
}
```

#### 4. Resource Management

**Limit Resource Usage**:
- Set timeouts for all requests
- Limit concurrent requests
- Rate limit to avoid DoS
- Clean up resources properly

### Testing Infrastructure

#### 1. Test Data Management

**Structured Test Data**:
```yaml
# tests/fixtures/vulnerabilities.yaml
vulnerabilities:
  sql_injection:
    - name: "DVWA SQL Injection"
      url: "http://dvwa.local/vulnerabilities/sqli/"
      parameters:
        id: "1' OR '1'='1"
      expected_finding:
        category: "sql_injection"
        confidence: 0.95
        evidence: "mysql_fetch"

  command_injection:
    - name: "DVWA Command Injection"
      url: "http://dvwa.local/vulnerabilities/exec/"
      parameters:
        ip: "; ls"
      expected_finding:
        category: "command_injection"
        confidence: 0.90
        evidence: "command_output"
```

#### 2. Automated Accuracy Reports

**Generate Reports**:
```cpp
// Generate accuracy report after test run
void generateAccuracyReport(const TestResults& results) {
    std::cout << "=== Accuracy Report ===" << std::endl;
    std::cout << "Precision: " << results.precision << std::endl;
    std::cout << "Recall: " << results.recall << std::endl;
    std::cout << "F1 Score: " << results.f1_score << std::endl;
    std::cout << "False Positives: " << results.false_positives << std::endl;
    std::cout << "False Negatives: " << results.false_negatives << std::endl;

    // Detailed breakdown by vulnerability type
    for (const auto& vuln_type : results.by_type) {
        std::cout << vuln_type.first << ": "
                  << "P=" << vuln_type.second.precision
                  << " R=" << vuln_type.second.recall << std::endl;
    }
}
```

#### 3. Continuous Monitoring

**Track Metrics Over Time**:
- Store accuracy metrics in database
- Track trends (improving/degrading)
- Alert on significant changes
- Generate weekly/monthly reports

### Implementation Checklist

For each new vulnerability detection:

- [ ] Create test cases with known vulnerable endpoints
- [ ] Create test cases with safe endpoints (false positive tests)
- [ ] Run accuracy tests and calculate metrics
- [ ] Achieve target precision (≥90%) and recall (≥85%)
- [ ] Document false positive patterns and add to whitelist
- [ ] Document false negative patterns and update payloads
- [ ] Add performance benchmarks
- [ ] Create regression tests
- [ ] Update accuracy documentation

### Accuracy Testing Tools

**Recommended Tools**:
- **Custom Test Framework**: Build in C++ using Catch2
- **Test Data**: YAML/JSON test case files
- **Benchmark Apps**: DVWA, WebGoat, Juice Shop
- **Metrics Tracking**: SQLite database for historical data
- **Reporting**: Generate HTML/JSON accuracy reports

### Success Criteria

Accuracy testing is successful when:

1. ✅ All vulnerability detections have ≥90% precision
2. ✅ All vulnerability detections have ≥85% recall
3. ✅ False positive rate < 5%
4. ✅ False negative rate < 10%
5. ✅ Accuracy metrics tracked over time
6. ✅ Regression tests prevent accuracy degradation
7. ✅ Performance benchmarks meet targets (< 2x scan time increase)

## Mathematical Optimization Framework

### Overview and Objectives

The mathematical optimization framework uses TensorFlow C++ API to optimize Sentinel's detection parameters and risk budget hyperparameters through gradient descent with automatic differentiation. This enables data-driven tuning of detection thresholds, pattern matching weights, and risk scoring to minimize false positives and false negatives while maintaining optimal performance.

**Primary Objectives**:
- Optimize detection confidence thresholds to balance precision and recall
- Learn optimal pattern matching weights for error detection
- Tune risk budget hyperparameters (category scores, warn/block thresholds) for effective CI/CD gating
- Optimize payload effectiveness to prioritize high-value test payloads
- Use gradient descent with automatic differentiation (no neural networks in initial implementation)

**Key Benefits**:
- Data-driven parameter tuning based on test dataset performance
- Automatic optimization of multi-objective loss functions
- Continuous improvement as test data grows
- Mathematical rigor in parameter selection

### TensorFlow C++ Integration

**Requirements**:
- TensorFlow C++ API (libtensorflow_cc.so or TensorFlow C++ shared library)
- CMake integration for finding and linking TensorFlow
- C++17 compatible code (existing standard)

**Installation**:
```bash
# Download TensorFlow C++ library
# Option 1: Build from source (recommended for production)
# Option 2: Use pre-built binaries from TensorFlow releases

# Example: Download TensorFlow 2.x C++ library
wget https://storage.googleapis.com/tensorflow/libtensorflow/libtensorflow-cpu-linux-x86_64-2.x.x.tar.gz
tar -xzf libtensorflow-cpu-linux-x86_64-2.x.x.tar.gz
```

**CMake Integration**:
```cmake
# Find TensorFlow C++ library
find_path(TENSORFLOW_INCLUDE_DIR
    NAMES tensorflow/cc/client/client_session.h
    PATHS /usr/local/include
          ${CMAKE_SOURCE_DIR}/third_party/tensorflow/include
)

find_library(TENSORFLOW_LIB
    NAMES tensorflow_cc tensorflow_framework
    PATHS /usr/local/lib
          ${CMAKE_SOURCE_DIR}/third_party/tensorflow/lib
)

if(NOT TENSORFLOW_INCLUDE_DIR OR NOT TENSORFLOW_LIB)
    message(FATAL_ERROR "TensorFlow C++ library not found")
endif()

# Add optimization library
add_library(optimization
    src/optimization/optimizer.cpp
    src/optimization/loss_functions.cpp
    src/optimization/tensor_utils.cpp
    src/optimization/parameter_space.cpp
    src/optimization/gradient_descent.cpp
)

target_include_directories(optimization PUBLIC
    src/optimization
    ${TENSORFLOW_INCLUDE_DIR}
)

target_link_libraries(optimization PUBLIC
    ${TENSORFLOW_LIB}
    nlohmann_json::nlohmann_json
)
```

**File Structure**:
```
src/optimization/
  ├── optimizer.h/cpp          - Main optimization framework
  ├── loss_functions.h/cpp      - Loss function definitions using TensorFlow
  ├── tensor_utils.h/cpp        - Matrix/vector operations
  ├── parameter_space.h/cpp    - Parameter bounds and constraints
  └── gradient_descent.h/cpp    - Gradient descent implementation
```

### Optimization Targets

The framework optimizes four categories of parameters:

#### 1. Detection Confidence Thresholds
- **Type**: Continuous, differentiable (float values 0.0-1.0)
- **Parameters**: Per-vulnerability-type confidence thresholds
- **Example**: `confidence_threshold_sql_injection = 0.75`
- **Impact**: Controls when findings are reported (affects precision/recall tradeoff)

#### 2. Pattern Matching Weights
- **Type**: Continuous, differentiable (float weights)
- **Parameters**:
  - Error pattern weights (SQL error patterns, command output patterns, etc.)
  - Evidence correlation weights (multiple indicators boost confidence)
- **Example**: `sql_error_pattern_weight = 0.3`, `timing_anomaly_weight = 0.2`
- **Impact**: Determines how different evidence types contribute to confidence scores

#### 3. Risk Budget Hyperparameters
- **Type**: Continuous (relaxed), then rounded to integers
- **Parameters**:
  - Category scores: `category_scores[vulnerability_type]`
  - Warning threshold: `warn_threshold`
  - Block threshold: `block_threshold`
- **Constraints**:
  - `block_threshold > warn_threshold`
  - `category_scores[i] > 0` for all i
- **Impact**: Determines CI/CD gating behavior and risk prioritization

#### 4. Payload Effectiveness Scores
- **Type**: Continuous, differentiable (float scores 0.0-1.0)
- **Parameters**: Matrix of payload effectiveness: `effectiveness[payload_id][vulnerability_type]`
- **Example**: `effectiveness["sql_or_1_equals_1"]["sql_injection"] = 0.92`
- **Impact**: Prioritizes high-performing payloads, reduces test time

### Loss Function Design

The optimization uses a multi-objective loss function that combines multiple metrics:

**Mathematical Formulation**:

```
L(θ) = α·L_FP(θ) + β·L_FN(θ) + γ·L_F1(θ) + δ·L_budget(θ) + ε·L_constraints(θ)
```

Where:
- `θ` = parameter vector (confidence thresholds, weights, category scores, etc.)
- `L_FP` = False positive loss (weighted by α)
- `L_FN` = False negative loss (weighted by β)
- `L_F1` = F1 score loss (inverted, weighted by γ)
- `L_budget` = Risk budget alignment loss (weighted by δ)
- `L_constraints` = Constraint violation penalty (weighted by ε)

**Component Definitions**:

1. **False Positive Loss**:
   ```
   L_FP(θ) = FP_count(θ) / Total_test_cases
   ```
   Penalizes incorrectly flagged safe code.

2. **False Negative Loss**:
   ```
   L_FN(θ) = FN_count(θ) / Total_vulnerabilities
   ```
   Penalizes missed vulnerabilities.

3. **F1 Score Loss**:
   ```
   L_F1(θ) = 1.0 - F1_score(θ)
   F1_score(θ) = 2 × (Precision(θ) × Recall(θ)) / (Precision(θ) + Recall(θ))
   ```
   Maximizes balanced precision/recall.

4. **Risk Budget Alignment Loss**:
   ```
   L_budget(θ) = |Actual_block_rate(θ) - Target_block_rate|²
   ```
   Ensures risk budget thresholds align with desired CI/CD blocking behavior.

5. **Constraint Penalty**:
   ```
   L_constraints(θ) = Σ max(0, -constraint_i(θ))²
   ```
   Penalizes constraint violations (e.g., block_threshold ≤ warn_threshold).

**TensorFlow Implementation**:

```cpp
// Example loss function computation using TensorFlow
tensorflow::Tensor compute_loss(
    const tensorflow::Tensor& predictions,
    const tensorflow::Tensor& ground_truth,
    const tensorflow::Tensor& parameters
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();

    // Compute TP, FP, FN, TN
    auto tp = Equal(predictions, ground_truth);
    auto fp = Greater(predictions, ground_truth);  // Predicted 1, actual 0
    auto fn = Less(predictions, ground_truth);     // Predicted 0, actual 1

    // False positive rate
    auto fp_rate = ReduceMean(Cast(fp, DT_FLOAT));

    // False negative rate
    auto fn_rate = ReduceMean(Cast(fn, DT_FLOAT));

    // Precision and recall
    auto precision = ReduceMean(Cast(tp, DT_FLOAT)) /
                     (ReduceMean(Cast(tp, DT_FLOAT)) + fp_rate + 1e-8);
    auto recall = ReduceMean(Cast(tp, DT_FLOAT)) /
                  (ReduceMean(Cast(tp, DT_FLOAT)) + fn_rate + 1e-8);

    // F1 score
    auto f1 = 2.0 * (precision * recall) / (precision + recall + 1e-8);
    auto f1_loss = 1.0 - f1;

    // Combined loss
    auto total_loss = alpha * fp_rate + beta * fn_rate + gamma * f1_loss;

    // Execute computation
    ClientSession session(root);
    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({total_loss}, &outputs));

    return outputs[0];
}
```

**Weight Selection**:
- Default: `α = 0.3`, `β = 0.3`, `γ = 0.3`, `δ = 0.05`, `ε = 0.05`
- Adjustable based on organizational priorities (precision vs. recall vs. budget alignment)

### Gradient Descent Implementation

**Automatic Differentiation Setup**:

TensorFlow's automatic differentiation computes gradients automatically:

```cpp
#include <tensorflow/cc/client/client_session.h>
#include <tensorflow/cc/ops/standard_ops.h>
#include <tensorflow/core/framework/tensor.h>

class GradientDescentOptimizer {
private:
    tensorflow::Scope root_;
    tensorflow::ClientSession session_;
    std::vector<tensorflow::Output> parameters_;
    tensorflow::Output loss_;
    tensorflow::Output gradients_;
    float learning_rate_;

public:
    GradientDescentOptimizer(float initial_lr = 0.01)
        : root_(tensorflow::Scope::NewRootScope()),
          session_(root_),
          learning_rate_(initial_lr) {}

    void setup_optimization(
        const std::vector<tensorflow::Output>& parameters,
        const tensorflow::Output& loss
    ) {
        parameters_ = parameters;
        loss_ = loss;

        // Compute gradients using automatic differentiation
        std::vector<tensorflow::Output> grad_outputs;
        TF_CHECK_OK(tensorflow::AddSymbolicGradients(
            root_, {loss_}, parameters_, &grad_outputs
        ));
        gradients_ = grad_outputs;
    }

    void step() {
        // Gradient descent update: θ = θ - α·∇L(θ)
        using namespace tensorflow::ops;

        std::vector<tensorflow::Output> updates;
        for (size_t i = 0; i < parameters_.size(); ++i) {
            auto grad = gradients_[i];
            auto update = Sub(parameters_[i],
                            Mul(Const(root_, learning_rate_), grad));
            updates.push_back(update);
        }

        // Apply updates
        std::vector<tensorflow::Tensor> outputs;
        TF_CHECK_OK(session.Run(updates, &outputs));
    }
};
```

**Parameter Initialization**:

```cpp
// Initialize parameters with reasonable defaults
tensorflow::Tensor init_confidence_thresholds() {
    // Start with current values from VulnEngine
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_vuln_types}));
    auto matrix = tensor.matrix<float>();

    matrix(0, 0) = 0.70;  // sql_injection
    matrix(0, 1) = 0.70;  // command_injection
    matrix(0, 2) = 0.75;  // path_traversal
    // ... initialize all thresholds

    return tensor;
}

tensorflow::Tensor init_category_scores() {
    // Start with current policy values
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_categories}));
    auto matrix = tensor.matrix<float>();

    matrix(0, 0) = 10.0;  // sql_injection
    matrix(0, 1) = 10.0;  // command_injection
    matrix(0, 2) = 6.0;   // path_traversal
    // ... initialize all scores

    return tensor;
}
```

**Learning Rate Scheduling**:

```cpp
class LearningRateScheduler {
public:
    virtual float get_learning_rate(int iteration) = 0;
};

class ExponentialDecayScheduler : public LearningRateScheduler {
private:
    float initial_lr_;
    float decay_rate_;
    int decay_steps_;

public:
    ExponentialDecayScheduler(float initial, float decay, int steps)
        : initial_lr_(initial), decay_rate_(decay), decay_steps_(steps) {}

    float get_learning_rate(int iteration) override {
        return initial_lr_ * std::pow(decay_rate_,
                                      iteration / decay_steps_);
    }
};

// Example: Start at 0.01, decay by 0.95 every 100 iterations
auto scheduler = ExponentialDecayScheduler(0.01, 0.95, 100);
```

**Convergence Criteria**:

```cpp
bool check_convergence(
    const std::vector<float>& loss_history,
    float tolerance = 1e-5,
    int patience = 10
) {
    if (loss_history.size() < patience + 1) return false;

    // Check if loss has stopped improving
    float recent_avg = std::accumulate(
        loss_history.end() - patience, loss_history.end(), 0.0f
    ) / patience;

    float previous_avg = std::accumulate(
        loss_history.end() - 2*patience,
        loss_history.end() - patience, 0.0f
    ) / patience;

    return std::abs(recent_avg - previous_avg) < tolerance;
}
```

**Batch Processing**:

```cpp
void optimize_with_batches(
    GradientDescentOptimizer& optimizer,
    const std::vector<TestCase>& test_dataset,
    int batch_size = 32,
    int max_iterations = 1000
) {
    for (int iter = 0; iter < max_iterations; ++iter) {
        // Shuffle and batch dataset
        auto batches = create_batches(test_dataset, batch_size);

        float total_loss = 0.0;
        for (const auto& batch : batches) {
            // Compute loss for batch
            auto loss = compute_loss_batch(batch, optimizer.get_parameters());
            total_loss += loss.scalar<float>()();

            // Update gradients and step
            optimizer.compute_gradients(loss);
            optimizer.step();
        }

        float avg_loss = total_loss / batches.size();
        loss_history_.push_back(avg_loss);

        // Check convergence
        if (check_convergence(loss_history_)) {
            std::cout << "Converged at iteration " << iter << std::endl;
            break;
        }
    }
}
```

### Matrix and Vector Operations

**Tensor Representation of Detection Results**:

Detection results are represented as tensors for efficient matrix operations:

```cpp
// Represent detection results as a matrix
// Rows: test cases, Columns: vulnerability types
tensorflow::Tensor create_detection_matrix(
    const std::vector<DetectionResult>& results,
    int num_vuln_types
) {
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({
                                  static_cast<int>(results.size()),
                                  num_vuln_types
                              }));

    auto matrix = tensor.matrix<float>();
    for (size_t i = 0; i < results.size(); ++i) {
        for (int j = 0; j < num_vuln_types; ++j) {
            // 1.0 if detected, 0.0 if not, confidence value if partial
            matrix(i, j) = results[i].detected[j] ?
                          results[i].confidence[j] : 0.0f;
        }
    }

    return tensor;
}
```

**Pattern Matching Weight Matrix**:

```cpp
// Weight matrix: evidence_type × vulnerability_type
// Determines how much each evidence type contributes to each vulnerability
tensorflow::Tensor create_pattern_weight_matrix() {
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_evidence_types,
                                                       num_vuln_types}));
    auto matrix = tensor.matrix<float>();

    // Example: SQL error pattern weight for SQL injection
    matrix(0, 0) = 0.3;  // sql_error → sql_injection
    matrix(1, 0) = 0.2;  // timing_anomaly → sql_injection
    matrix(2, 0) = 0.1;  // payload_reflection → sql_injection

    // Example: Command output pattern weight for command injection
    matrix(0, 1) = 0.1;  // sql_error → command_injection (low)
    matrix(3, 1) = 0.4;  // command_output → command_injection (high)
    matrix(1, 1) = 0.2;  // timing_anomaly → command_injection

    return tensor;
}
```

**Evidence Correlation Matrix**:

```cpp
// Correlation matrix: evidence_type × evidence_type
// Captures how evidence types correlate (e.g., SQL error + timing = stronger signal)
tensorflow::Tensor create_evidence_correlation_matrix() {
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_evidence_types,
                                                       num_evidence_types}));
    auto matrix = tensor.matrix<float>();

    // Identity matrix (no correlation) as baseline
    for (int i = 0; i < num_evidence_types; ++i) {
        for (int j = 0; j < num_evidence_types; ++j) {
            matrix(i, j) = (i == j) ? 1.0f : 0.0f;
        }
    }

    // Add correlations (learned or manually set)
    matrix(0, 1) = 0.3;  // SQL error correlates with timing anomaly
    matrix(1, 0) = 0.3;  // Symmetric

    return tensor;
}
```

**Payload Effectiveness Matrix**:

```cpp
// Effectiveness matrix: payload_id × vulnerability_type
// Learned through optimization: which payloads work best for which vulnerabilities
tensorflow::Tensor create_payload_effectiveness_matrix() {
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_payloads,
                                                       num_vuln_types}));
    auto matrix = tensor.matrix<float>();

    // Initialize with uniform distribution or prior knowledge
    float initial_value = 1.0f / num_payloads;
    for (int i = 0; i < num_payloads; ++i) {
        for (int j = 0; j < num_vuln_types; ++j) {
            matrix(i, j) = initial_value;
        }
    }

    return tensor;
}
```

**Vector Calculus Operations**:

```cpp
// Gradient computation using TensorFlow automatic differentiation
tensorflow::Tensor compute_gradient(
    const tensorflow::Output& loss,
    const tensorflow::Output& parameter
) {
    using namespace tensorflow;

    Scope root = Scope::NewRootScope();
    std::vector<Output> grad_outputs;

    // Automatic differentiation
    TF_CHECK_OK(AddSymbolicGradients(root, {loss}, {parameter}, &grad_outputs));

    ClientSession session(root);
    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run(grad_outputs, &outputs));

    return outputs[0];
}

// Parameter update using gradient descent
tensorflow::Tensor update_parameters(
    const tensorflow::Tensor& parameters,
    const tensorflow::Tensor& gradients,
    float learning_rate
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // θ_new = θ_old - α·∇L(θ)
    auto lr_tensor = Const(root, learning_rate);
    auto scaled_grad = Mul(root, lr_tensor, gradients);
    auto updated = Sub(root, parameters, scaled_grad);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({updated}, &outputs));

    return outputs[0];
}

// Constraint projection (e.g., ensure parameters stay in valid range)
tensorflow::Tensor project_to_constraints(
    const tensorflow::Tensor& parameters,
    float min_value,
    float max_value
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // Clip values to [min_value, max_value]
    auto min_tensor = Const(root, min_value);
    auto max_tensor = Const(root, max_value);
    auto clipped = ClipByValue(root, parameters, min_tensor, max_tensor);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({clipped}, &outputs));

    return outputs[0];
}
```

**Matrix Operations for Detection Analysis**:

```cpp
// Compute confidence scores using matrix multiplication
// confidence = detection_matrix × pattern_weight_matrix
tensorflow::Tensor compute_confidence_scores(
    const tensorflow::Tensor& detection_matrix,
    const tensorflow::Tensor& pattern_weights
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // Matrix multiplication: [N × E] × [E × V] = [N × V]
    // N = num test cases, E = num evidence types, V = num vuln types
    auto confidence = MatMul(root, detection_matrix, pattern_weights);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({confidence}, &outputs));

    return outputs[0];
}

// Compute correlation-weighted evidence
tensorflow::Tensor apply_evidence_correlation(
    const tensorflow::Tensor& evidence_vector,
    const tensorflow::Tensor& correlation_matrix
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // Weighted evidence: correlated = evidence × correlation_matrix
    auto correlated = MatMul(root, evidence_vector, correlation_matrix);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({correlated}, &outputs));

    return outputs[0];
}
```

### Risk Budget Hyperparameter Tuning

**Continuous Relaxation Approach**:

Since category scores must be integers, we use continuous relaxation during optimization, then round:

```cpp
class RiskBudgetOptimizer {
private:
    tensorflow::Tensor category_scores_;      // Continuous (float)
    tensorflow::Tensor warn_threshold_;       // Continuous (float)
    tensorflow::Tensor block_threshold_;     // Continuous (float)

public:
    // Optimize with continuous values
    void optimize_continuous(const std::vector<TestResult>& test_data) {
        // Set up optimization with continuous parameters
        auto loss = compute_budget_loss(test_data);

        // Gradient descent on continuous values
        GradientDescentOptimizer optimizer(0.01);
        optimizer.setup_optimization(
            {category_scores_, warn_threshold_, block_threshold_},
            loss
        );

        for (int i = 0; i < max_iterations; ++i) {
            optimizer.step();

            // Project to constraints
            category_scores_ = project_to_constraints(
                category_scores_, 0.0f, 20.0f
            );
            warn_threshold_ = project_to_constraints(
                warn_threshold_, 1.0f, 50.0f
            );
            block_threshold_ = project_to_constraints(
                block_threshold_, warn_threshold_.scalar<float>()() + 1.0f, 50.0f
            );
        }
    }

    // Round to integers for final policy
    Policy get_rounded_policy() {
        Policy policy;

        auto scores_matrix = category_scores_.matrix<float>();
        for (int i = 0; i < num_categories; ++i) {
            policy.category_scores[category_names[i]] =
                static_cast<int>(std::round(scores_matrix(0, i)));
        }

        policy.warn_threshold = static_cast<int>(
            std::round(warn_threshold_.scalar<float>()())
        );
        policy.block_threshold = static_cast<int>(
            std::round(block_threshold_.scalar<float>()())
        );

        // Ensure constraints still hold after rounding
        if (policy.block_threshold <= policy.warn_threshold) {
            policy.block_threshold = policy.warn_threshold + 1;
        }

        return policy;
    }
};
```

**Multi-Objective Optimization**:

Balance precision, recall, and budget effectiveness:

```cpp
tensorflow::Tensor compute_budget_loss(
    const std::vector<TestResult>& test_data,
    const tensorflow::Tensor& category_scores,
    const tensorflow::Tensor& warn_threshold,
    const tensorflow::Tensor& block_threshold
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();

    // Compute risk scores for all test cases
    auto risk_scores = compute_risk_scores(test_data, category_scores);

    // Compute precision and recall
    auto metrics = compute_precision_recall(test_data, risk_scores,
                                           warn_threshold, block_threshold);

    // Budget alignment: how well do thresholds match desired behavior?
    auto target_block_rate = Const(root, 0.15f);  // Want to block 15% of scans
    auto actual_block_rate = metrics.block_rate;
    auto budget_alignment_loss = Square(root,
        Sub(root, actual_block_rate, target_block_rate));

    // Combined loss
    auto precision_loss = Sub(root, Const(root, 1.0f), metrics.precision);
    auto recall_loss = Sub(root, Const(root, 1.0f), metrics.recall);

    auto total_loss = Add(root,
        Add(root, Mul(root, Const(root, 0.4f), precision_loss),
                   Mul(root, Const(root, 0.4f), recall_loss)),
        Mul(root, Const(root, 0.2f), budget_alignment_loss));

    ClientSession session(root);
    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({total_loss}, &outputs));

    return outputs[0];
}
```

**Constraint Handling**:

```cpp
// Ensure block_threshold > warn_threshold
tensorflow::Tensor enforce_threshold_constraint(
    const tensorflow::Tensor& warn_threshold,
    const tensorflow::Tensor& block_threshold
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // Project: if block <= warn, set block = warn + 1
    auto min_block = Add(root, warn_threshold, Const(root, 1.0f));
    auto enforced_block = Maximum(root, block_threshold, min_block);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({enforced_block}, &outputs));

    return outputs[0];
}

// Ensure all category scores are positive
tensorflow::Tensor enforce_positive_scores(
    const tensorflow::Tensor& category_scores
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();
    ClientSession session(root);

    // Clip to minimum value of 1.0
    auto min_score = Const(root, 1.0f);
    auto enforced = Maximum(root, category_scores, min_score);

    std::vector<Tensor> outputs;
    TF_CHECK_OK(session.Run({enforced}, &outputs));

    return outputs[0];
}
```

### Payload Effectiveness Optimization

**Matrix Representation**:

```cpp
// Payload effectiveness matrix: [num_payloads × num_vuln_types]
// Learned value: effectiveness[payload_i][vuln_type_j] = success rate
tensorflow::Tensor create_payload_effectiveness_matrix(int num_payloads,
                                                       int num_vuln_types) {
    tensorflow::Tensor tensor(tensorflow::DT_FLOAT,
                              tensorflow::TensorShape({num_payloads,
                                                       num_vuln_types}));
    auto matrix = tensor.matrix<float>();

    // Initialize with uniform or prior knowledge
    for (int i = 0; i < num_payloads; ++i) {
        for (int j = 0; j < num_vuln_types; ++j) {
            matrix(i, j) = 0.5f;  // Start with neutral effectiveness
        }
    }

    return tensor;
}
```

**Learning Payload Effectiveness**:

```cpp
tensorflow::Tensor compute_payload_effectiveness_loss(
    const std::vector<PayloadTestResult>& test_results,
    const tensorflow::Tensor& effectiveness_matrix
) {
    using namespace tensorflow;
    using namespace tensorflow::ops;

    Scope root = Scope::NewRootScope();

    // For each payload-vulnerability pair, compute success rate
    tensorflow::Tensor loss_tensor(tensorflow::DT_FLOAT,
                                    tensorflow::TensorShape({}));

    float total_loss = 0.0f;
    int count = 0;

    for (const auto& result : test_results) {
        int payload_id = result.payload_id;
        int vuln_type = result.vulnerability_type;
        bool succeeded = result.detected;

        auto matrix = effectiveness_matrix.matrix<float>();
        float predicted_effectiveness = matrix(payload_id, vuln_type);
        float actual_effectiveness = succeeded ? 1.0f : 0.0f;

        // L2 loss: (predicted - actual)²
        float error = predicted_effectiveness - actual_effectiveness;
        total_loss += error * error;
        count++;
    }

    loss_tensor.scalar<float>()() = total_loss / count;
    return loss_tensor;
}
```

**Adaptive Payload Selection**:

```cpp
// Select top-k most effective payloads for each vulnerability type
std::vector<int> select_top_payloads(
    const tensorflow::Tensor& effectiveness_matrix,
    int vuln_type,
    int k = 5
) {
    auto matrix = effectiveness_matrix.matrix<float>();

    // Get effectiveness scores for this vulnerability type
    std::vector<std::pair<float, int>> scores;
    for (int i = 0; i < matrix.dimension(0); ++i) {
        scores.push_back({matrix(i, vuln_type), i});
    }

    // Sort by effectiveness (descending)
    std::sort(scores.begin(), scores.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    // Return top k payload IDs
    std::vector<int> top_payloads;
    for (int i = 0; i < std::min(k, static_cast<int>(scores.size())); ++i) {
        top_payloads.push_back(scores[i].second);
    }

    return top_payloads;
}

// Use learned effectiveness to prioritize payloads during scanning
void apply_learned_payload_selection(
    VulnEngine& engine,
    const tensorflow::Tensor& effectiveness_matrix
) {
    // For each vulnerability type, use top-k payloads
    for (int vuln_type = 0; vuln_type < num_vuln_types; ++vuln_type) {
        auto top_payloads = select_top_payloads(effectiveness_matrix,
                                               vuln_type, 5);
        engine.set_payload_priority(vuln_type, top_payloads);
    }
}
```

### Integration Points

**Integration with VulnEngine**:

```cpp
// VulnEngine modification to use optimized parameters
class VulnEngine {
private:
    // Optimized parameters (loaded from optimization results)
    std::map<std::string, float> optimized_confidence_thresholds_;
    std::map<std::string, float> optimized_pattern_weights_;

public:
    void load_optimized_parameters(const std::string& config_path) {
        // Load optimized parameters from JSON/YAML
        auto config = load_config(config_path);
        optimized_confidence_thresholds_ = config.confidence_thresholds;
        optimized_pattern_weights_ = config.pattern_weights;
    }

    void checkSQLInjection(const CrawlResult& result,
                          std::vector<Finding>& findings) {
        // Use optimized confidence threshold
        float threshold = optimized_confidence_thresholds_.count("sql_injection")
            ? optimized_confidence_thresholds_["sql_injection"]
            : confidenceThreshold_;  // Fallback to default

        // Use optimized pattern weights
        float error_weight = optimized_pattern_weights_.count("sql_error")
            ? optimized_pattern_weights_["sql_error"]
            : 0.3f;  // Default weight

        float timing_weight = optimized_pattern_weights_.count("timing_anomaly")
            ? optimized_pattern_weights_["timing_anomaly"]
            : 0.2f;

        // Compute confidence using weighted evidence
        float confidence = 0.0f;
        if (detect_sql_error(result)) {
            confidence += error_weight;
        }
        if (detect_timing_anomaly(result)) {
            confidence += timing_weight;
        }

        // Only report if confidence exceeds optimized threshold
        if (confidence >= threshold) {
            Finding f;
            f.confidence = confidence;
            // ... populate finding
            findings.push_back(std::move(f));
        }
    }
};
```

**Integration with BudgetEvaluator**:

```cpp
// BudgetEvaluator modification to use optimized risk budget
class BudgetEvaluator {
private:
    Policy optimized_policy_;

public:
    void load_optimized_policy(const std::string& policy_path) {
        optimized_policy_ = Policy::load(policy_path);
    }

    BudgetResult evaluate_findings(
        const std::vector<nlohmann::json>& findings
    ) const {
        // Use optimized category scores and thresholds
        BudgetEvaluator evaluator(optimized_policy_);
        return evaluator.evaluate_findings(findings);
    }
};
```

**Configuration File Updates**:

After optimization, generate optimized configuration:

```yaml
# config/optimized_policy.yaml (generated by optimizer)
optimized_parameters:
  confidence_thresholds:
    sql_injection: 0.73
    command_injection: 0.71
    path_traversal: 0.76
    information_disclosure: 0.68
    # ... other thresholds

  pattern_weights:
    sql_error: 0.32
    timing_anomaly: 0.21
    command_output: 0.38
    payload_reflection: 0.15
    # ... other weights

  category_scores:
    sql_injection: 9
    command_injection: 11
    path_traversal: 7
    # ... other scores (rounded to integers)

  thresholds:
    warn_threshold: 4
    block_threshold: 6

  payload_effectiveness:
    # Top payloads per vulnerability type
    sql_injection:
      - payload_id: "sql_or_1_equals_1"
        effectiveness: 0.92
      - payload_id: "sql_union_select"
        effectiveness: 0.88
    # ... other vulnerability types
```

### Testing and Validation

**Unit Tests for Tensor Operations**:

```cpp
// tests/test_tensor_utils.cpp
TEST_CASE("Matrix multiplication for confidence computation") {
    using namespace tensorflow;

    // Create test matrices
    Tensor detection_matrix(DT_FLOAT, TensorShape({2, 3}));
    Tensor pattern_weights(DT_FLOAT, TensorShape({3, 2}));

    // Initialize with test data
    auto det = detection_matrix.matrix<float>();
    det(0, 0) = 1.0; det(0, 1) = 0.0; det(0, 2) = 0.5;
    det(1, 0) = 0.0; det(1, 1) = 1.0; det(1, 2) = 0.0;

    auto weights = pattern_weights.matrix<float>();
    weights(0, 0) = 0.3; weights(0, 1) = 0.1;
    weights(1, 0) = 0.2; weights(1, 1) = 0.4;
    weights(2, 0) = 0.1; weights(2, 1) = 0.2;

    // Compute confidence
    auto confidence = compute_confidence_scores(detection_matrix,
                                                pattern_weights);

    // Verify results
    auto conf = confidence.matrix<float>();
    REQUIRE(conf(0, 0) == Approx(0.35));  // 1.0*0.3 + 0.0*0.2 + 0.5*0.1
    REQUIRE(conf(1, 1) == Approx(0.60));  // 0.0*0.1 + 1.0*0.4 + 0.0*0.2
}
```

**Integration Tests for Optimization Pipeline**:

```cpp
// tests/test_optimizer.cpp
TEST_CASE("End-to-end optimization pipeline") {
    // Load test dataset
    auto test_data = load_test_dataset("tests/fixtures/optimization_test.yaml");

    // Initialize optimizer
    GradientDescentOptimizer optimizer(0.01);
    optimizer.initialize_parameters();

    // Run optimization
    auto optimized_params = optimizer.optimize(test_data, 100);

    // Validate optimized parameters
    REQUIRE(optimized_params.confidence_thresholds["sql_injection"] >= 0.5);
    REQUIRE(optimized_params.confidence_thresholds["sql_injection"] <= 1.0);
    REQUIRE(optimized_params.category_scores["sql_injection"] > 0);
    REQUIRE(optimized_params.block_threshold >
            optimized_params.warn_threshold);

    // Test that optimized parameters improve metrics
    auto baseline_metrics = evaluate_with_default_params(test_data);
    auto optimized_metrics = evaluate_with_params(test_data, optimized_params);

    REQUIRE(optimized_metrics.f1_score >= baseline_metrics.f1_score);
    REQUIRE(optimized_metrics.false_positive_rate <=
            baseline_metrics.false_positive_rate);
}
```

**Validation Against Test Datasets**:

```cpp
void validate_optimization(
    const OptimizedParameters& params,
    const std::vector<TestResult>& validation_set
) {
    // Run detection with optimized parameters
    VulnEngine engine;
    engine.load_optimized_parameters(params);

    std::vector<Finding> findings;
    for (const auto& test_case : validation_set) {
        auto result = engine.analyze(test_case.crawl_result);
        findings.insert(findings.end(), result.begin(), result.end());
    }

    // Compute metrics
    auto metrics = compute_metrics(findings, validation_set);

    // Validate against targets
    REQUIRE(metrics.precision >= 0.90);
    REQUIRE(metrics.recall >= 0.85);
    REQUIRE(metrics.f1_score >= 0.87);

    std::cout << "Optimization validation:" << std::endl;
    std::cout << "  Precision: " << metrics.precision << std::endl;
    std::cout << "  Recall: " << metrics.recall << std::endl;
    std::cout << "  F1 Score: " << metrics.f1_score << std::endl;
}
```

**Performance Benchmarks**:

```cpp
void benchmark_optimization_performance() {
    auto test_data = load_large_test_dataset(10000);  // 10k test cases

    auto start = std::chrono::high_resolution_clock::now();

    GradientDescentOptimizer optimizer(0.01);
    auto params = optimizer.optimize(test_data, 100);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        end - start
    ).count();

    std::cout << "Optimization completed in " << duration << " seconds"
              << std::endl;
    std::cout << "Average time per iteration: "
              << duration / 100.0 << " seconds" << std::endl;

    // Target: < 5 minutes for 100 iterations on 10k test cases
    REQUIRE(duration < 300);
}
```

### Usage Examples

**Command-Line Interface**:

```cpp
// tools/sentinel_optimize.cpp
int main(int argc, char** argv) {
    std::string test_dataset_path;
    std::string output_config_path = "config/optimized_policy.yaml";
    int max_iterations = 1000;
    float learning_rate = 0.01;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dataset" && i + 1 < argc) {
            test_dataset_path = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_config_path = argv[++i];
        } else if (arg == "--iterations" && i + 1 < argc) {
            max_iterations = std::stoi(argv[++i]);
        } else if (arg == "--learning-rate" && i + 1 < argc) {
            learning_rate = std::stof(argv[++i]);
        }
    }

    if (test_dataset_path.empty()) {
        std::cerr << "Error: --dataset required" << std::endl;
        return 1;
    }

    // Load test dataset
    auto test_data = load_test_dataset(test_dataset_path);

    // Initialize optimizer
    GradientDescentOptimizer optimizer(learning_rate);
    optimizer.initialize_parameters();

    // Run optimization
    std::cout << "Starting optimization..." << std::endl;
    auto optimized_params = optimizer.optimize(test_data, max_iterations);

    // Save optimized parameters
    save_optimized_config(optimized_params, output_config_path);

    std::cout << "Optimization complete. Parameters saved to: "
              << output_config_path << std::endl;

    return 0;
}
```

**Usage**:

```bash
# Run optimization on test dataset
./build/tools/sentinel_optimize \
    --dataset tests/fixtures/optimization_dataset.yaml \
    --output config/optimized_policy.yaml \
    --iterations 1000 \
    --learning-rate 0.01

# Use optimized parameters in scans
./build/sentinel scan \
    --target http://example.com \
    --optimized-config config/optimized_policy.yaml
```

**Configuration Examples**:

```yaml
# Optimization configuration
optimization:
  learning_rate: 0.01
  learning_rate_decay: 0.95
  decay_steps: 100
  max_iterations: 1000
  convergence_tolerance: 1e-5
  convergence_patience: 10
  batch_size: 32

  loss_weights:
    false_positive: 0.3
    false_negative: 0.3
    f1_score: 0.3
    budget_alignment: 0.05
    constraints: 0.05

  parameter_bounds:
    confidence_thresholds:
      min: 0.5
      max: 0.95
    category_scores:
      min: 1
      max: 20
    warn_threshold:
      min: 1
      max: 50
    block_threshold:
      min: 2
      max: 50
```

**Expected Output**:

```
Starting optimization...
Iteration 0: Loss = 0.4523, Precision = 0.8234, Recall = 0.7891
Iteration 10: Loss = 0.3891, Precision = 0.8567, Recall = 0.8123
Iteration 20: Loss = 0.3456, Precision = 0.8723, Recall = 0.8345
...
Iteration 100: Loss = 0.2345, Precision = 0.9123, Recall = 0.8765
Converged at iteration 127

Optimization Results:
  Final Loss: 0.2234
  Precision: 0.9156 (target: ≥0.90) ✓
  Recall: 0.8812 (target: ≥0.85) ✓
  F1 Score: 0.8978 (target: ≥0.87) ✓

Optimized Parameters:
  Confidence Thresholds:
    sql_injection: 0.73
    command_injection: 0.71
    path_traversal: 0.76
    ...

  Category Scores:
    sql_injection: 9
    command_injection: 11
    ...

  Thresholds:
    warn_threshold: 4
    block_threshold: 6

Parameters saved to: config/optimized_policy.yaml
```

### Dependencies and Build Requirements

**TensorFlow C++ API Requirements**:

- **Version**: TensorFlow 2.x (recommended: 2.10 or later)
- **Platform Support**: Linux, macOS, Windows
- **Build Options**:
  - CPU-only build (sufficient for optimization)
  - GPU support (optional, for faster computation on large datasets)

**Installation Methods**:

1. **Pre-built Binaries** (Easiest):
   ```bash
   # Download from TensorFlow releases
   wget https://storage.googleapis.com/tensorflow/libtensorflow/libtensorflow-cpu-linux-x86_64-2.10.0.tar.gz
   tar -xzf libtensorflow-cpu-linux-x86_64-2.10.0.tar.gz
   sudo cp -r lib/* /usr/local/lib/
   sudo cp -r include/* /usr/local/include/
   ```

2. **Build from Source** (For custom configurations):
   ```bash
   # Clone TensorFlow
   git clone https://github.com/tensorflow/tensorflow.git
   cd tensorflow

   # Configure and build C++ API
   ./configure
   bazel build //tensorflow:libtensorflow_cc.so
   ```

**CMake Configuration**:

```cmake
# Add to CMakeLists.txt
# Find TensorFlow
find_path(TENSORFLOW_INCLUDE_DIR
    NAMES tensorflow/cc/client/client_session.h
    PATHS
        /usr/local/include
        /opt/tensorflow/include
        ${CMAKE_SOURCE_DIR}/third_party/tensorflow/include
)

find_library(TENSORFLOW_CC_LIB
    NAMES tensorflow_cc
    PATHS
        /usr/local/lib
        /opt/tensorflow/lib
        ${CMAKE_SOURCE_DIR}/third_party/tensorflow/lib
)

find_library(TENSORFLOW_FRAMEWORK_LIB
    NAMES tensorflow_framework
    PATHS
        /usr/local/lib
        /opt/tensorflow/lib
        ${CMAKE_SOURCE_DIR}/third_party/tensorflow/lib
)

if(TENSORFLOW_INCLUDE_DIR AND TENSORFLOW_CC_LIB AND TENSORFLOW_FRAMEWORK_LIB)
    message(STATUS "Found TensorFlow: ${TENSORFLOW_INCLUDE_DIR}")
    set(TENSORFLOW_FOUND TRUE)
else()
    message(WARNING "TensorFlow not found. Optimization features will be disabled.")
    set(TENSORFLOW_FOUND FALSE)
endif()

# Add optimization library (only if TensorFlow found)
if(TENSORFLOW_FOUND)
    add_library(optimization
        src/optimization/optimizer.cpp
        src/optimization/loss_functions.cpp
        src/optimization/tensor_utils.cpp
        src/optimization/parameter_space.cpp
        src/optimization/gradient_descent.cpp
    )

    target_include_directories(optimization PUBLIC
        src/optimization
        ${TENSORFLOW_INCLUDE_DIR}
    )

    target_link_libraries(optimization PUBLIC
        ${TENSORFLOW_CC_LIB}
        ${TENSORFLOW_FRAMEWORK_LIB}
        nlohmann_json::nlohmann_json
    )

    # Add optimizer executable
    add_executable(sentinel-optimize tools/sentinel_optimize.cpp)
    target_link_libraries(sentinel-optimize PRIVATE optimization core budget)
endif()
```

**Platform-Specific Considerations**:

- **Linux**: Use pre-built binaries or build from source with Bazel
- **macOS**: May need to build from source; ensure compatible C++ standard library
- **Windows**: Use Visual Studio build or vcpkg package manager

**Version Requirements**:

- **C++ Standard**: C++17 (compatible with existing codebase)
- **TensorFlow**: 2.10.0 or later (for C++ API stability)
- **CMake**: 3.18 or later (existing requirement)

**Optional Dependencies**:

- **Eigen3**: Not required (using TensorFlow for all matrix operations)
- **BLAS/LAPACK**: Included in TensorFlow, no separate installation needed

## Configuration Updates

### Update `config/policy.yaml`

Add category scores for new vulnerabilities:

```yaml
category_scores:
  sql_injection: 10
  command_injection: 10
  path_traversal: 6
  information_disclosure: 4
  ssrf: 8
  xxe: 6
  ssti: 7
  sensitive_data_exposure: 5
  ldap_injection: 5
  xpath_injection: 5
  open_redirect: 3
  directory_listing: 2
  weak_session_management: 4
  insecure_file_upload: 6
```

### Update `ci_policy.yml`

Ensure all new categories are included with appropriate scores.

## Success Criteria

Phase 4 is complete when:

1. ✅ All Phase 4.1 vulnerabilities are implemented and tested
2. ✅ All Phase 4.2 vulnerabilities are implemented and tested
3. ✅ At least 50% of Phase 4.3 vulnerabilities are implemented
4. ✅ Enhanced detection for existing vulnerabilities (XSS, CSRF, IDOR)
5. ✅ All new vulnerabilities have unit tests
6. ✅ Documentation updated with new vulnerability types
7. ✅ Policy files updated with new category scores

## Timeline Estimate

**Important**: These timelines reflect the reality that authenticated vulnerability detection requires foundational capabilities that don't currently exist.

- **Phase 4.0 (Foundation)**: 4-6 weeks (semester-long effort)
  - Session Management: 2-3 weeks
  - Response Pattern Analysis: 1-2 weeks
  - Timing Analysis: 1 week
  - Baseline Comparison: 1 week

- **Phase 4.1 (Unauthenticated)**: 2-3 weeks (5 vulnerabilities)
  - Can be done immediately, no prerequisites

- **Phase 4.2 (Authenticated)**: 6-8 weeks (8 vulnerabilities)
  - **Requires Phase 4.0 completion first**
  - SQL Injection, Command Injection, Path Traversal, SSRF, XXE, SSTI, Sensitive Data Exposure, Enhanced IDOR

- **Phase 4.3 (Moderate Impact)**: 3-4 weeks (6 vulnerabilities)
  - Some may require Phase 4.0 (LDAP, XPath, Weak Session Management)
  - Others can be done without (Open Redirect, Directory Listing already in 4.1)

- **Phase 4.4 (Enhancements)**: 2-3 weeks (4 enhancements)
  - Enhanced XSS, CSRF, IDOR, HTTP Method Vulnerabilities

**Total Realistic Timeline**:
- **Without Phase 4.0**: 7-10 weeks (Phase 4.1 + 4.3 partial + 4.4)
- **With Phase 4.0**: 15-21 weeks (full implementation including authenticated vulnerabilities)

**Recommendation**: Start with Phase 4.1 (unauthenticated vulnerabilities) which can be done immediately, then evaluate whether Phase 4.0 foundation work is feasible for your timeline.

## Next Steps

1. **Review Secure Coding Principles**: Ensure all team members understand the principles from the textbook
2. **Start with Phase 4.1**: Implement SQL Injection, Command Injection, Path Traversal, Information Disclosure
3. **Create payload library**: Expand `config/payloads.yaml` with all payloads, following input validation and sanitization principles
4. **Implement error pattern matching**: Create regex patterns for error detection, ensuring we detect information disclosure
5. **Add unit tests**: Test each detection function thoroughly, including edge cases and boundary conditions
6. **Update documentation**: Document new vulnerabilities in README, referencing secure coding principles
7. **Code Review**: Review all implementations against the secure coding principles checklist

## References

- Seacord, Robert C. "Secure Coding in C and C++" (2nd Edition). Addison-Wesley, 2013.
- OWASP Top 10:2021 - https://owasp.org/Top10/
- CWE Top 25 - https://cwe.mitre.org/top25/
- OWASP Testing Guide - https://owasp.org/www-project-web-security-testing-guide/

