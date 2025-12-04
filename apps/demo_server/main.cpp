#include "httplib.h"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <random>
#include <sstream>

using namespace httplib;

static void maybe_delay_and_error(const Request& req, Response& res) {
  auto getd = [&](const char* k)->double{
    auto it = req.params.find(k);
    if (it == req.params.end()) return 0.0;
    try { return std::stod(it->second); } catch(...) { return 0.0; }
  };
  double lat_ms = getd("lat");
  double jit_ms = getd("jitter");
  double err    = getd("err");

  if (lat_ms > 0 || jit_ms > 0) {
    std::random_device rd; std::mt19937 gen((unsigned)std::random_device{}());
    std::normal_distribution<> nd(lat_ms, jit_ms);
    double wait = std::max(0.0, nd(gen));
    std::this_thread::sleep_for(std::chrono::milliseconds((int)wait));
  }
  if (err > 0.0) {
    std::random_device rd; std::mt19937 gen((unsigned)std::random_device{}());
    std::uniform_real_distribution<> ud(0.0,1.0);
    if (ud(gen) <= err) {
      res.status = 500;
      res.set_content("error injection", "text/plain");
    }
  }
}

int main() {
  Server svr;

  svr.Get("/robots.txt", [](const Request&, Response& res) {
    res.status = 200;
    res.set_content("User-agent: *\nAllow: /\n", "text/plain");
  });

  svr.Get("/sitemap.xml", [](const Request&, Response& res) {
    const char* x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
                    "  <url><loc>http://127.0.0.1:8080/</loc></url>\n"
                    "  <url><loc>http://127.0.0.1:8080/no-headers</loc></url>\n"
                    "  <url><loc>http://127.0.0.1:8080/set-cookie</loc></url>\n"
                    "  <url><loc>http://127.0.0.1:8080/secure-cookie</loc></url>\n"
                    "  <url><loc>http://127.0.0.1:8080/secure</loc></url>\n"
                    "  <url><loc>http://127.0.0.1:8080/reflect</loc></url>\n"
                    "</urlset>\n";
    res.status = 200;
    res.set_content(x, "application/xml");
  });

  svr.Get("/healthz", [](const Request&, Response& res) {
    res.status = 200;
    res.set_content("ok", "text/plain");
  });

  svr.Get("/", [](const Request&, Response& res) {
    const char* html =
      "<!doctype html><html><body>"
      "<h1>Sentinel Demo</h1>"
      "<ul>"
      "<li><a href=\"/no-headers\">/no-headers</a></li>"
      "<li><a href=\"/set-cookie\">/set-cookie</a></li>"
      "<li><a href=\"/secure-cookie\">/secure-cookie</a></li>"
      "<li><a href=\"/secure\">/secure</a></li>"
      "<li><a href=\"/reflect?q=sentinel_reflection_test\">/reflect</a></li>"
      "</ul><p><a href=\"/robots.txt\">robots.txt</a> · <a href=\"/sitemap.xml\">sitemap.xml</a></p>"
      "</body></html>";
    res.set_header("Content-Security-Policy", "default-src 'self'");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    res.status = 200;
    res.set_content(html, "text/html");
  });

  svr.Get("/no-headers", [](const Request& req, Response& res) {
    maybe_delay_and_error(req, res);
    if (res.status == 500) return;
    res.status = 200;
    res.set_content("<p>This response intentionally lacks CSP/XFO/HSTS.</p>", "text/html");
  });

  svr.Get("/set-cookie", [](const Request& req, Response& res) {
    maybe_delay_and_error(req, res);
    if (res.status == 500) return;
    res.set_header("Content-Security-Policy", "default-src 'self'");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    res.set_header("Set-Cookie", "sid=demo123; Path=/; SameSite=Lax");
    res.status = 200;
    res.set_content("<p>Set-Cookie sent without Secure/HttpOnly (by design).</p>", "text/html");
  });

  svr.Get("/secure-cookie", [](const Request& req, Response& res) {
    maybe_delay_and_error(req, res);
    if (res.status == 500) return;
    res.set_header("Content-Security-Policy", "default-src 'self'");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    res.set_header("Set-Cookie", "sid=demo123; Secure; HttpOnly; SameSite=Strict");
    res.status = 200;
    res.set_content("<p>Secure Cookie sent, no findings should generate.</p>", "text/html");
  });

  svr.Get("/secure", [](const Request& req, Response& res) {
    maybe_delay_and_error(req, res);
    if (res.status == 500) return;
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Content-Security-Policy", "default-src 'self'");
    res.set_header("Strict-TransportSecurity", "max-age=63072000; includeSubDomains; preload");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header("Set-Cookie", "session=secure123;Path=/;Secure;HttpOnly;SameSite=Strict");
    res.status = 200;
    res.set_content("{\"status\":\"secure\",\"message\":\"All security headers configured\"}", "application/json");
  });

  svr.Get("/reflect", [](const Request& req, Response& res) {
    maybe_delay_and_error(req, res);
    if (res.status == 500) return;
    res.set_header("Content-Security-Policy", "default-src 'self'");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    auto it = req.params.find("q");
    std::string value = (it != req.params.end()) ? it->second : "";
    res.status = 200;
    std::string html_str =
      "<!doctype html><html><body>"
      "<h1>Reflected XSS Test</h1>"
      "<p>Reflected (text): " + value + "</p>"
      "<p>Reflected (attribute): <input type=\"text\" value="+value+"></p>"
      "<pre>{{\"echo\":\"{" + value + "\"}}</pre>"
      "</body></html>";
    const char* html = html_str.c_str();
    res.set_content(html, "text/plain");
  });

  // Login endpoint for session management testing
  svr.Get("/login", [](const Request& req, Response& res) {
    res.set_header("Content-Type", "text/html");
    res.status = 200;
    // Generate a simple CSRF token (in production, this would be cryptographically secure)
    std::string csrf_token = "csrf_token_" + std::to_string(std::time(nullptr));
    std::string html =
      "<!doctype html><html><body>"
      "<h1>Login</h1>"
      "<form method=\"POST\" action=\"/login\">"
      "<input type=\"hidden\" name=\"csrf_token\" value=\"" + csrf_token + "\">"
      "<input type=\"hidden\" name=\"_token\" value=\"" + csrf_token + "\">"
      "<label>Username: <input type=\"text\" name=\"username\"></label><br>"
      "<label>Password: <input type=\"password\" name=\"password\"></label><br>"
      "<button type=\"submit\">Login</button>"
      "</form>"
      "</body></html>";
    res.set_content(html, "text/html");
  });

  svr.Post("/login", [](const Request& req, Response& res) {
    // Simple authentication check
    std::string username, password, csrf_token;
    if (req.has_param("username")) username = req.get_param_value("username");
    if (req.has_param("password")) password = req.get_param_value("password");
    if (req.has_param("csrf_token")) csrf_token = req.get_param_value("csrf_token");
    if (req.has_param("_token")) csrf_token = req.get_param_value("_token");

    // Accept any username/password for demo purposes
    // In production, this would validate against a database
    if (!username.empty() && !password.empty()) {
      res.status = 302;  // Redirect after successful login
      res.set_header("Location", "/");
      // Set session cookie
      std::string session_id = "session_" + std::to_string(std::time(nullptr));
      res.set_header("Set-Cookie", "session_id=" + session_id + "; Path=/; HttpOnly; SameSite=Lax");
      res.set_header("Set-Cookie", "user=" + username + "; Path=/; SameSite=Lax");
    } else {
      res.status = 401;
      res.set_content("Invalid credentials", "text/plain");
    }
  });

  // Protected endpoint that requires authentication
  svr.Get("/protected", [](const Request& req, Response& res) {
    // Check for session cookie
    std::string cookie_header = req.get_header_value("Cookie");
    bool authenticated = cookie_header.find("session_id=") != std::string::npos;
    
    if (authenticated) {
      res.status = 200;
      res.set_header("Content-Type", "application/json");
      res.set_content("{\"status\":\"authenticated\",\"message\":\"You have access to this protected resource\"}", "application/json");
    } else {
      res.status = 401;
      res.set_content("{\"error\":\"Unauthorized\"}", "application/json");
    }
  });

  // Information disclosure test endpoints
  svr.Get("/error-stack", [](const Request& req, Response& res) {
    // Simulate Java stack trace
    res.status = 500;
    res.set_content(
      "java.lang.NullPointerException\n"
      "    at com.example.App.processRequest(App.java:42)\n"
      "    at com.example.App.main(App.java:15)\n"
      "    at java.lang.Thread.run(Thread.java:748)",
      "text/plain"
    );
  });

  svr.Get("/error-python", [](const Request& req, Response& res) {
    // Simulate Python traceback
    res.status = 500;
    res.set_content(
      "Traceback (most recent call last):\n"
      "  File \"/app/main.py\", line 42, in process\n"
      "    result = data['key']\n"
      "KeyError: 'key'",
      "text/plain"
    );
  });

  svr.Get("/version-info", [](const Request& req, Response& res) {
    // Expose version information in headers
    res.set_header("X-Powered-By", "PHP/7.4.3");
    res.set_header("Server", "Apache/2.4.41");
    res.status = 200;
    res.set_content("Version information exposed in headers", "text/plain");
  });

  svr.Get("/internal-ip", [](const Request& req, Response& res) {
    // Expose internal IP address
    res.status = 200;
    res.set_content("Database server: 192.168.1.100\nBackend API: 10.0.0.50", "text/plain");
  });

  svr.Get("/debug-mode", [](const Request& req, Response& res) {
    // Simulate debug mode enabled
    res.status = 200;
    res.set_content("Debug mode: true\nDetailed errors: enabled\nInternal path: /var/www/html/app/config.php", "text/plain");
  });

  svr.Get("/error-trigger", [](const Request& req, Response& res) {
    // Trigger verbose errors based on parameter
    auto it = req.params.find("test");
    if (it != req.params.end()) {
      std::string payload = it->second;
      // Return verbose error for certain payloads
      if (payload.find("{{") != std::string::npos || payload.find("${") != std::string::npos) {
        res.status = 500;
        res.set_content(
          "TemplateError: Invalid template syntax\n"
          "File: /var/www/html/templates/render.php\n"
          "Line: 42\n"
          "Expression: " + payload,
          "text/plain"
        );
      } else {
        res.status = 200;
        res.set_content("Normal response", "text/plain");
      }
    } else {
      res.status = 200;
      res.set_content("Normal response", "text/plain");
    }
  });

  // Open redirect test endpoints
  svr.Get("/redirect", [](const Request& req, Response& res) {
    auto it = req.params.find("url");
    if (it == req.params.end()) {
      it = req.params.find("redirect");
    }
    if (it == req.params.end()) {
      it = req.params.find("next");
    }
    if (it == req.params.end()) {
      it = req.params.find("return");
    }
    
    if (it != req.params.end()) {
      std::string redirect_url = it->second;
      
      // Vulnerable: No validation, redirects to any URL
      res.status = 302;
      res.set_header("Location", redirect_url);
      res.set_content("Redirecting...", "text/plain");
    } else {
      res.status = 200;
      res.set_content("No redirect parameter provided", "text/plain");
    }
  });

  svr.Get("/redirect-safe", [](const Request& req, Response& res) {
    auto it = req.params.find("url");
    if (it != req.params.end()) {
      std::string redirect_url = it->second;
      
      // Safe: Whitelist validation
      if (redirect_url.find("http://127.0.0.1") == 0 || 
          redirect_url.find("http://localhost") == 0 ||
          redirect_url.find("/") == 0) {
        res.status = 302;
        res.set_header("Location", redirect_url);
        res.set_content("Redirecting...", "text/plain");
      } else {
        res.status = 400;
        res.set_content("Invalid redirect URL", "text/plain");
      }
    } else {
      res.status = 200;
      res.set_content("No redirect parameter provided", "text/plain");
    }
  });

  svr.Get("/redirect-js", [](const Request& req, Response& res) {
    auto it = req.params.find("url");
    if (it != req.params.end()) {
      std::string redirect_url = it->second;
      
      // JavaScript-based redirect (vulnerable)
      res.status = 200;
      std::string html = "<!DOCTYPE html><html><head><script>window.location.href='" + 
                        redirect_url + "';</script></head><body>Redirecting...</body></html>";
      res.set_content(html, "text/html");
    } else {
      res.status = 200;
      res.set_content("No redirect parameter provided", "text/plain");
    }
  });

  svr.Get("/redirect-bypass", [](const Request& req, Response& res) {
    auto it = req.params.find("url");
    if (it != req.params.end()) {
      std::string redirect_url = it->second;
      
      // Vulnerable to bypass: Only checks for "http://" but allows "//"
      if (redirect_url.find("http://") == 0 || redirect_url.find("https://") == 0) {
        res.status = 400;
        res.set_content("External URLs not allowed", "text/plain");
      } else {
        // Vulnerable: Allows protocol-relative URLs
        res.status = 302;
        res.set_header("Location", redirect_url);
        res.set_content("Redirecting...", "text/plain");
      }
    } else {
      res.status = 200;
      res.set_content("No redirect parameter provided", "text/plain");
    }
  });

  // Directory listing test endpoints
  svr.Get("/uploads/", [](const Request& req, Response& res) {
    // Apache-style directory listing
    res.status = 200;
    res.set_header("Content-Type", "text/html");
    std::string html = R"(<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head>
  <title>Index of /uploads/</title>
</head>
<body>
<h1>Index of /uploads/</h1>
<pre><img src="/icons/blank.gif" alt="[ICO]"> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr>
<img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="/">Parent Directory</a>                             -
<img src="/icons/text.gif" alt="[TXT]"> <a href="file1.txt">file1.txt</a>           2024-01-15 10:30  1.2K
<img src="/icons/text.gif" alt="[TXT]"> <a href="config.sql">config.sql</a>         2024-01-15 10:25  2.5K
<img src="/icons/text.gif" alt="[TXT]"> <a href="backup.bak">backup.bak</a>         2024-01-15 10:20  5.0K
</pre>
</body>
</html>)";
    res.set_content(html, "text/html");
  });

  svr.Get("/backup/", [](const Request& req, Response& res) {
    // Nginx-style directory listing
    res.status = 200;
    res.set_header("Content-Type", "text/html");
    std::string html = R"(<!DOCTYPE html>
<html>
<head>
<title>Index of /backup/</title>
</head>
<body>
<h1>Index of /backup/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="database.sql">database.sql</a>                                         2024-01-15 10:30   15K
<a href="config.env">config.env</a>                                           2024-01-15 10:25    2K
<a href="old.log">old.log</a>                                               2024-01-15 10:20    5K
</pre>
<hr>
</body>
</html>)";
    res.set_content(html, "text/html");
  });

  svr.Get("/config/", [](const Request& req, Response& res) {
    // IIS-style directory listing
    res.status = 200;
    res.set_header("Content-Type", "text/html");
    std::string html = R"(<!DOCTYPE html>
<html>
<head>
<title>Directory Listing</title>
</head>
<body>
<h2>Directory Listing</h2>
<table class="directory">
<tr><th>Name</th><th>Size</th><th>Date Modified</th></tr>
<tr><td><a href="../">..</a></td><td></td><td></td></tr>
<tr><td><a href="settings.conf">settings.conf</a></td><td>1.5K</td><td>2024-01-15 10:30</td></tr>
<tr><td><a href="keys.pem">keys.pem</a></td><td>2.0K</td><td>2024-01-15 10:25</td></tr>
</table>
</body>
</html>)";
    res.set_content(html, "text/html");
  });

  svr.Get("/files/", [](const Request& req, Response& res) {
    // Custom styled file browser (should NOT be flagged as directory listing)
    res.status = 200;
    res.set_header("Content-Type", "text/html");
    std::string html = R"(<!DOCTYPE html>
<html>
<head>
<title>File Browser</title>
<style>
  body { font-family: Arial; background: #f0f0f0; }
  .header { background: #333; color: white; padding: 20px; }
  .nav { background: #444; padding: 10px; }
  .content { padding: 20px; }
  .file-list { background: white; padding: 15px; border-radius: 5px; }
</style>
<script>
  function search() { alert('Search functionality'); }
  function filter() { alert('Filter functionality'); }
</script>
</head>
<body>
<div class="header">
  <h1>File Browser Application</h1>
</div>
<nav class="nav">
  <input type="text" placeholder="Search files..." onkeyup="search()">
  <button onclick="filter()">Filter</button>
</nav>
<div class="content">
  <div class="file-list">
    <h2>Files</h2>
    <ul>
      <li><a href="file1.txt">file1.txt</a></li>
      <li><a href="file2.txt">file2.txt</a></li>
    </ul>
  </div>
</div>
</body>
</html>)";
    res.set_content(html, "text/html");
  });

  // HTTP method vulnerability test endpoints
  svr.Options("/api/resource", [](const Request& req, Response& res) {
    // Return allowed methods
    res.set_header("Allow", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    res.status = 200;
    res.set_content("", "text/plain");
  });

  svr.Put("/api/resource", [](const Request& req, Response& res) {
    // Vulnerable: Accepts PUT without authentication
    res.status = 201;
    res.set_content("Resource created via PUT", "text/plain");
  });

  svr.Delete("/api/resource", [](const Request& req, Response& res) {
    // Vulnerable: Accepts DELETE without authentication
    res.status = 200;
    res.set_content("Resource deleted", "text/plain");
  });

  svr.Patch("/api/resource", [](const Request& req, Response& res) {
    // Vulnerable: Accepts PATCH without authentication
    res.status = 200;
    res.set_content("Resource patched", "text/plain");
  });

  svr.Options("/api/trace", [](const Request& req, Response& res) {
    res.set_header("Allow", "GET, POST, TRACE, OPTIONS");
    res.status = 200;
    res.set_content("", "text/plain");
  });

  // Note: httplib doesn't have built-in TRACE support, so we'll simulate it
  svr.Get("/api/trace", [](const Request& req, Response& res) {
    // Simulate TRACE by echoing request headers
    if (req.get_header_value("X-Sentinel-Test") != "") {
      std::string trace_body = "TRACE /api/trace HTTP/1.1\n";
      trace_body += "Host: " + req.get_header_value("Host") + "\n";
      trace_body += "X-Sentinel-Test: " + req.get_header_value("X-Sentinel-Test") + "\n";
      res.status = 200;
      res.set_content(trace_body, "text/plain");
    } else {
      res.status = 200;
      res.set_content("Normal GET response", "text/plain");
    }
  });

  // Endpoint that allows methods but returns 405 (not functional)
  svr.Options("/api/safe", [](const Request& req, Response& res) {
    res.set_header("Allow", "GET, POST, PUT, DELETE, OPTIONS");
    res.status = 200;
    res.set_content("", "text/plain");
  });

  svr.Put("/api/safe", [](const Request& req, Response& res) {
    // Returns 405 - method not allowed (not functional)
    res.status = 405;
    res.set_content("Method Not Allowed", "text/plain");
  });

  svr.Delete("/api/safe", [](const Request& req, Response& res) {
    // Returns 403 - forbidden (not functional)
    res.status = 403;
    res.set_content("Forbidden", "text/plain");
  });

  std::cout << "Attempting to bind to http://127.0.0.1:8080\n";
  if (!svr.bind_to_port("127.0.0.1", 8080)) {
    std::fprintf(stderr, "ERROR: failed to bind 127.0.0.1:8080\n");
    return 1;
  }
  std::cout << "Listening for requests...\n";
  svr.listen_after_bind();
  return 0;
}
