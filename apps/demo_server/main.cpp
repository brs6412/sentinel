#include <iostream>
#include <string>
#include <cstdio>
#include "httplib.h"

using namespace httplib;

int main() {
  Server svr;

  // Health check: should return 200 so scripts/CI can tell the server is alive.
  svr.Get("/healthz", [](const Request&, Response& res) {
    res.status = 200;
    res.set_content("ok", "text/plain");
  });

  // Simple landing page with links to the intentionally bad routes below.
  svr.Get("/", [](const Request&, Response& res) {
    const char* html =
      "<!doctype html><html><body>"
      "<h1>Sentinel Demo</h1>"
      "<ul>"
      "<li><a href=\"/no-headers\">/no-headers</a></li>"
      "<li><a href=\"/set-cookie\">/set-cookie</a></li>"
      "</ul>"
      "</body></html>";
    res.set_content(html, "text/html");
  });

  // This route deliberately skips common security headers (CSP, XFO, HSTS).
  // It exists so scanners/tests have something obvious to flag.
  svr.Get("/no-headers", [](const Request&, Response& res) {
    res.status = 200;
    res.set_content("<p>This response intentionally lacks CSP/XFO/HSTS.</p>", "text/html");
  });

  // This one sets a cookie without Secure or HttpOnly on purpose.
  // Again: demo vuln so the tooling can detect it.
  svr.Get("/set-cookie", [](const Request&, Response& res) {
    res.set_header("Set-Cookie", "sid=demo123; Path=/; SameSite=Lax");
    res.status = 200;
    res.set_content("<p>Set-Cookie sent without Secure/HttpOnly (by design).</p>", "text/html");
  });

  std::cout << "Attempting to bind to http://127.0.0.1:8080\n";

  // Use bind_to_port + listen_after_bind so we can return non-zero on bind failure.
  if (!svr.bind_to_port("127.0.0.1", 8080)) {
    std::fprintf(stderr, "ERROR: failed to bind 127.0.0.1:8080. Is the port in use?\n");
    return 1;
  }

  // This will block and serve requests after a successful bind.
  svr.listen_after_bind();
  return 0;
}
