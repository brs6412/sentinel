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
      "</ul><p><a href=\"/robots.txt\">robots.txt</a> · <a href=\"/sitemap.xml\">sitemap.xml</a></p>"
      "</body></html>";
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
    res.set_header("Set-Cookie", "sid=demo123; Path=/; SameSite=Lax");
    res.status = 200;
    res.set_content("<p>Set-Cookie sent without Secure/HttpOnly (by design).</p>", "text/html");
  });

  std::cout << "Attempting to bind to http://127.0.0.1:8080\n";
  if (!svr.bind_to_port("127.0.0.1", 8080)) {
    std::fprintf(stderr, "ERROR: failed to bind 127.0.0.1:8080\n");
    return 1;
  }
  svr.listen_after_bind();
  return 0;
}
