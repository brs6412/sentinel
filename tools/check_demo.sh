#!/usr/bin/env bash
set -euo pipefail

: "${ENDPOINTS:=apps/demo_server/fixtures/endpoints.small.jsonl}"
: "${FINDINGS:=apps/demo_server/fixtures/findings.demo.jsonl}"
export ENDPOINTS FINDINGS

# Short, predictable curl timeouts
CURL_OPTS=( -s --connect-timeout 2 -m 3 )

echo "▶ Using fixtures:"
echo "   ENDPOINTS = $ENDPOINTS"
echo "   FINDINGS  = $FINDINGS"

if [[ ! -f "$ENDPOINTS" ]]; then
  echo "❌ Missing endpoints JSONL: $ENDPOINTS"; exit 1
fi
if [[ ! -f "$FINDINGS" ]]; then
  echo "❌ Missing findings JSONL:  $FINDINGS"; exit 1
fi

echo "▶ Linting JSONL files..."
grep -v '^[[:space:]]*$' "$ENDPOINTS" | while IFS= read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$l"; done
grep -v '^[[:space:]]*$' "$FINDINGS"  | while IFS= read -r l; do python -c 'import json,sys; json.loads(sys.argv[1])' "$l"; done
echo "✅ JSONL OK"

HOST="127.0.0.1:8080"

echo "▶ /healthz should be 200..."
code="$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "http://$HOST/healthz" || true)"
if [[ "$code" != "200" ]]; then
  echo "❌ /healthz returned ${code:-<no response>} (expected 200). Is the demo server running on 127.0.0.1:8080?"; exit 1
fi
echo "✅ /healthz OK"

echo "▶ /no-headers should NOT include CSP/XFO/HSTS..."
if curl "${CURL_OPTS[@]}" -i "http://$HOST/no-headers" | grep -Ei '(^|[[:space:]])(content-security-policy|x-frame-options|strict-transport-security)[[:space:]]*:' >/dev/null; then
  echo "❌ Security header found on /no-headers (should be missing)"; exit 1
fi
echo "✅ /no-headers missing CSP/XFO/HSTS (as intended)"

echo "▶ /set-cookie should include Set-Cookie but NOT Secure/HttpOnly..."
hdrs="$(curl "${CURL_OPTS[@]}" -i "http://$HOST/set-cookie")"

if ! grep -i '^Set-Cookie:' <<<"$hdrs" >/dev/null; then
  echo "❌ No Set-Cookie on /set-cookie"; exit 1
fi
if grep -qi '^Set-Cookie:.*\bsecure\b' <<<"$hdrs"; then
  echo "❌ Cookie has Secure flag (should be missing)"; exit 1
fi
if grep -qi '^Set-Cookie:.*\bhttponly\b' <<<"$hdrs"; then
  echo "❌ Cookie has HttpOnly flag (should be missing)"; exit 1
fi
echo "✅ /set-cookie header present without Secure/HttpOnly (as intended)"

echo "✅ All demo checks passed."
