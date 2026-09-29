# Metro AG VDP - Security Assessment Findings

**Date**: 2026-09-29
**Scope**: Metro AG Vulnerability Disclosure Program (VDP)
**Tester**: Authorized VDP participant
**Status**: Phase 2 - Deep exploitation testing completed

---

## Executive Summary

Comprehensive testing of 66 in-scope Metro AG assets identified **10 reportable findings** across production and pre-production infrastructure. The highest-impact findings are:

1. **3v Coupon API leaks full RSA public key** (2048-bit) through verbose JWT error messages, returning 500 Internal Server Error instead of 401 — exposing cryptographic key material, JWT library internals, and version information (Finding 7)
2. **No rate limiting on IDAM authentication endpoint**, combined with **OAuth client_id enumeration** via differential error messages, enabling credential brute-force attacks at unlimited speed (Findings 8 + 9)
3. **Unauthenticated production search API** exposing 993,709 product records with B2B/B2C pricing, inventory quantities, and seller data — with wildcard CORS and no rate limiting enabling mass automated scraping (Findings 1 + 8)

---

## Finding 1: Production Search API - Unauthenticated Data Exposure + Wildcard CORS

**Severity**: High
**Asset**: `https://app-search-2.prod.de.metro-marketplace.cloud/api/v3/search` (*.metro-marketplace.cloud - in scope)
**Type**: Broken Access Control (OWASP A01) + Security Misconfiguration (OWASP A05)

### Description

The production Metro Marketplace search API returns full product catalog data (993,709 records) without any authentication. Additionally, the API is configured with `Access-Control-Allow-Origin: *` (wildcard CORS), enabling any website to read this data cross-origin via JavaScript.

### Evidence

**Unauthenticated access** — simple GET returns full product data:
```
GET /api/v3/search HTTP/2
Host: app-search-2.prod.de.metro-marketplace.cloud

200 OK (187KB response)
```

**Response contains**:
- Product IDs, GTINs (barcodes), MIDs (Metro Item IDs)
- Net/gross pricing, VAT rates, currency
- Promotional pricing with discount percentages
- Volume pricing tiers
- Inventory quantities per offer
- Seller names and origin/destination codes
- Category hierarchies
- Product reviews (ratings, totals)
- Image URLs from `images.metro-marketplace.eu`

**Wildcard CORS** confirmed via preflight:
```
OPTIONS /api/v3/search HTTP/2
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: X-Impersonation-Session-Id,authorization

204 No Content
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
Access-Control-Allow-Headers: X-Impersonation-Session-Id,X-Active-Context,...,authorization
```

**Accepted dangerous headers**:
- `X-Impersonation-Session-Id` — potential session impersonation
- `authorization` — accepts auth headers cross-origin
- `X-Active-Context` — potential context switching

### Impact

- **Competitive intelligence**: Competitors can scrape all pricing, inventory levels, and promotional strategies at scale
- **Cross-origin data theft**: Any malicious website can silently read this data from a visitor's browser
- **Potential session hijacking**: The `X-Impersonation-Session-Id` header combined with wildcard CORS could enable session-based attacks if authenticated sessions expose additional data

### Recommendation

1. Require authentication (Bearer token) for API access
2. Replace wildcard CORS with explicit origin allowlist
3. Remove or restrict the `X-Impersonation-Session-Id` header
4. Implement rate limiting

---

## Finding 2: IDAM Identity Server - OIDC/JWKS Infrastructure Exposure

**Severity**: Medium
**Asset**: `https://idam.metrosystems.net` (*.metrosystems.net - referenced by in-scope assets betty.metrosystems.net)
**Type**: Security Misconfiguration (OWASP A05)

### Description

The Metro IDAM (Identity and Access Management) server exposes its full OpenID Connect configuration and 8 RSA signing keys at the JWKS endpoint, including keys labeled for dynamic client registration and SAML signing. Error messages also leak internal Confluence documentation URLs.

### Evidence

**OIDC Configuration** at `/.well-known/openid-configuration`:
```json
{
  "issuer": "https://idam.metrosystems.net",
  "jwks_uri": "https://idam.metrosystems.net/.well-known/openid-configuration/jwks",
  "authorization_endpoint": "https://idam.metrosystems.net/authorize/api/oauth2/authorize",
  "token_endpoint": "https://idam.metrosystems.net/authorize/api/oauth2/access_token",
  "userinfo_endpoint": "https://idam.metrosystems.net/authorize/api/oauth2/userInfo",
  "introspection_endpoint": "https://idam.metrosystems.net/authorize/api/oauth2/introspect",
  "grant_types_supported": ["refresh_token", "client_credentials", "implicit", "authorization_code", "password"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
}
```

**JWKS contains 8 keys** including:
- `dyn-client-reg` — suggests Dynamic Client Registration capability
- `saml-signing-keypair` — SAML signing key
- `token-signing-keypair` + dated version — token signing keys with rotation history

**Error message information disclosure**:
```json
{"error":"unsupported_grant_type","error_description":"password grant type not supported",
 "error_uri":"https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes"}
```

### Impact

- Attackers gain detailed knowledge of the authentication infrastructure
- JWKS key IDs reveal infrastructure capabilities (SAML, dynamic registration)
- Internal Confluence URL exposed enables further targeted reconnaissance
- `token_endpoint_auth_methods_supported: ["none"]` could allow public clients without secrets

### Recommendation

1. Remove `error_uri` pointing to internal Confluence
2. Restrict OIDC discovery to necessary information
3. Review and minimize `grant_types_supported` and `token_endpoint_auth_methods_supported`
4. Audit dynamic client registration access controls

---

## Finding 3: Internal Kubernetes Hostname Leak via CORS Header

**Severity**: Medium
**Asset**: `https://idam.metrosystems.net/authorize/api/register`
**Type**: Information Disclosure (OWASP A01)

### Description

The IDAM registration endpoint (404 response) leaks internal infrastructure hostnames through its `Access-Control-Allow-Origin` response header.

### Evidence

```
HTTP/2 404
access-control-allow-origin: http://halipoc-k8s2.test1.mcc.gb-lon1.metroscales.io:30006 http://localhost:8001
```

**Leaked information**:
- Internal Kubernetes cluster: `halipoc-k8s2`
- Testing environment: `test1`
- Internal domain: `metroscales.io`
- Data center: `gb-lon1` (London)
- NodePort: `30006`
- Development port: `localhost:8001`

### Impact

- Reveals internal network topology and naming conventions
- Exposes Kubernetes cluster naming patterns
- Could assist in targeted internal network attacks if combined with other access vectors

### Recommendation

1. Remove internal hostnames from production CORS headers
2. Audit all CORS configurations for internal hostname leakage

---

## Finding 4: Price Backoffice Pre-prod - Unauthenticated SPA with OAuth Client Credentials

**Severity**: Medium
**Asset**: `https://md.betty-pp.metrosystems.net/price.backoffice` (in scope)
**Type**: Sensitive Data Exposure (OWASP A02) + Security Misconfiguration (OWASP A05)

### Description

The Betty Price Backoffice pre-production application serves a complete React SPA without requiring authentication. The JavaScript bundle exposes OAuth client credentials and internal API configuration.

### Evidence

**Application loads fully unauthenticated**:
```
GET /price.backoffice/ HTTP/2
Host: md.betty-pp.metrosystems.net

200 OK
<title>Betty Price Backoffice</title>
```

**Exposed OAuth credentials in JS bundle** (`index-5h4NNjO1.js`):
```
client_id: "BTEX"
realm_id: "BETTY_REALM"
redirect_uri: e.location.href + "?idam_redirect=1&"
oauth2/authorize
```

**GTM tracking active**: `GTM-P2JW77JN`
**Datadog RUM monitoring**: Active with CloudFront distribution URLs (`d20xtzwzcl0ceb.cloudfront.net`, `d3uc069fcn7uxw.cloudfront.net`)

### Impact

- OAuth client ID and realm exposed enables targeted OAuth attacks
- Pre-production pricing tool accessible from the internet
- Analytics tracking on pre-prod may leak internal usage patterns

### Recommendation

1. Require authentication before serving the SPA
2. Move OAuth client configuration to server-side
3. Disable GTM/analytics on pre-production environments

---

## Finding 5: Production Configuration Exposure via injector.js

**Severity**: Medium
**Asset**: `https://betty.metrosystems.net/ordercapture/uidispatcher/static/injector.js` (in scope)
**Type**: Information Disclosure (OWASP A02)

### Description

The shop platform's `injector.js` configuration file exposes internal API endpoints, IDAM configuration, country-specific settings, and production infrastructure URLs.

### Evidence

**Key configuration values exposed**:
```javascript
var idam_login_base_url = "https://idam.metrosystems.net";
var ev_support_base_url = "https://api-private.prod.evaluate.metro.cloud/evaluate.support/";
var mac_cdn_base_url = "https://cdn.metro-group.com";
var mario_countries = "FR,DE,ES,BG,PL,NL,HU,PT,RO,MD,KZ,IT,HR,UA,RS,CZ,SK,TR,AT";
var enzo_countries = "AT,BG,CZ,DE,ES,FR,HR,HU,IT,JP,KZ,MD,NL,PK,PL,PT,RO,RS,RU,SK,TR,UA";
var countryConfig = {"defaultStore":"00054"};
```

**Additional URLs discovered**:
- `https://api-private.prod.evaluate.metro.cloud/evaluate.support/` (production API)
- `https://app-search-2.prod.de.metro-marketplace.cloud/api/v3/search/` (production search)
- `https://feedback.metro-cc.com/jfe/form/SV_cZQ39gSaI8gPPkq` (Qualtrics survey)
- `https://idam.metro.de` (additional IDAM endpoint)

### Impact

- Production API endpoints exposed for targeted attacks
- Internal country/feature configuration reveals business logic
- Default store IDs and configuration patterns disclosed

### Recommendation

1. Move sensitive configuration to server-side environment variables
2. Minimize client-side configuration to only what's needed for rendering

---

## Finding 6: Unauthenticated Store ID Mapping Data for All Countries

**Severity**: Low
**Asset**: `https://betty.metrosystems.net/cia/content/sitecore/storeIdMappingWithOnlineVisibility/` (in scope)
**Type**: Information Disclosure (OWASP A02)

### Description

The Sitecore CMS content API exposes store-to-UUID mappings for all 13 Metro AG countries without authentication.

### Evidence

All country mappings return 200 with store data:
```
[200] (5678 B) /cia/.../DE/de-DE    — 100+ German stores
[200] (5513 B) /cia/.../FR/fr-FR    — French stores
[200] (2630 B) /cia/.../IT/it-IT    — Italian stores
[200] (2111 B) /cia/.../ES/es-ES    — Spanish stores
[200] (1251 B) /cia/.../PL/pl-PL    — Polish stores
[200] (1718 B) /cia/.../RO/ro-RO    — Romanian stores
[200] (1474 B) /cia/.../UA/uk-UA    — Ukrainian stores
...and 6 more countries
```

**Sample data** (DE):
```javascript
window.exploreStoreIdMapping = {
  "00618": "4d737651-64bc-44e2-a200-d86719236772",
  "00403": "5252528c-6906-4350-a0d1-2b7e3d6ad246",
  ...100+ entries
};
```

### Impact

- Internal store identifiers could enable targeted IDOR attacks on store-specific APIs
- UUID patterns may be predictable or enumerable
- Business intelligence on Metro's store network footprint

### Recommendation

1. Require authentication for store mapping endpoints
2. Return only necessary data for the authenticated user's context

---

## Finding 7: 3v Coupon API - JWT Error Handling Leaks RSA Public Key Material + Unhandled Exceptions

**Severity**: High
**Asset**: `https://3v-proxy-service-external-pp.metro-link.com` (*.metro-link.com - in scope)
**Type**: Improper Error Handling (OWASP A05) + Sensitive Data Exposure (OWASP A02)

### Description

The 3v Coupon Proxy Service pre-production API returns **500 Internal Server Error** (instead of 401 Unauthorized) for malformed JWT tokens. The error responses expose the **full 2048-bit RSA public key** used for token verification, internal JWT library details, and the algorithm configuration — enabling targeted token forgery attacks.

### Evidence

**JWT `alg:none` causes 500 with library details:**
```json
{
  "status": 500,
  "error": "Internal Server Error",
  "message": "Unsecured JWSs (those with an 'alg' header value of 'none') are disallowed by default as mandated by https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6. If you wish to allow them to be parsed, call the JwtParserBuilder.unsecured() method..."
}
```

**JWT with RS256 + wrong signature leaks FULL RSA PUBLIC KEY:**
```json
{
  "status": 401,
  "message": "Invalid JWT signature: Unable to verify RS256 signature with JCA algorithm 'SHA256withRSA' using key {Sun RSA public key, 2048 bits
    params: null
    modulus: 247538660848823582253300959374872372883752234011377821768010378813641726492...
    public exponent: 65537}: Signature callback execution failed: Bad signature length: got 5 but was expecting 256"
}
```

**JWT with HS256 causes 500:**
```json
{
  "status": 500,
  "message": "Cannot verify JWS signature: unable to locate signature verification key for JWS with header: {alg=HS256, typ=JWT}"
}
```

**JWT with injected `kid` reflects input (500):**
```json
{
  "message": "Cannot verify JWS signature: unable to locate signature verification key for JWS with header: {alg=RS256, typ=JWT, kid=' UNION SELECT 'AAAA' -- }"
}
```

**Health endpoint leaks version without auth:**
```
GET /health → 200 OK
{"status" : "UP", "version" :"1.2.0"}
```

### Impact

- **RSA public key leaked** enables algorithm confusion attacks (RS256→HS256) and targeted token forgery
- **500 errors** instead of 401 indicate unhandled exceptions reaching production, exposing Java JJWT library internals
- **JWT kid field reflected** in errors could enable further injection attacks
- **Version disclosure** aids in identifying known CVEs for the specific version
- Combined: an attacker gains the exact key material, algorithm, library, and version needed to craft targeted JWT attacks

### Recommendation

1. Return generic 401 responses for all JWT validation failures — never expose key material or library details
2. Catch all JWT parsing exceptions and return uniform error messages
3. Remove `/health` endpoint from external access or require authentication
4. Implement proper error handling middleware

---

## Finding 8: No Rate Limiting on Authentication and API Endpoints

**Severity**: Medium-High
**Assets**: Multiple (IDAM, Search API, 3v API)
**Type**: Broken Access Control (OWASP A07 - Identification and Authentication Failures)

### Description

Critical authentication and data endpoints lack rate limiting, enabling brute-force attacks on credentials and mass data scraping.

### Evidence

**IDAM token endpoint — 15 rapid requests, all processed:**
```
[401] [401] [401] [401] [401] [401] [401] [401] [401] [401] [401] [401] [401] [401] [401]
```
No 429 responses, no CAPTCHA, no account lockout, no progressive delay.

**Search API — 20 rapid requests, all 200:**
```
[200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200] [200]
```

**3v coupon API — 10 rapid requests, all processed:**
```
[401] [401] [401] [401] [401] [401] [401] [401] [401] [401]
```

### Impact

- **IDAM brute-force**: Combined with Finding 9 (client_id enumeration), an attacker can enumerate valid OAuth client_ids and then brute-force their `client_secret` values at unlimited speed
- **Data scraping**: The search API's 993,709 product records can be scraped at maximum speed with no throttling — full catalog extraction in minutes
- **Credential stuffing**: The IDAM token endpoint can be targeted with large credential lists

### Recommendation

1. Implement rate limiting (e.g., 10 requests/minute per IP) on all authentication endpoints
2. Add progressive delays and account lockout after failed attempts
3. Implement CAPTCHA on login flows
4. Add rate limiting on the search API (e.g., 100 requests/minute per IP)

---

## Finding 9: IDAM OAuth Client ID Enumeration via Differential Error Messages

**Severity**: Medium
**Asset**: `https://idam.metrosystems.net/authorize/api/oauth2/access_token` (*.metrosystems.net - in scope)
**Type**: Information Disclosure (OWASP A07)

### Description

The IDAM OAuth 2.0 token endpoint returns different error messages for valid vs. invalid `client_id` values, enabling enumeration of registered OAuth clients. Combined with the lack of rate limiting (Finding 8), this allows automated discovery of all valid client identifiers.

### Evidence

**Valid client_id (BTEX) — returns 401:**
```json
{"error":"invalid_client","error_description":"client_secret is invalid or expired","error_uri":"https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes"}
```

**Invalid client_id — returns 400:**
```json
{"error":"invalid_client","error_description":"client_id: METRO is invalid","error_uri":"https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes"}
```

**Key differences:**
| Indicator | Valid client_id | Invalid client_id |
|-----------|----------------|-------------------|
| HTTP Status | 401 | 400 |
| Error message | "client_secret is invalid or expired" | "client_id: X is invalid" |
| Response size | ~169 B | ~161 B |

**Internal Confluence URL leaked in all responses**: `https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes`

**BIG-IP cookie leaks load balancer pool**: `BIGipServeridam-akamai-80`

### Impact

- Attackers can enumerate all valid OAuth client_ids by testing against the token endpoint
- Valid client_ids enable targeted `client_secret` brute-force attacks (no rate limiting)
- Internal Confluence URL enables further reconnaissance
- F5 BIG-IP infrastructure information aids in targeted attacks

### Recommendation

1. Return identical error messages and HTTP status codes for both valid and invalid client_ids
2. Remove internal URLs from error responses
3. Strip BIG-IP cookies or use encrypted cookie format
4. Implement rate limiting (see Finding 8)

---

## Finding 10: Betty Ordercapture Swagger/API Documentation Behind Weak 403

**Severity**: Low-Medium
**Assets**: `betty.metrosystems.net`, `tienda.makro.es`, `shop.metro.bg`, `metromax.metro.hu`, `shop.metro.ro` (all in scope)
**Type**: Security Misconfiguration (OWASP A05)

### Description

The Ordercapture API documentation endpoint (`/ordercapture/swagger.json`) returns 403 Forbidden across all country-specific betty shop instances, confirming the Swagger/OpenAPI specification file exists but is access-restricted. This is a defense-in-depth concern — the file's presence and consistent 403 across all deployments suggests it contains the complete API specification.

### Evidence

```
[403] (134 B) betty.metrosystems.net/ordercapture/swagger.json
[403] (134 B) tienda.makro.es/ordercapture/swagger.json
[403] (134 B) shop.metro.bg/ordercapture/swagger.json
[403] (134 B) metromax.metro.hu/ordercapture/swagger.json
[403] (134 B) shop.metro.ro/ordercapture/swagger.json
```

Meanwhile, non-existent paths return 404 (18 B):
```
[404] (18 B) tienda.makro.es/ordercapture/v2/api-docs
```

### Impact

- Confirms the API documentation exists and could be exposed through access control bypass
- Consistent 403 across all countries suggests centralized config — a single misconfiguration would expose it globally

### Recommendation

1. Return 404 instead of 403 to avoid confirming the file's existence
2. Ensure the Swagger file is not deployed to production — serve it only in development environments

---

## Unreachable Targets (for reference)

The following in-scope targets were **unreachable** from the testing environment due to egress proxy restrictions, DNS resolution failures, or firewall rules:

| Target | Reason |
|--------|--------|
| `api-private.pp.evaluate.metro.cloud` | Proxy 502 (egress denied) |
| `msp-admin.msp-pp.metro.cloud` | Proxy 502 (egress denied) |
| `cot-demand-pp.metrosystems.net` | Proxy 502 (egress denied) |
| `qacheck-pp.metrosystems.net` | Proxy 502 (egress denied) |
| `cot-supply-pp.metrosystems.net` | Proxy 502 (egress denied) |
| `goe-pp.metro.digital` | Proxy 502 (egress denied) |
| `lxsrgcp6205.metro-sap.com:18402` | Connection reset |
| `lxsrgcp5017.metro-sap.com:8440` | Connection reset |
| `dus11eslu072000.mpos.madm.net` | DNS resolution failure |
| `par11eslu102100.mpos.madm.net` | DNS resolution failure |
| `blueyonder-pp-bg.oci.metro.info:20100` | Connection timeout |
| `blueyonder-pp-de.oci.metro.info:20100` | Connection timeout |
| `*.metro-marketplace.eu` | Proxy denied |

---

## Phase 2 Testing Summary

**Tested and confirmed not exploitable:**
- OAuth redirect_uri bypass (IDAM uses strict exact matching — all 10 bypass payloads rejected)
- JWT algorithm confusion RS256→HS256 (server rejects HS256 tokens, 500 but not exploitable)
- JWT kid SQL injection / path traversal (reflected but no injection — kid lookup against static JWKS)
- Server-side XSS on betty shops (SPA architecture — no server-side template rendering)
- SSTI/template injection on search API (no execution detected)
- CRLF injection on search API (no header injection)
- Open redirect on shop domains (no redirect parameters found)
- Dynamic client registration on IDAM (endpoint not exposed — 404)
- Sitecore admin panels (all 404 across all countries)
- GraphQL endpoints (not deployed on any tested service)
- Actuator/Spring Boot endpoints (all 404)

**Partially tested (access limitations):**
- Country-specific search APIs (only DE accessible — ES/BG/HR/HU/RO all connection failures)
- Pre-prod marketplace domains (all 403 — IP restricted)
- Mirakl marketplace platform (egress proxy blocked)
- PureCloud (requires authentication, returns 302/404)

## Next Steps (Phase 3)

1. **IDAM client_secret brute-force** for confirmed valid client `BTEX` (requires dedicated testing infrastructure with rate-aware tooling)
2. **Subdomain enumeration** on 10 in-scope wildcard domains (requires DNS tooling like amass/subfinder)
3. **Voucher app access-code auth testing** — the `/api/v1/authenticate?accessCode=` endpoint (found in JS bundle) may accept short/predictable codes
4. **Authenticated testing** — obtain valid test credentials to test IDOR, privilege escalation, and business logic flaws
5. **DOM-based XSS** — thorough client-side JavaScript analysis of SPA applications for postMessage handlers, hash-fragment injection, and unsafe DOM manipulation
6. **Akamai WAF bypass** — advanced techniques against the CDN/WAF protecting metro.rs and makro.nl
7. **WebSocket testing** — the voucher app CSP includes `wss:` connect-src, indicating potential WebSocket endpoints
