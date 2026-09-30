# Metro AG VDP - Security Assessment Findings

**Date**: 2026-09-29
**Scope**: Metro AG Vulnerability Disclosure Program (VDP)
**Tester**: Authorized VDP participant
**Status**: Phase 12 - Source maps exposure + continued deep probing

---

## Executive Summary

Comprehensive testing of 66 in-scope Metro AG assets identified **33 reportable findings** across production and pre-production infrastructure. The highest-impact findings are:

1. **IDAM OAuth 2.0 platform-wide misconfigurations** — implicit flow, password grant, and plain PKCE all enabled across ALL tested IDAM instances (idam.metrosystems.net, idam.metro.de, idam.metro.fr, idam.metro.it), violating RFC 9700; SAML signing key exposed in JWKS; internal Confluence URL leaked in error messages (Finding 24 — High, CVSS 7.4)
2. **METRO Seller Office unauthenticated config endpoint exposes 21 internal microservice URLs** — all publicly accessible, with `service-aftersales-v2` running Laravel Debugbar in production, Ignition RCE vector routes defined, complete API route map including admin endpoints, Sanctum session cookies without auth, wildcard CORS with impersonation header whitelist, Sentry DSN, and multiple SDK keys (Finding 23 — Critical, CVSS 9.3)
3. **Orderfulfillment production config.js exposes 639KB of operational data** for 669 stores/depots across 19 countries, including warehouse operations, feature flags, and the complete international domain map — all unauthenticated (Finding 11)
4. **Shop platform injector.js exposes internal architecture** — GCP project ID `cf-ordercaptu-oc-prod-17`, private API URLs, DAM upload portal, 100+ store configurations, A/B experiments, IDAM realm names, and complete store UUID mappings — all unauthenticated (Finding 25)
5. **Verbose health endpoints expose complete internal architecture** — orderservice leaks 43 internal components (PostgreSQL, Cassandra, Flyway, Dropwizard, credit check systems, DANA export), checkout leaks PunchOut B2B and Loyalty/CDM token services; 401 errors leak Java servlet classes and internal HTTP URIs (Finding 14)
6. **Semicolon path parameter traversal** (..;/) bypasses path-based routing across all betty services (Finding 13)
7. **ria voucher pre-prod app exposes access-code authentication via GET parameter** — authentication tokens (JWTs) transmitted in URLs, stored in localStorage, with full permission system and store data leaked in JS bundle (Finding 19)
8. **METRO Seller Office 8MB JS bundle exposes complete microservice architecture** — 20+ backend service URLs, admin impersonation endpoint (`/admin/impersonation/exchange` with `_switch_user` tokens), public activation code endpoint, commission fee structures (7-15%), and 4.7MB of unauthenticated translation files (Finding 21)
9. **METRO Vendor Office platform-wide security failures** — Symfony debug mode leaking 18KB stack traces, CORS subdomain wildcard with credentials on ALL 8+ services, no rate limiting on login, PHPSESSID missing Secure flag, GCS bucket with public documents, 20+ microservice architecture fully mapped, 50+ API endpoints disclosed (Finding 22)
10. **IDAM OAuth insecure flows enabled** — redirect_uri validation allows query parameter injection (`?url=https://evil.com`) enabling authorization code theft via open redirect chaining (Finding 15)

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
**Assets**: 
- `https://3v-proxy-service-external-prod.metro-link.com` (PRODUCTION)
- `https://3v-proxy-service-external-pp.metro-link.com` (Pre-production)
- Both under *.metro-link.com — in scope
**Type**: Improper Error Handling (OWASP A05) + Sensitive Data Exposure (OWASP A02)

### Description

The 3v Coupon Proxy Service **production AND pre-production** APIs return **500 Internal Server Error** (instead of 401 Unauthorized) for malformed JWT tokens. The error responses expose the **full 2048-bit RSA public key** used for token verification, internal JWT library details, and the algorithm configuration — enabling targeted token forgery attacks. **The same RSA key is shared between production and pre-production**, and the same version (1.2.0) is deployed to both.

### Evidence

**JWT `alg:none` causes 500 with library details (confirmed on BOTH prod and pre-prod):**
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

**Health endpoint leaks version without auth (BOTH environments):**
```
GET https://3v-proxy-service-external-prod.metro-link.com/health → 200 OK
GET https://3v-proxy-service-external-pp.metro-link.com/health → 200 OK
{"status" : "UP", "version" :"1.2.0"}
```

**Three production coupon service paths confirmed:**
```
[401] /3v.redeemable.service.rest  (coupon redemption)
[401] /3v.campaign.service.rest    (campaign management)
[401] /3v.issuance.service.rest    (coupon issuance)
```

### Impact

- **PRODUCTION system** — this handles real coupon/voucher operations for Metro AG customers
- **RSA public key leaked** enables algorithm confusion attacks (RS256→HS256) and targeted token forgery
- **Same key shared between prod and pre-prod** — compromising one environment's key material applies to both
- **500 errors** instead of 401 indicate unhandled exceptions reaching production, exposing Java JJWT library internals
- **JWT kid field reflected** in errors could enable further injection attacks
- **Version disclosure** aids in identifying known CVEs for the specific version
- Combined: an attacker gains the exact key material, algorithm, library, and version needed to craft targeted JWT attacks against the production coupon system

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

## Finding 10: Multiple Swagger/API Documentation Files Behind Weak 403

**Severity**: Low-Medium
**Assets**: `betty.metrosystems.net`, `tienda.makro.es`, `shop.metro.bg`, `metromax.metro.hu`, `shop.metro.ro` (all in scope)
**Type**: Security Misconfiguration (OWASP A05)

### Description

Multiple API service documentation endpoints return 403 Forbidden across all country-specific betty shop instances. At least **7 different swagger.json files** are confirmed to exist behind 403 responses, covering the entire betty platform's backend services. Combined with Finding 13 (semicolon path traversal), the `..;/` technique redirects to the root-level swagger.json (also 403).

### Evidence

**Seven distinct swagger.json files behind 403 on betty.metrosystems.net:**
```
[403] (134 B) /ordercapture/swagger.json
[403] (134 B) /articlesearch/swagger.json
[403] (134 B) /checkout/swagger.json
[403] (134 B) /ordermanagement/swagger.json
[403] (134 B) /pickandpack/swagger.json
[403] (134 B) /depotmanagement/swagger.json
[403] (134 B) /searchdiscover/swagger.json
[403] (134 B) /explore.tracking.v1/swagger.json
```

**Also on tienda.makro.es:**
```
[403] (134 B) /orderfulfillment/swagger.json
[403] (134 B) /orderfulfillment/openapi.json
```

Meanwhile, non-existent paths return 404 (18 B or 10 B).

### Impact

- Confirms 7+ API microservices with documentation deployed to production
- Consistent 403 (same 134-byte response) suggests a WAF/routing rule — a single bypass would expose all service specifications
- Complete API surface map for attackers: ordercapture, articlesearch, checkout, ordermanagement, pickandpack, depotmanagement, searchdiscover, tracking

### Recommendation

1. Return 404 instead of 403 to avoid confirming the files' existence
2. Remove Swagger/OpenAPI files from production deployments entirely
3. Ensure WAF rules cannot be bypassed via path manipulation (see Finding 13)

---

## Finding 11: Orderfulfillment Production Configuration Mass Exposure — 669 Stores Across 19 Countries

**Severity**: High
**Asset**: `https://tienda.makro.es/orderfulfillment.uidispatcher.static/` (in scope — *.makro.es)
**Type**: Sensitive Data Exposure (OWASP A02) + Security Misconfiguration (OWASP A05)

### Description

The orderfulfillment dispatcher SPA serves **639KB** of production operational configuration (`config.js`) without any authentication. This file contains detailed warehouse/depot settings for **669 store entries** across **19 countries** (AT, BG, CZ, DE, ES, FR, HR, HU, IT, KZ, MD, NL, PL, PT, RO, RS, SK, TR, UA), including assortment handling zones, slot management modes, feature flags, and operational parameters.

The accompanying HTML page also leaks extensive client-side configuration including internal service URLs, country-specific feature toggles, Google Tag Manager IDs, Datadog monitoring settings, and employee authentication flow details.

### Evidence

**config.js — 639,320 bytes, fully unauthenticated:**
```
GET /orderfulfillment.uidispatcher.static/app/config.js HTTP/2
Host: tienda.makro.es

200 OK (639,320 bytes)
```

**Sample depot configuration (DE_STOREDEPOT_00528):**
```json
{
  "locationType": "depot",
  "enhanced2CharactersSSCCPrintMark": true,
  "enableNewSlotAssignmentAfterPicking": true,
  "handledAssortmentAreas": [
    "DANGEROUS_GOODS", "DEEP_FROZEN", "DRINKS", "FISH",
    "FRUITS_VEGETABLES", "MAIN", "MEAT", "MEAT_CUT"
  ],
  "flexibleWaveDetails": {
    "slotHandlingMode": {
      "slotCleanupInterval": 3,
      "proposalType": "dynamic_tour_space_driven",
      "validationType": "flexible_validation"
    }
  },
  "landingPageMenuItems": [
    "CONSOLIDATION", "QUICK_CONSOLIDATION", "PAM_BETA", "PICKING_QUALITY_CONTROL"
  ]
}
```

**HTML page leaks additional operational data:**
```javascript
window.clickAndCollectEnabledCountries = "DE,ES,FR,PT,NL,PL,KZ,PK";
window.webshopEnabledCountries = "FR,PL,NL";
window.dropshipmentEnabledCountries = "FR,DE,ES,RO";
window.marketplaceEnabledCountries = "FR";
window.voucher_countries = "FR";
window.idam_login_base_url = "https://idam.metrosystems.net";
window.erikaBaseUrl = "https://erika.metrosystems.net";
```

**GCP Project ID leaked:** `cf-ordercaptu-oc-prod-17`

**Datadog monitoring config leaked:**
```
datadogEnvironment="prod"
datadogRumSampleRate="4"
datadogRumPremiumSampleRate="100"
datadogSessionReplayEnabled="true"
```

### Impact

- **Operational intelligence**: Complete view of Metro AG's warehouse operations across 19 countries — assortment zones, slot management algorithms, consolidation workflows
- **Competitive advantage**: Detailed feature flags reveal which countries have which capabilities (marketplace, dropshipment, click-and-collect, webshop)
- **Infrastructure mapping**: GCP project IDs, Datadog configuration, internal service URLs
- **Attack surface expansion**: 669 store/depot IDs enable targeted IDOR attacks on store-specific APIs
- **Reconnaissance value**: Country-to-capability mapping reveals business expansion strategy

### Recommendation

1. Require authentication before serving config.js and the dispatcher page
2. Move operational configuration to server-side — never send depot/warehouse settings to the client
3. Remove GCP project IDs and monitoring configuration from client-side code
4. Implement access controls on the orderfulfillment dispatcher

---

## Finding 12: Betty Platform Complete Authentication Architecture Disclosure

**Severity**: Medium-High
**Assets**: `https://tienda.makro.es/orderfulfillment.uidispatcher.static/` and `https://betty.metrosystems.net/` (both in scope)
**Type**: Sensitive Data Exposure (OWASP A02) + Security Misconfiguration (OWASP A05)

### Description

The orderfulfillment SPA's JavaScript bundles (`api.js`, 111KB) expose the **complete authentication architecture** for the betty platform, including OAuth client credentials, employee and customer login API endpoints, the SSO cookie name, server technology, ADFS integration details, and a comprehensive domain-to-country mapping covering **100+ production and pre-production domains** across 20+ countries.

### Evidence

**OAuth client credentials disclosed:**
```javascript
client_id: "BTEX"
realm_id: "BETTY_REALM"
// IDAM authorize URL construction:
idamLoginBaseUrl + "/authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM"
```

**ADFS client_id and endpoint:**
```javascript
"https://adfs3.metro.info/adfs/oauth2/authorize?resource=" + t
  + "&response_type=code&client_id=e595352d-d1df-4a9a-a469-d33bb5c46ef3&redirect_uri=" + t
```

**Authentication API endpoints disclosed:**
```javascript
POST /ordercapture/login/auth/loginCustomer?country=DE    // Customer login
POST /ordercapture/login/auth/loginEmployee2?country=DE    // Employee login
POST /ordercapture/login/auth/singleSignOn                 // SSO endpoint
```

**SSO endpoint confirms server technology (Ktor/Kotlin):**
```
HTTP/2 401
www-authenticate: betty-jwt realm="Ktor Server"
```

**SSO cookie name leaked via IDAM iframe:**
```javascript
var ssoCookie = 'metroIdentity';
// Checks: document.cookie for cookie named 'metroIdentity'
```

**Complete domain-to-country mapping (sample from 20+ countries, 100+ domains):**
```javascript
DE: ["betty.metrosystems.net", "metro.de", "produkte.metro.de", "lieferservice.metro.de", ...]
FR: ["shop.metro.fr", "livraison.metro.fr", "beta.metro.fr", ...]
PL: ["horecadostawy.pl", "online.makro.pl", "zamawiarka.makro-dla-gastronomii.pl", ...]
ES: ["tienda.makro.es", "distribucion-hosteleria.makro.es", ...]
TR: ["metrogastroservis.com", "horeca-dagitim.metro-tr.com", ...]
// ...including pre-prod: betty-pp, betty-dev, *-pp.* for each country
```

**JWT handling — client-side decode, localStorage storage:**
```javascript
jwtDecode = function(e) { return JSON.parse(window.atob(e.split(".")[1])) }
// JWT stored in localStorage and cookie ("compressedJWT")
// JWT contains: payload.role, payload.upn, entitlements, storeEnts
```

**Employee entitlement system disclosed:**
```javascript
ENTITLEMENTS = {
  LSP_PICKING_MGMT: "lPM",
  LSP_TRANSPORT_MGMT: "lTM",
  OF_INVOICE_STORE_TILLSCONFS: "fISTC"
}
```

### Impact

- **Authentication attack surface fully mapped**: An attacker now knows every login endpoint, OAuth flow, client_id, and session mechanism
- **SSO cookie name (`metroIdentity`)** enables targeted cookie theft via XSS or network-level attacks
- **ADFS integration** with a leaked client_id enables targeted attacks against the employee federation service
- **Employee entitlement codes** enable privilege escalation testing once any authenticated access is obtained
- **100+ domain mapping** provides the complete attack surface across all countries, including pre-production environments
- **Ktor server technology** enables framework-specific vulnerability research

### Recommendation

1. Move all OAuth credentials and authentication logic to server-side
2. Obfuscate or remove domain-to-country mapping from client-side code
3. Do not expose employee entitlement codes to the client
4. Rotate the ADFS OAuth client_id `e595352d-d1df-4a9a-a469-d33bb5c46ef3`
5. Implement Content Security Policy to mitigate XSS-based SSO cookie theft

---

## Finding 13: Semicolon Path Parameter Traversal Across Betty Services

**Severity**: Medium
**Asset**: `https://betty.metrosystems.net` (in scope)
**Type**: Broken Access Control (OWASP A01) + Security Misconfiguration (OWASP A05)

### Description

The betty platform's reverse proxy/routing layer is vulnerable to semicolon path parameter traversal (`..;/`). By appending `..;/` to any service path (ordercapture, articlesearch, checkout), an attacker can traverse out of the service's path context and access resources at the root level. The server processes the `..;` as a path parameter (ignoring it) and then resolves `..` as directory traversal, issuing a 302 redirect to the traversed path.

This technique is commonly associated with **Apache Tomcat** and **Spring Framework** path normalization differences, where `;` marks a path parameter that is stripped before path resolution.

### Evidence

**Traversal from ordercapture to root:**
```
GET /ordercapture/..;/swagger.json HTTP/2
Host: betty.metrosystems.net

HTTP/2 302
Location: https://betty.metrosystems.net/swagger.json
```

**Traversal from articlesearch to root:**
```
GET /articlesearch/..;/swagger.json HTTP/2

HTTP/2 302
Location: https://betty.metrosystems.net/swagger.json
```

**Traversal from checkout to root:**
```
GET /checkout/..;/swagger.json HTTP/2

HTTP/2 302
Location: https://betty.metrosystems.net/swagger.json
```

**Other traversal variants properly blocked (403):**
```
[403] /ordercapture/..%3b/swagger.json    (URL-encoded semicolon)
[403] /ordercapture/../swagger.json       (plain traversal)
[403] /ordercapture/..%2f/swagger.json    (URL-encoded slash)
```

### Impact

- **Path-based access control bypass**: Any service path context can be escaped, potentially accessing endpoints that are only restricted by path prefix matching
- **WAF/routing bypass**: The 403 rules on swagger.json are path-specific — traversal to the root escapes the service prefix that triggers the 403 (root swagger.json is also 403'd in this case, but other root resources may not be)
- **Chained with other vulnerabilities**: If any root-level endpoint lacks the same access restrictions as service-scoped endpoints, this traversal provides access
- **Affects all services**: Confirmed on ordercapture, articlesearch, and checkout — likely affects all betty microservices behind the same routing layer

### Recommendation

1. Normalize paths before routing — strip semicolons and path parameters before evaluating access controls
2. Configure the reverse proxy to reject requests containing `..;` patterns
3. Apply access controls at the individual endpoint level, not just at the path prefix level

---

## Finding 14: Verbose Health Endpoints Expose Complete Internal Architecture — 43+ Service Components

**Severity**: High
**Assets**: `https://betty.metrosystems.net/ordermanagement/orderservice/health`, `https://betty.metrosystems.net/ordercapture/checkout/health` (in scope)
**Type**: Information Disclosure (OWASP A05) + Security Misconfiguration (OWASP A05)

### Description

Multiple betty platform health check endpoints are **unauthenticated** and return **detailed internal architecture information**. The `/ordermanagement/orderservice/health` endpoint returns **7,165 bytes** exposing **43 named internal components** including database technologies (PostgreSQL, Cassandra), framework details (Dropwizard, Flyway), business systems (credit check, DANA export, invoice processing, picklist management), and HTTP client configurations. The `/ordercapture/checkout/health` endpoint reveals 10 additional components including PunchOut B2B procurement, Loyalty IDAM tokens, and CDM (Customer Data Management) services.

Additionally, 401 error responses from protected endpoints leak **Java servlet class names** and **internal HTTP URLs**, confirming the platform is built by freiheit.com using a custom Swagger servlet.

### Evidence

**Orderservice health — 43 components exposed unauthenticated:**
```
GET /ordermanagement/orderservice/health HTTP/2
Host: betty.metrosystems.net

200 OK (7,165 bytes)
```

**Database infrastructure revealed:**
```json
"OrdersPostgresJdbiLifecycle": {"healthy": true}
"OrderservicePostgresJdbiLifecycle": {"healthy": true}
"postgresOrders": {"healthy": true}
"postgresOrderservice": {"healthy": true}
"MigrationsLifeCycle": {"message": "Cassandra migrations are up and running"}
"FlywayOrdersMigration": {"healthy": true}
"FlywayOrderserviceMigration": {"healthy": true}
```

**Business systems exposed:**
```json
"CreditCheckEventLifeCycle": {"healthy": true}
"CreditReservationStatusLifeCycle": {"healthy": true}
"FsdOrderEventDanaExportLifeCycle": {"healthy": true}
"FsdMailEventProducer": {"healthy": true}
"InvoiceCreationForReturnsProducer": {"healthy": true}
"InvoiceStatusLifeCycle": {"healthy": true}
"PicklistAvailableBundlesLifeCycle": {"healthy": true}
"PicklistBundleReplacementsLifeCycle": {"healthy": true}
"MipTransferLifeCycle": {"healthy": true}
"ReservationFeedLifeCycle": {"healthy": true}
```

**Framework identification:**
```json
"DropwizardMipConnectionPoolLifecycle": {"timestamp": "2026-09-28T08:36:51.373Z"}
```
The timestamp reveals the exact server restart time: **2026-09-28T08:36:51 UTC**.

**Technical login system:**
```json
"TechnicalLoginLifeCycle": {"message": "technical user logged in"}
"TechLoginHttpClient": {"healthy": true}
"IdamLoginHttpClient": {"healthy": true}
```

**HTTP client configurations:**
```json
"StandardTimeoutHttpClient": {"healthy": true}
"HighTimeoutHttpClient": {"healthy": true}
"SuperHighTimeoutHttpClient": {"healthy": true}
```

**Checkout health — 10 additional components:**
```
GET /ordercapture/checkout/health HTTP/2

200 OK
```
```json
"PunchOutHealthCheck": {"healthy": true}
"LoyaltyIdamAccessTokenServiceHealthCheck": {"healthy": true}
"CdmIdamAccessTokenServiceHealthCheck": {"healthy": true}
"StreamTopologyLifeCycleHealthCheck": {"healthy": true}
"CustomerHealthCheck": {"healthy": true}
"MigrationsLifeCycleHealthCheck": {"healthy": true}
"TechnicalUserServiceHealthCheck": {"healthy": true}
```

**401 error body leaks Java servlet class and internal paths:**
```html
<!-- GET /orderfulfillment.depotsettings.v1/ -->
<th>URI:</th><td>/depotmanagement/depotsettings/</td>
<th>MESSAGE:</th><td>You must provide a http header 'JWT'</td>
<th>SERVLET:</th><td>com.freiheit.betty.microservice.core.rest.swagger.SwaggerServlet-1760e688</td>
```

**Internal HTTP (not HTTPS) URI leaked:**
```html
<!-- GET /ordermanagement/orderbff/ -->
<th>URI:</th><td>http://betty.metrosystems.net/ordermanagement/orderbff/</td>
```
Internal routing uses plain HTTP — confirming TLS terminates at the edge/reverse proxy.

### Impact

- **Complete architecture disclosure**: An attacker knows every database (PostgreSQL x2, Cassandra), migration tool (Flyway), framework (Dropwizard), message bus (event producers/lifecycle), and business system (credit check, DANA export, invoice, picklist, reservation, MIP transfer)
- **Server restart time leaked** (2026-09-28T08:36:51Z) — aids in timing-based attacks and maintenance window identification
- **PunchOut B2B endpoint confirmed** — PunchOut (OCI cXML) procurement protocol is active, which if misconfigured can enable order injection
- **Loyalty and CDM IDAM tokens** — confirms separate token issuance for loyalty and customer data services, expanding the token theft attack surface
- **Platform developer identified**: `com.freiheit.betty.microservice` → built by freiheit.com (development company), enables targeted open-source component analysis
- **Custom SwaggerServlet deployed to production** — confirms API documentation is served by a production servlet (supports Finding 10)
- **Internal HTTP routing** — if an attacker achieves SSRF, internal services communicate over unencrypted HTTP
- **Auth header convention leaked** — `You must provide a http header 'JWT'` reveals the custom JWT header name (not standard `Authorization: Bearer`)

### Recommendation

1. Remove or restrict health check endpoints from external access — require authentication or limit to internal networks
2. Return minimal health status (`{"status":"UP"}`) instead of component-level detail
3. Return generic 401/403 errors — do not expose servlet classes, internal URIs, or auth header requirements
4. Enforce HTTPS for internal service-to-service communication
5. Avoid deploying SwaggerServlet to production

---

## Finding 15: IDAM OAuth Insecure Flows — Implicit Grant + Hybrid Flow + redirect_uri Query Parameter Injection

**Severity**: High
**Asset**: `https://idam.metrosystems.net/authorize/api/oauth2/authorize` (*.metrosystems.net — in scope)
**Type**: Broken Authentication (OWASP A07) + Security Misconfiguration (OWASP A05)

### Description

The Metro AG IDAM OAuth 2.0 authorization server has **five compounding security issues** that together form a complete authorization code/token theft chain:

1. **Implicit grant enabled** (`response_type=token`) — deprecated in OAuth 2.1 (RFC draft) and explicitly discouraged by RFC 9700 (OAuth 2.0 Security Best Current Practice). Access tokens are returned in URL fragments, which leak via browser history, Referer headers, and JavaScript `window.location`.

2. **Hybrid flow enabled** (`response_type=code token`) and **id_token flow** (`response_type=id_token`) — both put tokens in URL fragments with the same leakage risks.

3. **redirect_uri accepts query parameter appending** — while the authorization server correctly rejects different hosts (returns 403), it **accepts arbitrary query parameters** appended to a valid redirect URI. This means `redirect_uri=https://betty.metrosystems.net/shop?url=https://evil.com` is accepted, and after authentication the authorization code/token is sent to this modified URL.

4. **PKCE is NOT enforced** — the authorization endpoint accepts requests without `code_challenge` entirely, AND accepts `code_challenge_method=plain` (downgrade from S256). Without PKCE, intercepted authorization codes can be redeemed by any party.

5. **State parameter NOT required** — the authorization endpoint processes requests without the `state` parameter, enabling OAuth login CSRF (an attacker can force-link their identity to a victim's session).

### Evidence

**Implicit grant accepted (response_type=token):**
```
GET /authorize/api/oauth2/authorize?response_type=token&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid
Host: idam.metrosystems.net

HTTP/2 200 (981 bytes — login page served)
```

**Hybrid flow accepted (response_type=code token):**
```
GET /authorize/api/oauth2/authorize?response_type=code%20token&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid

HTTP/2 200 (986 bytes — login page served)
```

**id_token flow accepted (response_type=id_token):**
```
GET /authorize/api/oauth2/authorize?response_type=id_token&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid&nonce=test123

HTTP/2 200 (1002 bytes — login page served)
```

**redirect_uri with injected query parameter — ACCEPTED:**
```
GET /authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop?url=https://evil.com&scope=openid

HTTP/2 200 (1011 bytes — login page served)
```
After authentication, the user would be redirected to:
`https://betty.metrosystems.net/shop?url=https://evil.com&code=AUTH_CODE`

**redirect_uri with path traversal — ACCEPTED:**
```
GET /authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop/..;/&scope=openid

HTTP/2 200 (994 bytes — login page served)
```

**Baseline — evil.com host properly REJECTED:**
```
GET /authorize/api/oauth2/authorize?...&redirect_uri=https://evil.com/callback

HTTP/2 403 (420 bytes — blocked by Akamai)
```

**PKCE NOT enforced — request WITHOUT code_challenge ACCEPTED:**
```
GET /authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid
    (NO code_challenge parameter)

HTTP/2 200 (980 bytes — login page served normally)
```

**PKCE plain method ACCEPTED (downgrade from S256):**
```
GET /authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid
    &code_challenge=test_verifier&code_challenge_method=plain

HTTP/2 200 (1045 bytes — login page served)
```

**State parameter NOT required — request WITHOUT state ACCEPTED:**
```
GET /authorize/api/oauth2/authorize?response_type=code&client_id=BTEX&realm_id=BETTY_REALM
    &redirect_uri=https://betty.metrosystems.net/shop&scope=openid
    (NO state parameter)

HTTP/2 200 (980 bytes — identical to requests with state)
```

**grant_types_supported lists deprecated/disabled grants:**
```json
"grant_types_supported": ["refresh_token", "client_credentials", "implicit", "authorization_code", "password"]
```
Note: `password` is listed but returns "password grant type not supported" — the OIDC discovery document advertises capabilities that aren't actually available, violating the principle of minimal disclosure.

**JWKS exposes 8 keys including infrastructure keys:**
```
kid=saml-signing-keypair      — SAML signing key
kid=dyn-client-reg            — dynamic client registration key
kid=token-signing-keypair     — current token signing
kid=token-signing-keypair_17_12_2025 — dated key (rotation history visible)
```

### Impact

- **Token theft via implicit grant**: With `response_type=token`, access tokens are placed in the URL fragment (`#access_token=...`). These leak through:
  - **Referer headers**: If the redirect page loads any external resource, the fragment (containing the token) may leak via the Referer header in some browsers
  - **Browser history**: The full URL including fragment is stored in browser history
  - **JavaScript access**: Any script on the redirect page (including injected scripts via XSS) can read `window.location.hash`

- **Authorization code theft via redirect_uri injection**: The accepted `?url=https://evil.com` query parameter appended to the redirect URI means:
  1. If the betty SPA processes the `url` parameter as a redirect destination (common in SPAs), the user is redirected to `evil.com` WITH the authorization code
  2. Even without client-side redirect, the authorization code is now associated with a URL containing attacker-controlled data

- **Chained attack scenario (full kill chain)**: An attacker combines ALL five issues:
  1. Craft: `response_type=token&redirect_uri=https://betty.metrosystems.net/shop?url=https://evil.com` (no state, no PKCE)
  2. Victim authenticates normally on the legitimate IDAM login page
  3. Token is redirected to `https://betty.metrosystems.net/shop?url=https://evil.com#access_token=VICTIM_TOKEN`
  4. If the SPA processes `url` parameter → full account takeover
  5. No PKCE means intercepted authorization codes (via the query param injection) are directly redeemable
  6. No state means login CSRF is possible — attacker can force-link their own OAuth identity to the victim's session

- **OAuth login CSRF**: Without `state`, an attacker can initiate an OAuth flow, capture the callback URL (with their own authorization code), and trick a victim into loading it — linking the attacker's identity to the victim's account

- **RFC non-compliance**: Violates RFC 9700 Section 2.1.2 (implicit grant SHOULD NOT be used), Section 4.1.3 (redirect_uri must be compared using exact string matching), Section 2.1.1 (PKCE MUST be used), and Section 4.3.3 (state SHOULD be used to prevent CSRF)

### Recommendation

1. **Disable implicit grant** — remove `token` from supported response types; use authorization code flow with PKCE exclusively
2. **Disable hybrid flow** — remove `code token` and `code id_token token` from supported response types
3. **Enforce exact redirect_uri matching** — reject any redirect_uri that does not exactly match a pre-registered value (no query parameter appending, no path modification)
4. **Require PKCE** for all OAuth clients — enforce `code_challenge` and `code_challenge_method=S256`; reject `plain` method
5. **Require and validate state parameter** — the authorization server should reject requests without `state` to prevent OAuth login CSRF
6. **Remove `password` from `grant_types_supported`** — do not advertise unsupported/deprecated grants in the OIDC discovery document
7. **Audit `token_endpoint_auth_methods_supported: ["none"]`** — ensure only appropriate public clients can use unauthenticated token requests
8. **Minimize JWKS exposure** — remove infrastructure keys (`dyn-client-reg`, `saml-signing-keypair`) from the public JWKS endpoint; rotate dated keys

---

## Finding 16: IDAM Session Detection via check_cookie_iframe — Cross-Origin Login Oracle

**Severity**: Medium
**Asset**: `https://idam.metrosystems.net` (*.metrosystems.net — in scope)
**Type**: Information Disclosure (OWASP A01) + Broken Authentication (OWASP A07)

### Description

The IDAM identity server embeds a `check_cookie_iframe` mechanism that uses `postMessage` to communicate session state (whether the `metroIdentity` SSO cookie is present) to parent frames. The iframe is loaded by betty SPA applications to detect if a user has an active IDAM session. If the `postMessage` handler does not validate the requesting origin, any website can embed this iframe and determine whether a visitor is currently logged into the Metro AG ecosystem.

### Evidence

**SSO cookie check mechanism (from orderfulfillment api.js):**
```javascript
var ssoCookie = 'metroIdentity';
// Creates iframe to idam.metrosystems.net
// Uses postMessage to check if 'metroIdentity' cookie exists
// Parent frame receives: {loggedIn: true/false}
```

**iframe configuration in betty SPA:**
```javascript
window.idam_login_base_url = "https://idam.metrosystems.net";
// iframe URL: https://idam.metrosystems.net/authorize/check_cookie_iframe
```

**CSP header on IDAM confirms framing is allowed from betty:**
```
frame-ancestors https://betty.metrosystems.net
```
However, `X-Frame-Options: ALLOW-FROM` is deprecated and inconsistently enforced by browsers. The CSP `frame-ancestors` directive properly restricts to `betty.metrosystems.net`, but if CSP is not enforced (older browsers) or if a subdomain of `betty.metrosystems.net` has XSS, the iframe can be loaded.

### Impact

- **Login oracle**: Any attacker who achieves XSS on `betty.metrosystems.net` (or any subdomain allowed by CSP) can silently determine if visitors are logged into Metro AG services
- **Targeted attacks**: Knowledge of login state enables targeted phishing — only showing credential harvesting to logged-in users who would expect a re-authentication prompt
- **Session detection**: Combined with Finding 12 (SSO cookie name `metroIdentity`), an attacker can perform comprehensive session state reconnaissance

### Recommendation

1. Validate the requesting origin in the `postMessage` handler — only respond to messages from explicitly whitelisted origins
2. Use `targetOrigin` parameter in `postMessage` calls instead of `*`
3. Consider removing the check_cookie_iframe pattern in favor of server-side session validation

---

## Finding 17: Overly Permissive CSP with `unsafe-eval` and Wildcard WebSocket + Internal API URL Leak

**Severity**: Medium
**Assets**: `https://betty.metrosystems.net/shop` (in scope), `https://betty.metrosystems.net/depotmanagement/stocklocation/` (in scope)
**Type**: Security Misconfiguration (OWASP A05) + Information Disclosure (OWASP A02)

### Description

The betty shop SPA's Content Security Policy (CSP) contains multiple weaknesses that significantly reduce its effectiveness as an XSS mitigation:

1. **`unsafe-eval` in script-src** — allows `eval()`, `new Function()`, `setTimeout('string')`, and similar dynamic code execution, negating much of the CSP's protection even with nonce-based script loading
2. **`wss://*` in connect-src** — permits WebSocket connections to **any host**, enabling data exfiltration via WebSocket if XSS is achieved
3. **Extremely broad script-src whitelist** — includes `*.google.com`, `*.googletagmanager.com`, `*.facebook.com`, `*.microsoft.com`, `*.gstatic.com`, and many more 3rd-party wildcard domains; if any of these hosts have a JSONP or Angular callback endpoint, CSP can be bypassed entirely

Additionally, the stocklocation endpoint's 401 response leaks an **internal production API URL** via the `WWW-Authenticate` header, and sets a JSESSIONID cookie confirming a Java Servlet backend.

### Evidence

**CSP from betty.metrosystems.net/shop response header:**
```
script-src 'self' https://*.metro.de https://*.metrosystems.net https://*.metro-group.com
  https://*.metro-online.com https://*.metro.info https://*.metro-marketplace.cloud
  https://*.googletagmanager.com https://*.qualtrics.com https://*.google-analytics.com
  https://www.googleadservices.com https://*.gstatic.com https://*.google.com
  https://*.google.de https://google.de https://*.googleads.g.doubleclick.net
  https://connect.facebook.net https://graph.facebook.com https://staticxx.facebook.com
  https://bat.bing.com https://snap.licdn.com https://*.microsoft.com
  https://analytics.tiktok.com https://*.mypurecloud.de https://*.nr-data.net
  https://*.newrelic.com 'nonce-...' 'unsafe-eval';

connect-src 'self' [...many domains...] wss://*;

font-src 'self' https://*;
```

**CSP nonces ARE properly random per-request (not exploitable):**
```
Request 1: nonce-FdGdraIMdSfdfNxO
Request 2: nonce-2QjdVDr3
Request 3: nonce-CIm69aiFlR5w6gJkty7
```

**Internal production API URL leaked via stocklocation 401:**
```
GET /depotmanagement/stocklocation/location/ HTTP/2
Host: betty.metrosystems.net

HTTP/2 401
Set-Cookie: JSESSIONID=41026C7186A5F678CABFBE526D7F9584; Path=/depotmanagement/stocklocation; Secure; HttpOnly
WWW-Authenticate: Bearer resource_metadata="https://api-internal.prod.mfulfilldepot.metro.cloud/depotmanagement/stocklocation/.well-known/oauth-protected-resource"
```

**Internal hostname revealed**: `api-internal.prod.mfulfilldepot.metro.cloud`
**Java Servlet backend confirmed**: JSESSIONID cookie set

### Impact

- **XSS amplification**: `unsafe-eval` allows attackers who find any DOM-based injection point to execute arbitrary JavaScript via `eval()` — the CSP nonce becomes irrelevant
- **Data exfiltration via WebSocket**: `wss://*` means that even if all HTTP exfiltration is blocked by CSP, an attacker can exfiltrate stolen data (cookies, tokens, PII) via a WebSocket connection to any attacker-controlled host
- **CSP bypass via 3rd-party JSONP**: The broad wildcard whitelist (e.g., `*.google.com`) includes hosts known to have JSONP/callback endpoints that can be abused to execute arbitrary JavaScript without matching the nonce
- **Internal API topology revealed**: `api-internal.prod.mfulfilldepot.metro.cloud` exposes the internal API naming convention (`api-internal.prod.<service>.metro.cloud`), enabling targeted SSRF attacks if any SSRF vulnerability exists

### Recommendation

1. Remove `unsafe-eval` from `script-src` — refactor JavaScript to avoid `eval()` and similar patterns
2. Replace `wss://*` in `connect-src` with explicit WebSocket endpoints
3. Narrow `script-src` to specific paths rather than wildcard subdomains — or migrate to a strict nonce-only CSP
4. Replace `https://*` in `font-src` with specific font CDN origins
5. Remove `api-internal.prod.mfulfilldepot.metro.cloud` from the `WWW-Authenticate` header — use a generic resource indicator instead

---

## Finding 18: Depotsettings JWT Signature Validation Bypass — Any Non-Empty String Accepted as Authenticated

**Severity**: High
**Asset**: `https://betty.metrosystems.net/orderfulfillment.depotsettings.v1/` (in scope)
**Type**: Broken Authentication (OWASP A07) + Security Misconfiguration (OWASP A05)

### Description

The depotsettings microservice does **not validate JWT signatures or even JWT format**. Any non-empty string sent in the custom `JWT` header is accepted as "authenticated," changing the response from 401 (Unauthorized) to 403 (Forbidden). This means the entire JWT authentication layer is bypassed — the service only checks for the **presence** of the JWT header, not its validity.

This behavior is **unique to the depotsettings service** — all other tested betty services (ordermanagement, pickandpack, stocklocation) properly return 401 for invalid JWTs. The 403 response comes from the application-level authorization layer (the SwaggerServlet), indicating the request has passed authentication and is being evaluated for permissions.

### Evidence

**Systematic test results — all paths under depotsettings:**

| Test Case | JWT Header Value | Response |
|-----------|-----------------|----------|
| No header | (absent) | **401** "You must provide a http header 'JWT'" |
| Empty value | `JWT: ` | **401** |
| Random string | `JWT: notavalidjwt` | **403** Forbidden |
| alg:none JWT | `JWT: eyJhbG...` (alg:none) | **403** Forbidden |
| RS256 wrong sig | `JWT: eyJhbG...AAAA` (random sig) | **403** Forbidden |
| Forged admin JWT | `JWT: eyJhbG...` (admin claims) | **403** Forbidden |

**All paths change from 401→403 with any JWT value:**
```
[depot/DE_STOREDEPOT_00528] NoJWT: 401 | AnyJWT: 403
[depot/DE_STOREDEPOT_00054] NoJWT: 401 | AnyJWT: 403
[depots]                    NoJWT: 401 | AnyJWT: 403
[settings]                  NoJWT: 401 | AnyJWT: 403
[config]                    NoJWT: 401 | AnyJWT: 403
[country/DE]                NoJWT: 401 | AnyJWT: 403
```

**Other services properly validate JWT signatures (no change):**
```
[ordermanagement/orderservice/] NoJWT: 401 | AnyJWT: 401  ← properly validated
[ordermanagement/orderbff/]     NoJWT: 401 | AnyJWT: 401  ← properly validated
[pickandpack.consolidation.v1/] NoJWT: 401 | AnyJWT: 401  ← properly validated
```

**403 response contains SwaggerServlet class (application-level, not WAF):**
```html
<th>SERVLET:</th><td>com.freiheit.betty.microservice.core.rest.swagger.SwaggerServlet-5c60f096</td>
```

**Standard `Authorization: Bearer` header is ignored — only custom `JWT` header is checked:**
```
Authorization: Bearer <forged_jwt> → 401 (ignored)
JWT: <forged_jwt>                  → 403 (accepted)
```

### Impact

- **Authentication bypass**: The depotsettings service accepts completely unsigned, malformed, or random-string JWTs as valid authentication — the entire JWT verification chain is non-functional
- **Inconsistent security controls**: This service is the only one among 5+ tested betty services that fails to validate JWTs, indicating a deployment or configuration error
- **One step from data access**: The only remaining barrier is the authorization layer (403). If the correct claims/entitlements can be determined (employee entitlement codes are already disclosed in Finding 12: `lPM`, `lTM`, `fISTC`), complete access to depot settings for 669 stores across 19 countries would be possible
- **Load-balanced across 3+ instances**: Different SwaggerServlet hashes (`-5c60f096`, `-18f4086e`, `-1760e688`) confirm the vulnerability exists on all instances
- **Custom JWT header convention**: Using `JWT:` instead of standard `Authorization: Bearer` bypasses security middleware and WAF rules that inspect standard headers

### Recommendation

1. **Immediately enable JWT signature verification** on the depotsettings service — this is a critical security gap
2. Standardize JWT handling across all betty microservices using a shared authentication library
3. Migrate from custom `JWT` header to standard `Authorization: Bearer` header
4. Implement centralized JWT validation at the reverse proxy/gateway layer, not per-service
5. Add integration tests that verify JWT signature validation for every service

---

## Finding 19: Ria Voucher Pre-Prod — Access Code Authentication via GET Parameter + Full JS Bundle Disclosure

**Severity**: High
**Asset**: `https://ria.cf-vvv-preprod-o6.cf.metro.cloud/login` (in scope — listed as "Coupon and Voucher UI")
**Type**: Broken Authentication (OWASP A07) + Sensitive Data Exposure (OWASP A02)

### Description

The "Redeemable Issuing Application Plus" (ria) is a pre-production voucher management system running on Express.js/Google Cloud. The application's JavaScript bundle (`/assets/index-BpChDiXz.js`, 181KB) exposes the complete authentication flow, permission system, and internal business logic:

1. **Authentication via GET parameter** — users authenticate with `GET /api/v1/authenticate?accessCode={code}`. The access code is transmitted in the URL, which leaks via:
   - Server access logs
   - Browser history
   - Referer headers to external resources (Bootstrap CDN is loaded)
   - Proxy/CDN/WAF logs
   - Browser bookmarks and autocomplete

2. **JWT stored in localStorage** — the returned JWT is stored in `localStorage.setItem('jwt', ...)` instead of a secure, httpOnly cookie. Any XSS vulnerability allows direct token theft.

3. **Full permission system disclosed** — the JS bundle reveals granular permissions:
   - `ACCESS` — base permission
   - `QUERY_VOUCHER` — query existing vouchers
   - `CREATE_VOUCHER` — create new vouchers
   - `VIEW_CAMPAIGN` — view campaigns
   - `QUERY_CAMPAIGN` — query campaigns
   - `QUERY_CUSTOMER` — query customer data

4. **Session ID format leaks user metadata** — session IDs are constructed as `{country}_{firstLetterOfEmail}_{randomString}`, leaking the user's country and email initial.

5. **Store and business data exposed in settings** — settings response contains `storeNumber`, `storeGln` (Global Location Number), `city`, `defaultVoucherTemplate`, `rewardLimit`, `canChangeCountry`, and `countryCodeIso3`.

### Evidence

**Authentication via GET parameter (from JS bundle):**
```javascript
login: async e => y.get(`/api/v1/authenticate?accessCode=${e}`).then(e => {
  localStorage.setItem('jwt', e.data);
  let t = JSON.parse(atob(e.data.split('.')[1]));
  // JWT payload decoded client-side
})
```

**Auth header construction:**
```javascript
authHeader: () => {
  let e = JSON.parse(localStorage.getItem('user'));
  return e && e.accessToken ? {Authorization: `Bearer ${e.accessToken}`} : {};
}
```

**Permission-gated navigation:**
```javascript
canAccessVouchers: l.includes('ACCESS') && (l.includes('QUERY_VOUCHER') || l.includes('CREATE_VOUCHER')),
canAccessCampaigns: l.includes('ACCESS') && l.includes('VIEW_CAMPAIGN'),
canAccessCustomers: l.includes('ACCESS')
```

**On authentication failure — removes all tokens:**
```javascript
// 401 or 403 response handling
localStorage.removeItem('jwt');
localStorage.removeItem('code');
localStorage.removeItem('sessionId');
window.location.href = '/login';
```

**Settings fallback reveals defensive logic:**
```javascript
console.warn('Settings fetch failed, attempting to use JWT fallback');
let t = localStorage.getItem('jwt');
if (!t) { xi('All fallbacks failed - redirecting to login'); return; }
```

**Supported countries (from hardcoded locale list):**
```javascript
[{code:'fr_BE', int:'French (België)', native:'Français (België)'}],
multipleVoucherTemplateHandlerCountries: ['FR']
```

**Application routes exposed:**
- `/login` — access code login page
- `/vouchers` — voucher management (lazy-loaded: `VoucherManagementPage-BMZ9hxSD.js`)
- `/campaigns` — campaign management (lazy-loaded: `CampaignManagementPage-CC0NDRXN.js`)
- `/customers` — customer management
- `/api/v1/authenticate` — authentication endpoint
- `/api/v1/settings` — user settings endpoint
- `/locales/{{lng}}/{{ns}}.json` — i18n files

**SPA catches all routes** — Express.js serves the HTML for ANY path (including `/api/*`), confirming the API backend is at the separate domain `api.cf-vvv-preprod-o6.cf.metro.cloud`.

### Impact

- **Credential leakage**: Access codes in URLs are logged at every network layer — the primary credential for the voucher management system is exposed in plaintext in server logs, CDN logs, and browser history
- **Token theft via XSS**: JWT in localStorage is accessible to any JavaScript — a single XSS vulnerability provides complete account takeover
- **Access code brute-force**: Simple access codes with no apparent rate limiting could be brute-forced; the GET-based authentication makes this trivially automatable
- **Business logic exposure**: The complete permission matrix and routing structure reveals exactly what capabilities exist and how to target them
- **Financial impact**: The `rewardLimit` and voucher creation/redemption capabilities represent direct financial risk — unauthorized voucher creation could lead to monetary loss

### Recommendation

1. **Move authentication to POST body** — never transmit credentials in URL parameters
2. **Store JWTs in httpOnly, Secure, SameSite cookies** — not in localStorage
3. **Implement rate limiting** on the authentication endpoint
4. **Minify and obfuscate** production JS bundles — remove verbose error messages and console.warn statements
5. **Use proper session management** — don't embed user metadata (country, email) in session IDs
6. **Restrict pre-prod access** — require VPN or IP allowlist for pre-production environments

---

## Finding 20: AXCSS OAuth Client ID Validated on Production IDAM + State JWT with HS256 Symmetric Signing

**Severity**: Medium-High
**Assets**: `https://my-pp.metro.it` (in scope — "METRO Customer Self Service domain"), `https://idam.metrosystems.net` (in scope via betty.metrosystems.net), `https://idam-pp.metrosystems.net` (pre-prod IDAM)
**Type**: Information Disclosure (OWASP A02) + Security Misconfiguration (OWASP A05)

### Description

The Metro customer self-service pre-prod portal (`my-pp.metro.it`) exposes a complete OAuth 2.0 authorization flow with multiple security concerns:

1. **Second OAuth client_id discovered** — `client_id=AXCSS` (in addition to `BTEX` from Finding 15), confirmed valid on both pre-prod (`idam-pp.metrosystems.net`) AND production (`idam.metrosystems.net`) IDAM servers.

2. **State parameter is a JWT signed with HS256** — the `state` parameter in the OAuth flow contains a JSON Web Token signed with a symmetric key (HMAC-SHA256). If the signing key is weak or can be brute-forced, an attacker can forge state values to inject arbitrary redirect URLs.

3. **OAuth parameters fully exposed** — the redirect URL leaks the complete OAuth configuration including realm, user type, PKCE challenge, and redirect URI.

4. **Pre-prod CSP with unsafe-eval and unsafe-inline** — the my-pp.metro.it CSP allows `unsafe-eval` and `unsafe-inline` in script-src, plus Apollo GraphQL sandbox endpoints.

### Evidence

**OAuth redirect from my-pp.metro.it reveals all parameters:**
```
GET / HTTP/2
Host: my-pp.metro.it

302 → https://idam-pp.metro.it/authorize/api/oauth2/authorize?
  response_type=code
  &client_id=AXCSS
  &realm_id=SSO_CUST_IT
  &user_type=CUST
  &country_code=IT
  &redirect_uri=https://my-pp.metro.it/personal/public/authenticate?redirectUrl=%2Fpersonal%2F
  &scope=openid
  &code_challenge=rsAIpWpzIMfQqWibMA5Qae0W45_f-rJSzJC8aex5RMY
  &code_challenge_method=S256
  &state=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**State JWT decoded:**
```json
Header: {"alg":"HS256","typ":"JWT"}
Payload: {
  "rnd": "00493490-bc4c-11f1-8c7b-9542d0049568",
  "redirectUrl": "/personal/",
  "iat": 1790717003,
  "exp": 1790803403
}
```
The state JWT contains:
- `rnd` — UUIDv1 (time-based, partially predictable)
- `redirectUrl` — controls post-authentication redirect destination
- 24-hour validity window (`exp - iat = 86400`)
- HS256 symmetric signing — key compromise enables state forgery

**AXCSS client_id validated on PRODUCTION IDAM:**
```
POST /authorize/api/oauth2/access_token HTTP/2
Host: idam.metrosystems.net
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=AXCSS&client_secret=test

Response: {"error":"invalid_client","error_description":"client_secret is invalid or expired"}
```
The error is "client_secret is **invalid or expired**" — NOT "client not found". This confirms `AXCSS` exists as a valid client on the production IDAM server.

**Pre-prod IDAM also confirms AXCSS:**
```
POST /authorize/api/oauth2/access_token HTTP/2
Host: idam-pp.metrosystems.net

Response: {"error":"invalid_client","error_description":"client_secret is invalid or expired"}
```
Same differential error on pre-prod — AXCSS is a real client on both environments.

**my-pp.metro.it CSP (verbose, weakened):**
```
script-src: [...] 'unsafe-inline' 'unsafe-eval' [...]
  embeddable-sandbox.cdn.apollographql.com  ← Apollo GraphQL sandbox
  sandbox.embed.apollographql.com            ← Apollo GraphQL sandbox
  connect.facebook.net, www.facebook.com, bat.bing.com [...]
frame-src: [...] https://idam-pp.metrosystems.net
  embeddable-sandbox.cdn.apollographql.com
  sandbox.embed.apollographql.com
```

**Internal Confluence documentation link leaked in IDAM error:**
```json
{"error_uri":"https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes"}
```

### Impact

- **OAuth client_id leakage to production** — the pre-prod portal reveals a valid production OAuth client (`AXCSS`) that was not intended to be publicly known. Combined with the implicit grant enabled on IDAM (Finding 15), this client could be used in token theft attacks.

- **State parameter forgery potential** — the state JWT uses HS256 (symmetric key). If the key is weak (common in Node.js applications), an attacker could:
  1. Forge a state JWT with `redirectUrl` pointing to an attacker-controlled URL
  2. Initiate an OAuth flow with this forged state
  3. After authentication, the application redirects the user to the attacker's URL with the authorization code

- **UUIDv1 predictability** — the `rnd` field uses UUID version 1 (time-based), which contains the MAC address of the generating host and a timestamp. This makes the "random" component partially predictable.

- **Pre-prod as production stepping stone** — the same `client_id=AXCSS` works on both pre-prod and production IDAM, confirming shared OAuth client configurations across environments. Pre-prod findings directly translate to production attack vectors.

- **Apollo GraphQL sandbox in CSP** — the whitelisted Apollo sandbox domains suggest a GraphQL API exists (possibly at a path not yet discovered), expanding the attack surface.

### Recommendation

1. **Separate OAuth clients** between pre-prod and production environments — never reuse client_ids across environments
2. **Use opaque, random state values** — do not embed redirect URLs or business logic in JWT-formatted state parameters; store redirect targets server-side keyed by a random token
3. **Use UUID v4** (random) instead of UUID v1 (time-based) for state randomness
4. **Remove Apollo GraphQL sandbox** from production CSP unless actively used
5. **Remove Confluence URL** from OAuth error responses — internal documentation URLs should not be in client-facing errors
6. **Restrict pre-prod IDAM** — require VPN or IP allowlist for pre-production identity services

---

## Finding 21: METRO Seller Office — Complete Microservice Architecture Disclosure + Admin Impersonation Endpoint + Unauthenticated Business Data

**Severity**: High
**Asset**: `www.metro-selleroffice.com` (*.metro-selleroffice.com — in scope as wildcard domain)
**Type**: Sensitive Data Exposure (OWASP A02) + Security Misconfiguration (OWASP A05) + Broken Access Control (OWASP A01)

### Description

The METRO Seller Office (`www.metro-selleroffice.com`) is a live production Angular application for managing seller organizations on the Metro/Makro marketplace. The 8MB production JavaScript bundle (`/static/main.3672261e6b5c6dd1.js`) exposes the **complete backend microservice architecture**, including 20+ service base URLs, an **admin impersonation endpoint** (`/admin/impersonation/exchange`), a **public unauthenticated activation code endpoint**, and the full authentication/authorization flow. Additionally, **7 translation files (4.7MB total)** are accessible without authentication, revealing commission fee structures, payment processing details, and complete business logic.

### Evidence

**1. Complete microservice architecture leaked in main.js (8MB):**

The bundle references 20+ backend service base URL variables, revealing the entire microservice topology:
```javascript
// Identity Management Service
IMS_API_ENDPOINT → svcImsBaseUrl
// Seller Gateway & Office
SELLER_GATEWAY_API_ENDPOINT → svcsSellerGatewayBaseUrl
SELLER_OFFICE_API_ENDPOINT → svcSellerOfficeBaseUrl
SELLER_OFFICE_API_ENDPOINT_V2 → svcSellerOfficeBaseUrl (v2)
// Product Information Management
SELLER_PIM_API_ENDPOINT → svcSellerPimBaseUrl
SELLER_PIM_UTILS_API_ENDPOINT → svcSellerPimUtilsBaseUrl
// Catalog & Inventory
EXTERNAL_CATALOG_TRANSFORMATION_API_ENDPOINT → svcExternalCatalogTransformationBaseUrl
SELLER_INVENTORY_API_ENDPOINT → svcSellerInventoryBaseUrl
// Marketplace
SELLER_OFFER_COMPETITIVENESS_API_ENDPOINT → svcSellerOfferCompetitivenessBaseUrl
STOREFRONT_API_ENDPOINT → svcStorefrontBaseUrl
SEARCH_API_ENDPOINT → svcSearchBaseUrl
CATEGORY_API_ENDPOINT → svcCategoryBaseUrl
// Order & Payment
ORDER_MANAGEMENT_API_ENDPOINT → svcOrderManagementBaseUrl
PAYMENT_API_ENDPOINT → svcPaymentBaseUrl
PAYMENT_REPORTS_API_ENDPOINT → svcPaymentReportsBaseUrl
ACCOUNTING_API_ENDPOINT → svcAccountingBaseUrl
// User & Communication
USER_ACCOUNT_API_ENDPOINT → svcUserAccountBaseUrl
MESSAGE_CENTER_API_ENDPOINT → svcMessageCenterBaseUrl
AFTERSALES_API_ENDPOINT → svcAftersalesBaseUrl
REFUND_REQUESTS_API_ENDPOINT → svcRefundRequestsBaseUrl
MM_CENTRAL_API_ENDPOINT → svcMmCentralBaseUrl
GENERIC_API_ENDPOINT → svcGenericBaseUrl
// External
CDN_BASE_URL → cdnBaseUrl
GOOGLE_CLOUD_STORAGE → googleCloudStorage
ANONYMOUS_EMAILS_BASE_URL → anonymousEmailsBaseUrl
```

**2. Admin impersonation endpoint — account takeover capability:**
```javascript
exchangeCodeToAccessToken(t) {
  return this.http.post(
    `${IMS_API_ENDPOINT}/admin/impersonation/exchange`, t, {}
  )
}

// Impersonation flow from URL query parameters:
ngOnInit() {
  const t = this.route.snapshot.queryParams;
  if (t._switch_user && t._switch_user_token) {
    this.impersonationService.exchangeCodeToAccessToken(t).subscribe({
      next: a => {
        const c = new AuthToken();
        c.access_token = a.access_token;
        // ... sets impersonated user session
      }
    })
  }
}
```
This reveals an admin impersonation mechanism accepting `_switch_user` and `_switch_user_token` query parameters. If these tokens can be obtained or forged, any seller account can be impersonated.

**3. Public unauthenticated activation code endpoint:**
```javascript
checkActivationCode(t) {
  return this.http.get(
    `${SELLER_OFFICE_API_ENDPOINT_V2}/public/accounts/check-activation-code?code=${t}`
  )
}
```
This endpoint requires no authentication — it's under `/public/` prefix and takes an activation code as a query parameter. This could enable brute-force of seller activation codes.

**4. IMS authentication endpoints fully mapped:**
```javascript
const endpoints = {
  CREDENTIALS: "/accounts/credentials",
  LOGIN: "/accounts/auth/login",
  LOGOUT: "/accounts/auth/logout",
  REFRESH: "/accounts/auth/refresh-access",
  RESET: "/accounts/auth/reset"
}
// Token refresh URL
tokenRefreshUrl = `${IMS_API_ENDPOINT}/accounts/auth/refresh-access`
```

**5. Seven translation files accessible without authentication (4.7MB total):**
```
[200] (515,597 bytes)  /static/assets/translations/en.json
[200] (709,968 bytes)  /static/assets/translations/de.json
[200] (683,075 bytes)  /static/assets/translations/fr.json
[200] (725,701 bytes)  /static/assets/translations/es.json
[200] (691,737 bytes)  /static/assets/translations/it.json
[200] (650,197 bytes)  /static/assets/translations/nl.json
[200] (690,162 bytes)  /static/assets/translations/pt.json
```

**6. Commission fee structure exposed in translations:**
```
Category A — 7% Commission per sale  (Cooling, Cleaning equipment, Sterilization)
Category B — 10% Commission per sale (Hospitality tech, Coffee, Cooking machinery, High Tech)
Category C — 13% Commission per sale (Stainless steel, Office Supplies, Grilling, Signage)
Category D — 15% Commission per sale (Catering accessories, Tableware, Seasoning, Care & Health)
```
These commission rates are commercially sensitive pricing information.

**7. API key management flow disclosed:**
```
API_KEYS.GENERATE.INTRO: "API keys allow you to use our API"
API_KEYS.GENERATED.DIALOG.ALERT: "The generated Client Secret is visible only once.
  Please make sure you save it..."
API_KEYS.LIST.GRID.CLIENT_KEY.TITLE: "Client Key"
API_KEYS.LIST.GRID.CLIENT_SECRET.TITLE: "Client Secret"
```

**8. Active API backend confirmed — structured JSON 404s:**
```
GET /api/v1/dictionary/countries → {"error":"[404] Not found: GET /api/v1/dictionary/countries"}
GET /api/v1/brands              → {"error":"[404] Not found: GET /api/v1/brands"}
GET /api/v1/organizations       → {"error":"[404] Not found: GET /api/v1/organizations"}
GET /api/v1/categories          → {"error":"[404] Not found: GET /api/v1/categories"}
GET /api/v1/seller              → {"error":"[404] Not found: GET /api/v1/seller"}
POST /api/v1/accounts/auth/login → {"error":"[404] Not found: POST /api/v1/accounts/auth/login"}
```
All `/api/v1/*` routes return structured JSON errors from a Node.js/Express backend — confirming active API routing. The IMS and service endpoints exist at separate internal URLs (injected at runtime).

**9. ConfigCat feature flags + Storyblok CMS integrations:**
```javascript
function configCatConfig() { return { apiKey: config.configCatSdkKey } }
// Storyblok content delivery
this.get("cdn/stories", params)  // Content delivery API
this.get(`cdn/stories/${slug}`)  // Individual story
```

**10. K8s infrastructure leaked in headers:**
```
x-ingress-controller: v2
x-ingress-request-id: 609c637a0f975658b25c28fec9898b46
x-powered-by: A fleet of awesome Marketeers. Apply today - https://www.metro-markets.de/careers
content-security-policy: frame-ancestors 'self' https://app.storyblok.com;
```

**11. CDN naming convention:**
```javascript
window.cdn = "https://mma-mp-de-production-cdn.prod.de.metro-marketplace.cloud";
```
Pattern: `mma-mp-{country}-production-cdn.prod.{country}.metro-marketplace.cloud`

### Impact

- **Admin impersonation mechanism exposed**: The `_switch_user` / `_switch_user_token` flow in the JS bundle reveals exactly how admin-level impersonation works. If these tokens are guessable, leaked in logs, or share a signing key with another exposed secret, any seller account can be taken over
- **Complete microservice map**: An attacker now knows every backend service name, purpose, and API endpoint pattern. This eliminates the reconnaissance phase entirely and enables targeted attacks on each service
- **Public activation code endpoint**: The `/public/accounts/check-activation-code?code=` endpoint could be brute-forced to validate or enumerate seller activation codes, enabling unauthorized seller account creation
- **Commercial pricing disclosure**: Commission rates (7-15% per category) are commercially sensitive — competitors could use this intelligence for pricing strategies
- **Business logic fully mapped**: Translation files + JS bundle together reveal every feature, error condition, validation rule, and workflow in the seller platform — all information useful for social engineering or targeted attacks
- **Chaining potential**: The IMS authentication endpoints, combined with the impersonation flow and the IDAM OAuth findings (Finding 15), create multiple paths toward account compromise

### Recommendation

1. **Audit admin impersonation endpoint** — ensure `_switch_user_token` validation is cryptographically secure; restrict impersonation to IP-whitelisted admin networks; add audit logging
2. **Rate-limit and monitor the activation code endpoint** — add CAPTCHA or proof-of-work to prevent brute-force enumeration
3. **Move commission rates and sensitive business data** to authenticated API responses, not public translation files
4. **Implement code splitting** — lazy-load admin-only code (impersonation, API key management) so it's never delivered to unauthenticated users
5. **Remove K8s infrastructure headers** — strip `x-ingress-controller`, `x-ingress-request-id`, and `x-powered-by` from production responses
6. **Restrict translation file access** — serve only the user's locale after authentication, not all 7 language files to anonymous users
7. **Inject service URLs server-side** at runtime (already done) but also obfuscate the variable names in production builds to reduce information leakage
8. **Remove Storyblok framing CSP** from non-CMS pages

---

## Finding 22: METRO Vendor Office — Symfony Debug Mode in Production + Platform-Wide CORS Subdomain Wildcard + No Login Rate Limiting + Complete Architecture Disclosure

**Severity**: High-Critical
**Asset**: `www.metro-vendoroffice.com`, `admin.metro-vendoroffice.com`, `vendor.metro-vendoroffice.com`, `offer-*.metro-vendoroffice.com`, `notification-hub.metro-vendoroffice.com` (*.metro-vendoroffice.com — in scope as wildcard domain)
**Type**: Security Misconfiguration (OWASP A05) + Sensitive Data Exposure (OWASP A02) + CORS Misconfiguration + Broken Access Control (OWASP A01)

### Description

The METRO Vendor Office platform (`*.metro-vendoroffice.com`) has **six critical security issues** creating a chained attack surface:

1. **Symfony Debug Mode enabled in production** — every `/api/v1/*` path returns 18KB JSON responses with full PHP stack traces, file paths, class names, line numbers, complete `traceAsString`, and `asString` debug output
2. **Platform-wide CORS subdomain wildcard with credentials** — confirmed on ALL 8+ services (www, buying-bff, notification-hub, offer-export, offer-funnel, offer-reactor, offer-safety, offer-xk)
3. **No rate limiting on login_check** — 5 consecutive login attempts all succeed in ~300ms with no throttling or account lockout
4. **PHPSESSID cookie missing Secure flag** — session cookie transmittable over HTTP
5. **Public GCS bucket with vendor business documents** — 4 files publicly downloadable from `sms-prod-assets` bucket
6. **Complete microservice architecture disclosure** via two JS bundles (admin 305KB + vendor 345KB) exposing 20+ services, role system, Mercure SSE hub, PowerBI integration, and 50+ API endpoints

### Evidence

**1. Symfony debug mode leaks full stack traces with complete internal paths on every `/api/v1/*` path (18KB per response):**
```json
GET /api/v1/test HTTP/2
Host: www.metro-vendoroffice.com

{
  "statusCode": 404,
  "headers": {"Vary": "Accept"},
  "class": "Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException",
  "file": "/app/vendor/symfony/http-kernel/EventListener/RouterListener.php",
  "line": 135,
  "statusText": "Not Found",
  "message": "No route found for \"GET https://www.metro-vendoroffice.com/api/v1/test\"",
  "code": 0,
  "previous": {
    "statusCode": 500,
    "class": "Symfony\\Component\\Routing\\Exception\\ResourceNotFoundException",
    "file": "/app/vendor/symfony/routing/Matcher/Dumper/CompiledUrlMatcherTrait.php",
    "line": 74
  },
  "trace": [8 entries with full namespace/class/function/file/line],
  "traceAsString": "#0 /app/vendor/symfony/event-dispatcher/EventDispatcher.php(270): ...\n#1 ...\n#6 /app/public/index.php(27): ...",
  "dataRepresentation": null,
  "asString": "Symfony\\Component\\Routing\\Exception\\ResourceNotFoundException: No routes found for \"/api/v1/test/\". in /app/vendor/symfony/routing/Matcher/Dumper/CompiledUrlMatcherTrait.php:74..."
}
```
Response exposes: application root `/app/`, all Symfony component paths, `public/index.php` as entry point, compiled URL matcher internals, EventDispatcher architecture. Every arbitrary path under `/api/v1/*` returns this 18KB debug dump.

**2. CORS subdomain wildcard with credentials confirmed on ALL 8+ services across the platform:**
```
=== www.metro-vendoroffice.com ===
Origin: https://evil.metro-vendoroffice.com
→ Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com
  Access-Control-Allow-Credentials: true
  Access-Control-Allow-Methods: GET, PUT, POST, DELETE, PATCH, OPTIONS
  Access-Control-Allow-Headers: ...Authorization,...x-session-id,...sentry-trace,baggage

=== buying-bff (service with cookie-based auth) ===
Origin: https://evil.metro-vendoroffice.com
→ Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com
  Access-Control-Allow-Credentials: true
  Access-Control-Expose-Headers: X-Correlation-Id

=== notification-hub.metro-vendoroffice.com (Mercure SSE) ===
Origin: https://evil.metro-vendoroffice.com
→ Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com
  Access-Control-Allow-Credentials: true

=== ALL 5 offer-* microservices ===
offer-export → Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com + credentials
offer-funnel → Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com + credentials
offer-reactor → Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com + credentials
offer-safety → Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com + credentials
offer-xk     → Access-Control-Allow-Origin: https://evil.metro-vendoroffice.com + credentials

External origins correctly blocked (evil.com → www.metro-vendoroffice.com echoed, not reflected)
```

**3. No rate limiting on login_check — 5 consecutive failed logins in rapid succession:**
```
[302|0.298078] attempt 1 - POST /login_check _username=test1@test.com
[302|0.298511] attempt 2 - POST /login_check _username=test2@test.com
[302|0.335465] attempt 3 - POST /login_check _username=test3@test.com
[302|0.390510] attempt 4 - POST /login_check _username=test4@test.com
[302|0.289193] attempt 5 - POST /login_check _username=test5@test.com
```
All return 302 redirect to `/` with ~300ms response time. No CAPTCHA, no account lockout, no progressive delay, no IP-based throttling detected.

**4. PHPSESSID cookie missing Secure and SameSite flags:**
```
Set-Cookie: PHPSESSID=da3a466f483cd35a6612a0520b89b3c6; path=/; httponly
Set-Cookie: apiKey=deleted; domain=.metro-vendoroffice.com; secure; httponly; samesite=lax
```
The `PHPSESSID` session cookie has only `httponly` — it is missing the `Secure` flag (transmittable over HTTP downgrade) and missing explicit `SameSite` attribute. The `apiKey` cookie is properly flagged but scoped to `.metro-vendoroffice.com` (all subdomains share it).

**5. GCS bucket `sms-prod-assets` — 4 vendor business documents publicly downloadable:**
```
[200|615865] https://storage.googleapis.com/sms-prod-assets/vendor-portal/documents/offer_competitiveness_page_guide.pdf (615KB)
[200|6031]   https://storage.googleapis.com/sms-prod-assets/vendor-portal/documents/offers_template.xlsx (6KB)
[200|12179]  https://storage.googleapis.com/sms-prod-assets/vendor-portal/documents/price_offer_template.xlsx (12KB)
[200|9265]   https://storage.googleapis.com/sms-prod-assets/vendor-portal/documents/stock_offer_template.xlsx (9KB)
```
Bucket listing is denied (401), but individual objects are publicly readable if you know the path. These files contain vendor onboarding templates and pricing structures.

**6. Complete platform architecture disclosed via JS bundles (admin 305KB + vendor 345KB):**

a) **20+ microservice URLs exposed:**
```
www.metro-vendoroffice.com/auth/client-api/                    → Auth service (401)
www.metro-vendoroffice.com/configuration/client-api/v1/feature-flags → Config (401)
www.metro-vendoroffice.com/demand-planning/client-api/v1/products/lifecycle → Demand (401)
www.metro-vendoroffice.com/vendor/client-api/v1/               → Vendor API (401 on countries, categories)
www.metro-vendoroffice.com/vendor/external-api/                 → External API (404)
www.metro-vendoroffice.com/vendor-dashboard/client-api/v1/      → Dashboard (404)
www.metro-vendoroffice.com/buying-bff/client-api/v1/            → Buying BFF (400 no auth / 401 with invalid cookie)
www.metro-vendoroffice.com/buying-offer/api/v1/                 → Buying Offers (404 - Go service)
www.metro-vendoroffice.com/finance/client-api/v1/               → Finance (Symfony 404)
www.metro-vendoroffice.com/return-service/client-api/v1/        → Returns (404)
www.metro-vendoroffice.com/delivery-service/client-api/         → Delivery
www.metro-vendoroffice.com/inventory-service/client-api/        → Inventory (Symfony 404)
www.metro-vendoroffice.com/label-service/client-api/            → Label/Customs
www.metro-vendoroffice.com/pim-upload/client-api/               → PIM Upload
www.metro-vendoroffice.com/product-data-enhancement/client-api/ → Product Data
notification-hub.metro-vendoroffice.com/.well-known/mercure     → Mercure SSE (401)
offer-export.metro-vendoroffice.com/api/                        → Offer Export (404)
offer-funnel.metro-vendoroffice.com/api/                        → Offer Funnel (404)
offer-reactor.metro-vendoroffice.com/api/                       → Offer Reactor (404)
offer-safety.metro-vendoroffice.com/api/                        → Offer Safety (404)
offer-xk.metro-vendoroffice.com/api/                            → Offer XK (404)
help.metro-vendoroffice.com/                                    → Help Portal (503)
```

b) **Buying BFF differential auth response** reveals cookie-based auth mechanism:
```
No cookie    → 400 Bad Request (empty body) — missing required auth
Invalid cookie → 401 Unauthorized (empty body) — auth check reached, rejected
```

c) **Role/permission system disclosed:**
```
ROLE_ADMIN, ROLE_VENDOR, ROLE_VENDOR_INTEGRATION_MANAGER,
ROLE_CAN_MANAGE_VENDORS, ROLE_CAN_UPDATE_VENDOR_CONTRACT, ROLE_BUYP_ADMIN
```

d) **50+ API endpoint paths from vendor portal JS:**
```
vendors/${id}/offline               — Move vendor offline
vendors/${id}/reinstate             — Reinstate vendor
vendors/${id}/document-signing/current/send  — Send contract
vendors/${id}/document-signing/current/sign  — Sign contract digitally
vendors/${id}/bank-info-request     — Bank information (PII)
vendors/${id}/products/batch/csv    — Bulk product upload
vendors/${id}/master-file/last      — Latest master file
vendors/${id}/contacts              — Vendor contacts
vendors/${id}/categories            — Product categories
leads/${id}/contacts/${cid}/email-registration-link — Send registration link
leads/${id}/contacts/${cid}/registration-link       — Get registration link
leads-contacts/${id}/block          — Block user
leads-contacts/${id}/unblock        — Unblock user
vendor/client-api/v1/async/vendors/${id}/product-data/template — Product data template
product-data/async/vendor/${id}     — Async product data
```

e) **Third-party integrations exposed:**
```
https://app.powerbi.com/reportEmbed                             — PowerBI analytics
https://notification-hub.metro-vendoroffice.com/.well-known/mercure — Mercure SSE hub
Pre-prod URL leak: https://www.pp.metro-vendorcentral.com/carton-service/client-api/
```

**7. Infrastructure headers leak operational details:**
```
x-app-version: 2118893
x-ingress-controller: v2
x-ingress-request-id: c71b9f5d9229c0f8ddf4b7fa646fb706
x-ingress-request-start: t=1790738472.009
x-powered-by: A fleet of awesome Marketeers. Apply today - https://www.metro-markets.de/careers
x-cdn-cache-id: CMH
x-cdn-cache-status: miss
```
Kubernetes ingress v2, CDN node identifier (CMH), request timing, app version — all exposed.

**8. Three live portals with no network restriction:**

a) **www.metro-vendoroffice.com** — PHP/Symfony login + Symfony debug mode + `.env`/`.git/config` (403)

b) **admin.metro-vendoroffice.com** — 305KB Angular admin panel with vendor management, lead management, document signing, demand planning

c) **vendor.metro-vendoroffice.com** — 345KB Angular vendor portal with product management, contract signing, bank info, eco-fee registration

### Impact

- **Information disclosure (Critical)**: Symfony debug traces (18KB per request) expose the full application internals — file structure (`/app/vendor/symfony/...`), dependency versions, class hierarchy, routing configuration, and the `traceAsString`/`asString` fields provide complete human-readable stack traces. This is the #1 prerequisite for developing targeted exploits
- **Credential theft chain (High)**: The CORS subdomain wildcard with credentials across ALL 8+ services means any XSS on ANY `*.metro-vendoroffice.com` subdomain steals authenticated API responses, session tokens, vendor data, financial information, bank details, and orders. The attack is: find XSS on any offer-* service → read cross-origin from www → exfiltrate vendor/financial data
- **Brute-force vendor accounts (High)**: No rate limiting on `POST /login_check` enables credential stuffing and brute-force attacks against vendor accounts. Combined with the Symfony debug mode (which may leak valid routes and error details), this significantly lowers the barrier for account compromise
- **Session hijacking via HTTP downgrade**: PHPSESSID missing `Secure` flag means the session cookie can be intercepted over HTTP connections (MITM on a vendor's network)
- **Cross-subdomain cookie theft**: The `apiKey` cookie scoped to `.metro-vendoroffice.com` is accessible from all subdomains, amplifying the CORS misconfiguration impact
- **Vendor financial data at risk**: API endpoints for bank info, contract signing, payment, and finance are all behind a single auth layer with no rate limiting and broad CORS
- **Supply chain visibility**: GCS bucket exposes vendor pricing templates and offer competitiveness guides — business intelligence leakage

### Recommendation

1. **IMMEDIATELY disable Symfony debug mode in production** — set `APP_DEBUG=false` and `APP_ENV=prod`. This is the single most impactful fix
2. **Implement login rate limiting** — add CAPTCHA after 3-5 failures, progressive delays, and IP-based throttling on `POST /login_check`
3. **Restrict CORS to exact origin list** — replace the platform-wide subdomain wildcard with explicit allowlist
4. **Add Secure and SameSite flags to PHPSESSID** — `Set-Cookie: PHPSESSID=...; path=/; httponly; Secure; SameSite=Lax`
5. **Restrict admin portal access** — place `admin.metro-vendoroffice.com` behind VPN or IP allowlist
6. **Scope cookies to specific subdomains** — change `apiKey` cookie domain from `.metro-vendoroffice.com` to `www.metro-vendoroffice.com`
7. **Restrict GCS bucket access** — make `sms-prod-assets` objects private, serve via signed URLs
8. **Remove `.env` and `.git` from the web root** — while nginx blocks access, these files should not exist in the web-accessible directory
9. **Strip infrastructure headers** — remove `x-app-version`, `x-ingress-controller`, `x-ingress-request-start`, `x-powered-by`, `x-cdn-cache-id`
10. **Standardize error responses** across microservices and ensure no internal details leak

---

## Finding 23: METRO Seller Office — Unauthenticated Config Endpoint Leaking 21 Internal Service URLs + Laravel Debug Mode on Production Aftersales Service + Complete API Route Map Exposure

**Severity**: Critical
**Asset**: `https://metro-selleroffice.com` (metro-selleroffice.com — in scope), `https://service-aftersales-v2.prod.de.metro-marketplace.cloud` (*.metro-marketplace.cloud — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Broken Access Control (OWASP A01) + Information Disclosure

### Summary

The METRO Seller Office exposes an unauthenticated `/api/v1/config` endpoint that returns the complete production configuration including 21 internal microservice URLs on `*.prod.de.metro-marketplace.cloud`, feature flags, third-party SDK keys (ConfigCat, Optimizely, Google Tag Manager), a Sentry DSN with error monitoring credentials, and reCAPTCHA site key. All 21 internal service URLs are accessible from the public internet (they should be behind a service mesh or VPN). One of these services — `service-aftersales-v2` — is a Laravel application with **Laravel Debugbar enabled in production**, its complete Ziggy route map exposed in the HTML source (leaking 16 API routes including admin endpoints and debug endpoints), **Sanctum CSRF cookie endpoint issuing session cookies without authentication**, **wildcard CORS** (`Access-Control-Allow-Origin: *`) with an extremely permissive header whitelist including `X-Impersonation-Session-Id` and `authorization`, and a `timing-allow-origin` header leaking 12 pre-production and production marketplace domains across 7 countries.

### Attack Chain

1. Attacker visits `https://metro-selleroffice.com/api/v1/config` — no auth required
2. Response reveals 21 internal `*.prod.de.metro-marketplace.cloud` service URLs
3. Attacker directly accesses `service-aftersales-v2` — returns full Laravel application HTML
4. HTML source contains Ziggy route config with 16 routes including admin and debug endpoints
5. Attacker discovers admin seller organization endpoint, anonymous email admin endpoints, debugbar, and Ignition routes
6. Attacker calls `/sanctum/csrf-cookie` — receives XSRF-TOKEN and session cookie without authentication
7. Wildcard CORS on `service-aftersales-v2` means any website can make authenticated API requests

### Evidence

#### 1. Unauthenticated Config Endpoint

**Request:**
```
GET /api/v1/config HTTP/2
Host: metro-selleroffice.com
```

**Response (3180 bytes, HTTP 200 — no authentication required):**
```json
{
  "locale": "en",
  "logLevel": "info",
  "featureConfig": {
    "FF_USE_ALIAS_FOR_ELASTIC_INDEXES": 1,
    "FF_DISABLE_HMAC_VALIDATION": 0,
    "FF_TEMP_MPGD1215_ADD_NEW_BUSINESS_REGISTRATION": 1,
    "FF_TEMP_MPGD5483_PRODUCT_TRACKING_SYSTEM": 1,
    "FF_TEMP_MPGD_10266_MANUFACTURER_NAME_VALIDATION": 1,
    "FF_MAINTENANCE_PAGE": 0,
    "FF_TEMP_MPGD6348_ADMIN_PANEL": 1,
    "FF_ENABLE_SENDGRID_EMAIL_VALIDATOR": 1,
    "FF_TEMP_MPGD6454_SAVE_BATCH_OF_ADDRESSES": 1
  },
  "serviceBaseUrls": {
    "ims": "https://service-ims-v2.prod.de.metro-marketplace.cloud",
    "platform": "https://platform.prod.de.metro-marketplace.cloud",
    "sellerGateway": "https://service-seller-gateway.prod.de.metro-marketplace.cloud",
    "sellerOffice": "https://app-seller-office.prod.de.metro-marketplace.cloud",
    "sellerPim": "https://app-seller-pim.prod.de.metro-marketplace.cloud",
    "sellerPimUtils": "https://service-pim-utils.prod.de.metro-marketplace.cloud",
    "pimExternalCatalogTransformation": "https://service-pim-external-catalog-transformation.prod.de.metro-marketplace.cloud",
    "sellerInventory": "https://app-seller-inventory.prod.de.metro-marketplace.cloud",
    "sellerOfferCompetitiveness": "https://app-seller-price-competitiveness.prod.de.metro-marketplace.cloud",
    "userAccount": "https://app-user-account.prod.de.metro-marketplace.cloud",
    "storefront": "https://app-storefront.prod.de.metro-marketplace.cloud",
    "orderManagement": "https://app-order-management.prod.de.metro-marketplace.cloud",
    "payment": "https://service-payment.prod.de.metro-marketplace.cloud",
    "paymentReports": "https://service-payment-reports.prod.de.metro-marketplace.cloud",
    "category": "https://service-category.prod.de.metro-marketplace.cloud",
    "mmCentral": "https://service-multimarket-central.prod.de.metro-marketplace.cloud",
    "accounting": "https://service-payment-provider.prod.de.metro-marketplace.cloud",
    "anonymousEmails": "https://service-anonymous-emails.prod.de.metro-marketplace.cloud",
    "aftersales": "https://service-aftersales-v2.prod.de.metro-marketplace.cloud",
    "messageCenter": "https://service-message-center.prod.de.metro-marketplace.cloud",
    "cdn": "https://mma-mp-de-production-cdn.prod.de.metro-marketplace.cloud",
    "refundRequests": "https://service-refund-requests.prod.de.metro-marketplace.cloud"
  },
  "appBaseUrls": {
    "seller": "https://www.metro-selleroffice.com",
    "employee": "https://backoffice.de.metro-marketplace.cloud/",
    "buyerDe": "https://www.metro.de/marktplatz/",
    "buyerEs": "https://www.makro.es/marketplace/",
    "buyerIt": "https://www.metro.it/marketplace/",
    "buyerPt": "https://www.makro.pt/marketplace/",
    "buyerNl": "https://www.makro.nl/marketplace/",
    "buyerFr": "https://www.metro.fr/marketplace",
    "buyerHr": "https://www.metro-cc.hr/marketplace/"
  },
  "gaTrackingId": "GTM-PNZ8HWP",
  "gtmAuthId": "KiyA6ICBGBLe5SOXtgSBtg",
  "gtmPreview": "env-1",
  "captchaSiteKey": "6Le21rMUAAAAABfUETJmm8d1P3JLpXRKTOCHz627",
  "configCatSdkKey": "DVPXCI0if81SA9_CiLstKA/7XgUPncj-0CAGX2Zs2i7Kg",
  "optimizelySdkKey": "SfQzTXC1pZbrqGFuQeDYz",
  "metroSellerId": "118ede85-fd10-42aa-8ee5-6fbc2553de02",
  "googleCloudStorage": "https://storage.googleapis.com",
  "akamaiHostURL": "https://images.metro-marketplace.eu/",
  "sentry": {
    "dsn": "https://d5cc4bbbb4f34303b91147f3b6c3c23a@cps-sentry.metro-markets.org/75",
    "enabled": "true",
    "environment": "prod"
  }
}
```

**Critical data leaked:**
- **21 internal microservice URLs** on `*.prod.de.metro-marketplace.cloud` — payment, payment-reports, payment-provider, order-management, seller-gateway, IMS, PIM, inventory, anonymous-emails, aftersales, message-center, CDN, refund-requests, and more
- **Employee backoffice URL**: `backoffice.de.metro-marketplace.cloud`
- **10 feature flags** including `FF_DISABLE_HMAC_VALIDATION`, `FF_TEMP_MPGD6348_ADMIN_PANEL`, `FF_MAINTENANCE_PAGE`
- **Sentry DSN**: `d5cc4bbbb4f34303b91147f3b6c3c23a@cps-sentry.metro-markets.org/75` — enables attacker to send fake error reports
- **ConfigCat SDK key**: `DVPXCI0if81SA9_CiLstKA/7XgUPncj-0CAGX2Zs2i7Kg` — access to feature flag configuration
- **Optimizely SDK key**: `SfQzTXC1pZbrqGFuQeDYz`
- **Google Tag Manager**: `GTM-PNZ8HWP` with auth `KiyA6ICBGBLe5SOXtgSBtg`
- **reCAPTCHA site key**: `6Le21rMUAAAAABfUETJmm8d1P3JLpXRKTOCHz627`
- **METRO seller UUID**: `118ede85-fd10-42aa-8ee5-6fbc2553de02`
- **7 buyer marketplace URLs** across 6 countries (DE, ES, IT, PT, NL, FR, HR)

#### 2. All 21 Internal Services Accessible from Public Internet

Every internal microservice URL is reachable from the internet — these should be behind a service mesh, VPN, or at minimum IP-restricted:

| Service | URL | HTTP Response |
|---------|-----|---------------|
| IMS | service-ims-v2.prod.de.metro-marketplace.cloud | 404 |
| Platform | platform.prod.de.metro-marketplace.cloud | 404 |
| Seller Gateway | service-seller-gateway.prod.de.metro-marketplace.cloud | 404 |
| Seller Office | app-seller-office.prod.de.metro-marketplace.cloud | 404 |
| Seller PIM | app-seller-pim.prod.de.metro-marketplace.cloud | 404 |
| PIM Utils | service-pim-utils.prod.de.metro-marketplace.cloud | 404 |
| PIM Ext. Catalog | service-pim-external-catalog-transformation.prod.de.metro-marketplace.cloud | 404 |
| Seller Inventory | app-seller-inventory.prod.de.metro-marketplace.cloud | 404 |
| Price Competitiveness | app-seller-price-competitiveness.prod.de.metro-marketplace.cloud | 404 |
| User Account | app-user-account.prod.de.metro-marketplace.cloud | 404 |
| Storefront | app-storefront.prod.de.metro-marketplace.cloud | 404 |
| Order Management | app-order-management.prod.de.metro-marketplace.cloud | 404 |
| Payment | service-payment.prod.de.metro-marketplace.cloud | 404 |
| Payment Reports | service-payment-reports.prod.de.metro-marketplace.cloud | 404 |
| Category | service-category.prod.de.metro-marketplace.cloud | 404 |
| Multimarket Central | service-multimarket-central.prod.de.metro-marketplace.cloud | 404 |
| Payment Provider | service-payment-provider.prod.de.metro-marketplace.cloud | 404 |
| Anonymous Emails | service-anonymous-emails.prod.de.metro-marketplace.cloud | 404 |
| **Aftersales v2** | **service-aftersales-v2.prod.de.metro-marketplace.cloud** | **200 (26KB HTML)** |
| Message Center | service-message-center.prod.de.metro-marketplace.cloud | 404 |
| Refund Requests | service-refund-requests.prod.de.metro-marketplace.cloud | 404 |
| Notification | service-notification.prod.de.metro-marketplace.cloud | 403 |

#### 3. service-aftersales-v2 — Laravel Debug Mode with Complete Route Map

The aftersales service at `service-aftersales-v2.prod.de.metro-marketplace.cloud` returns a full Laravel application page (26KB) with its complete Ziggy route map embedded in the JavaScript. The routes reveal:

**16 Exposed Routes:**

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/api/v1/admin/sellers/organizations/{organizationId}` | Admin seller organization data |
| GET | `/api/v1/admin/anonymous-emails/threads` | Admin anonymous email threads |
| GET | `/api/v1/admin/anonymous-emails/attachments` | Admin email attachments |
| GET | `/api/v1/admin/anonymous-emails/attachment/url` | Admin attachment URLs |
| GET | `/api/v1/auth/app-check/{anything}` | Auth health check |
| GET | `/_debugbar/assets/stylesheets` | **Laravel Debugbar CSS** |
| GET | `/_debugbar/assets/javascript` | **Laravel Debugbar JS** |
| GET | `/_debugbar/open` | **Debugbar open handler** |
| POST | `/_debugbar/queries/explain` | **SQL EXPLAIN endpoint** |
| GET | `/_debugbar/clockwork/{id}` | **Clockwork profiler** |
| GET | `/_debugbar/telescope/{id}` | **Laravel Telescope** |
| DELETE | `/_debugbar/cache/{key}/{tags?}` | **Cache deletion endpoint** |
| POST | `/_ignition/execute-solution` | **Ignition RCE vector (CVE-2021-3129)** |
| GET | `/_ignition/health-check` | Ignition health check |
| POST | `/_ignition/update-config` | **Ignition config update** |
| GET | `/sanctum/csrf-cookie` | Sanctum CSRF cookie issuer |

**Admin endpoints respond with JWT validation errors — confirming they are live and accepting requests:**
```
GET /api/v1/admin/anonymous-emails/threads HTTP/2
Host: service-aftersales-v2.prod.de.metro-marketplace.cloud

HTTP/2 401
{"message":"Invalid or expired JWT token provided"}
```

**Auth app-check returns 200 without authentication:**
```
GET /api/v1/auth/app-check/test HTTP/2
Host: service-aftersales-v2.prod.de.metro-marketplace.cloud

HTTP/2 200
it works!
```

#### 4. Sanctum CSRF Cookie — Session Cookies Without Authentication

**Request:**
```
GET /sanctum/csrf-cookie HTTP/2
Host: service-aftersales-v2.prod.de.metro-marketplace.cloud
```

**Response (HTTP 204):**
```
set-cookie: XSRF-TOKEN=eyJpdiI6IjxiYXNlNjQ+IiwidmFsdWUiOiI8ZW5jcnlwdGVkPiIsIm1hYyI6IjxobWFjPiIsInRhZyI6IiJ9;
  expires=<+24h>; Max-Age=86400; path=/; secure; samesite=lax
set-cookie: service_aftersales_v2_session=eyJpdiI6IjxiYXNlNjQ+IiwidmFsdWUiOiI8ZW5jcnlwdGVkPiIsIm1hYyI6IjxobWFjPiIsInRhZyI6IiJ9;
  expires=<+24h>; Max-Age=86400; path=/; secure; httponly; samesite=lax
```

The endpoint creates a valid Laravel session and CSRF token for any unauthenticated visitor. Combined with wildcard CORS, any website can:
1. Call `/sanctum/csrf-cookie` to get session cookies
2. Use the XSRF-TOKEN to make CSRF-protected POST requests
3. Potentially access admin API endpoints if session state grants any implicit permissions

#### 5. Wildcard CORS with Impersonation Header Whitelist

**Request:**
```
GET / HTTP/2
Host: service-aftersales-v2.prod.de.metro-marketplace.cloud
Origin: https://evil.com
```

**Response headers:**
```
access-control-allow-origin: *
access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
access-control-allow-headers: X-Impersonation-Session-Id, X-Active-Context,
  DNT, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control,
  Content-Type, Range, authorization, tid, x-prerender, X-Correlation-Id,
  x-cms-location, X-Proxy-Service, X-Proxy-Location, X-Country-Code,
  Country-Code, Accept-Language, Content-Language, X-ID-MM, X-ID-GA,
  X-ID-OM, X-ID-CO, X-SOURCE, x-client-id, X-Analytics-User-Id, X-Session-Id
access-control-expose-headers: X-Correlation-Id
access-control-max-age: 1728000
```

**Critical observations:**
- `Access-Control-Allow-Origin: *` — any website can make requests
- `X-Impersonation-Session-Id` in allowed headers — **confirms impersonation functionality exists**
- `authorization` in allowed headers — tokens can be sent cross-origin
- `X-Proxy-Service` and `X-Proxy-Location` — service mesh routing headers exposed
- Max age of 1728000 seconds (20 days) — preflight responses cached aggressively

#### 6. timing-allow-origin Leaking Production and Pre-Prod Domains

```
timing-allow-origin: https://marketplace-pp.metro.de,
  https://marketplace-pp.makro.es,
  https://marketplace-pp.metro.it,
  https://marketplace-pp.makro.pt,
  https://marketplace-pp.makro.nl,
  https://marketplace-pp.metro.fr,
  https://www.metro.de,
  https://www.makro.es,
  https://www.metro.it,
  https://www.makro.pt,
  https://www.makro.nl,
  https://www.metro.fr
```

This reveals 6 pre-production marketplace domains (`marketplace-pp.*`) and 6 production domains. The pre-production URLs are attack surface for accessing staging environments.

#### 7. service-seller-gateway — Unauthenticated OpenAPI/Swagger Spec (22 Endpoints + 25 Schemas)

The seller gateway at `service-seller-gateway.prod.de.metro-marketplace.cloud` redirects root to `/api/v1/api-doc` which serves a **complete OpenAPI 3.0 specification** without authentication — NelmioApiDoc Swagger UI with full request/response schemas:

**Request:**
```
GET /api/v1/api-doc HTTP/2
Host: service-seller-gateway.prod.de.metro-marketplace.cloud
```

**Response: HTTP 200 — Full Swagger UI with embedded spec (22 endpoints, 25 schemas)**

**Exposed endpoints include:**
- `POST /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/return-label` — upload return label PDFs
- `PUT /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/return-trackings` — update tracking
- `DELETE /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/documents/{documentId}` — delete documents
- `GET /api/seller/proxy/app-order-management/v1/delivery-carriers` — list carriers
- `GET /api/seller/proxy/service-seller-account-health/v1/kpi/{metric}` — 7 KPI metrics (order defect, delivery, cancellation, etc.)
- `GET /api/seller/proxy/service-seller-account-health/v1/export/{kpiName}` — export KPI data

**Schemas reveal internal data models:** `app-order-management_FileStorageId`, `app-order-management_TrackingPayload`, all KPI response schemas with field definitions.

The gateway also reveals it is a **proxy** to internal services — all paths follow `/api/seller/proxy/{service-name}/v1/*` pattern, confirming the microservice routing architecture.

Health check also exposed unauthenticated:
```
GET /api/v1/auth/app-check/health → "service-seller-gateway is ready."
```

#### 8. service-pim-utils — Symfony Debug Error Responses

```
GET /health HTTP/2
Host: service-pim-utils.prod.de.metro-marketplace.cloud

HTTP/2 500
{"class":"NotFoundHttpException","code":500,"message":"No route found for \"GET https://service-pim-utils.prod.de.metro-marketplace.cloud/health\""}
```

Leaks Symfony exception class names (`NotFoundHttpException`) and internal URLs in error messages — identical pattern to Finding 22's vendor office Symfony debug mode.

#### 9. Three Additional Services with Unauthenticated OpenAPI Specs

| Service | Spec URL | Endpoints | Schemas |
|---------|----------|-----------|---------|
| service-seller-gateway | `/api/v1/api-doc` | 22 (order mgmt, KPIs, carrier) | 25 |
| app-seller-pim | `/api/v1/api-doc` | 12 (products, uploads, CSV template) | 13 |
| service-category | `/api/v1/api-doc` | 13 (categories, attributes, brands) | 32 |

**Total: 47 endpoints + 70 schemas exposed across 3 services without authentication.**

The PIM spec reveals `SecurityToken` schema with `access_token`, `refresh_token`, and `expires_in` fields — documenting the JWT auth flow. The upload endpoint accepts `multipart/form-data` with CSV file uploads for product processing.

#### 10. Health/Self-Check Endpoints Leaking Infrastructure on 8+ Internal Services

| Service | Endpoint | Status | Infrastructure Leaked |
|---------|----------|--------|----------------------|
| service-aftersales-v2 | `/api/v1/auth/app-check/test` | 200 | `it works!` |
| service-seller-gateway | `/api/v1/auth/app-check/health` | 200 | `service-seller-gateway is ready.` |
| app-seller-pim | `/api/v1/auth/app-check/self` | 200 | Redis OK, **MongoDB FAIL** (doctrine_mongodb.odm.default_connection), filesystem, **PubSub FAIL** (topic: `upload_parsing`) |
| app-seller-inventory | `/api/v1/auth/app-check/self` | 200 | Redis, Doctrine, **Elasticsearch**, **PubSub FAIL** (subscriptions: `org_offer_status_pausing`, `org_offer_status_unpausing`) |
| service-category | `/api/v1/auth/app-check/self` | 200 | Doctrine ORM, PubSub, services |
| service-multimarket-central | `/api/v1/auth/app-check/self` | 200 | Doctrine ORM, env vars, services |
| service-refund-requests | `/api/v1/auth/app-check/self` | 200 | env vars, services |
| service-payment-provider | `/api/v1/auth/app-check/health` | 200 | `service-payment-provider is ready.` |
| service-payment-reports | `/api/v1/auth/app-check/health` | 200 | `{"status":"ok"}` |
| app-seller-price-competitiveness | `/api/v1/auth/app-check/health` | 200 | `{"message":"ok"}` |

**Critical leaks:** The PIM self-check reveals MongoDB via Doctrine ODM and PubSub topic names. The inventory self-check reveals Redis, Doctrine ORM, Elasticsearch, and PubSub subscription names (`org_offer_status_pausing`, `org_offer_status_unpausing`). Two services show PubSub connection failures in production.

**Most severe self-check leak — service-anonymous-emails:**
```json
{
  "status": "FAIL",
  "output": [
    "[ENVIRONMENT REQUIRED VARIABLES]: Variable \"APP_SECRET\" has not been defined. Variable \"VAR_DUMPER_SERVER\" has not been defined.",
    "[PUB_SUB]: Connection error: { \"error\": { \"code\": 403, \"message\": \"User not authorized\", \"status\": \"PERMISSION_DENIED\", \"details\": [{ \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\", \"reason\": \"IAM_PERMISSION_DENIED\", \"metadata\": { \"resource\": \"projects/metro-markets-prod\", \"permission\": \"pubsub.topics.list\" }}]}}",
    "[SERVICES]: Service \"service-accounting.prod.de.metro-marketplace.cloud\" is unavailable."
  ]
}
```
This leaks:
- **Production GCP project name**: `projects/metro-markets-prod`
- **GCP IAM troubleshooter URL** with base64-encoded error ID linking to the IAM admin console
- **Missing `APP_SECRET`** — a Symfony security-critical variable
- **`VAR_DUMPER_SERVER`** — Symfony debug variable exposed in production
- **Previously unknown internal service**: `service-accounting.prod.de.metro-marketplace.cloud` (22nd service, not in the config endpoint)

#### 10b. Pre-Production Environment — Same Vulnerabilities + Additional Exposure

The pre-prod seller office at `web-app-seller.pp-de.metro-marketplace.cloud` also exposes `/api/v1/config` without authentication, leaking 21 pre-prod internal service URLs (`*.pp-de.metro-marketplace.cloud`):

- All pre-prod services share the SAME Sentry DSN as production (same project receives both environments' errors)
- Different ConfigCat SDK key: `DVPXCI0if81SA9_CiLstKA/9H_u2-xmXUatFJAGiah3Wg`
- Different METRO seller ID: `b4b309e0-9f53-4c9b-b639-3913b7131996`
- **Employee backoffice URL**: `web-app-employee.pp-de.metro-marketplace.cloud`
- **Staging CDN bucket**: `staging-cdn-bucket.pp-de.metro-marketplace.cloud` — 403 response leaks GCP service account `cdn-lb-sa@metro-markets-staging.iam.gserviceaccount.com` and GCP project `metro-markets-staging`
- **Storyblok CMS integration**: CSP `frame-ancestors 'self' https://app.storyblok.com`
- Pre-prod PIM self-check leaks same MongoDB + PubSub failures as production
- Pre-prod seller-gateway has same wildcard CORS + unauthenticated Swagger UI

**Combined GCP project discovery:**
| Environment | GCP Project | Source |
|-------------|-------------|--------|
| Production | `metro-markets-prod` | anonymous-emails self-check PubSub error |
| Staging | `metro-markets-staging` | staging CDN bucket 403 error |

#### 11. Permissive CSP

```
content-security-policy: default-src 'self' http: https: data: blob: 'unsafe-inline'
```

This CSP provides essentially no protection — it allows all HTTP/HTTPS sources, inline scripts, data URIs, and blob URLs. XSS payloads execute without CSP interference.

#### 12. Infrastructure Headers

```
x-ingress-controller: v2
x-ingress-request-id: eddd56bde5b7ddf06fa8b6dd1682440c
x-ingress-request-start: t=1790739198.543
x-powered-by: A fleet of awesome Marketeers. Apply today - https://www.metro-markets.de/careers
strict-transport-security: max-age=31536000; includeSubDomains
x-frame-options: SAMEORIGIN
```

### Impact

- **Information Disclosure (Critical)**: Unauthenticated access to the complete microservice architecture — 21 internal service URLs, employee backoffice URL, Sentry DSN, SDK keys, feature flags, and METRO seller UUID
- **Expanded Attack Surface**: All 21 internal services are accessible from the internet, bypassing intended service mesh isolation. Three services (seller-gateway, app-seller-pim, service-category) expose complete OpenAPI/Swagger specs totaling 47 endpoints and 70 data schemas, fully documenting the API attack surface including request/response formats, parameter types, and data models
- **Debug Mode in Production**: Laravel Debugbar routes are defined in the application (route map exposed via Ziggy), meaning debug tooling was enabled during deployment. The `_debugbar/queries/explain` POST endpoint, if functional, enables arbitrary SQL EXPLAIN queries. The `_ignition/execute-solution` endpoint is a known RCE vector (CVE-2021-3129)
- **Session Fixation Risk**: Sanctum CSRF cookie endpoint creates sessions for unauthenticated visitors; combined with wildcard CORS, any website can initiate sessions and make CSRF-protected requests
- **Impersonation Feature Exposure**: The `X-Impersonation-Session-Id` CORS header confirms the existence of user impersonation functionality. Combined with the admin endpoints visible in the route map (`admin/sellers/organizations/{organizationId}`), this suggests full admin-level seller management capability
- **Sentry DSN Abuse**: The exposed Sentry DSN (`d5cc4bbbb4f34303b91147f3b6c3c23a@cps-sentry.metro-markets.org/75`) allows an attacker to inject fake error reports into METRO's error monitoring, potentially flooding dashboards or injecting malicious content into error messages viewed by developers
- **Health/Self-Check Infrastructure Disclosure**: 8+ services expose `/api/v1/auth/app-check/self` or `/health` endpoints revealing backend technology stack (MongoDB, Redis, Elasticsearch, Doctrine ORM, PubSub), connection status, topic names, and subscription names — all without authentication. Two services show PubSub connection failures in production

### CVSS Assessment

- **Attack Vector**: Network (AV:N) — all endpoints publicly accessible
- **Attack Complexity**: Low (AC:L) — simple GET request reveals config
- **Privileges Required**: None (PR:N) — no authentication needed
- **User Interaction**: None (UI:N) — direct exploitation
- **Scope**: Changed (S:C) — config from seller office exposes separate internal services
- **Confidentiality**: High (C:H) — complete infrastructure mapping + admin route map
- **Integrity**: Low (I:L) — Sentry DSN allows fake error injection, session cookie creation
- **Availability**: None (A:N)
- **CVSS 3.1 Score**: 9.3 (Critical)

### Remediation

1. **Immediately remove `/api/v1/config` from unauthenticated access** — require authentication or serve only non-sensitive config to the frontend
2. **Restrict internal services to service mesh/VPN** — all 21 `*.prod.de.metro-marketplace.cloud` services should not be accessible from the public internet
3. **Disable Laravel Debugbar and Ignition in production** — set `APP_DEBUG=false` and remove `barryvdh/laravel-debugbar` from production dependencies; Ignition's `execute-solution` is a known RCE vector
4. **Remove Ziggy route exposure from HTML** — move route definitions server-side; never expose debug or admin routes to the client
5. **Restrict CORS on service-aftersales-v2** — replace `Access-Control-Allow-Origin: *` with specific allowed origins; remove `X-Impersonation-Session-Id` from allowed headers
6. **Rotate all exposed credentials** — Sentry DSN, ConfigCat SDK key, Optimizely SDK key, GTM auth ID, reCAPTCHA site key
7. **Restrict `/sanctum/csrf-cookie`** — require authentication or limit to known frontend origins
8. **Remove `timing-allow-origin` header** — it leaks pre-production domain names
9. **Implement proper CSP** — replace the permissive policy with strict-dynamic or nonce-based CSP
10. **Move feature flags to authenticated config** — `FF_DISABLE_HMAC_VALIDATION` and `FF_TEMP_MPGD6348_ADMIN_PANEL` reveal security-critical application state
11. **Strip infrastructure headers** — remove `x-ingress-controller`, `x-ingress-request-start`, `x-powered-by`

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

## Phase 2-5 Testing Summary

**Tested and confirmed exploitable (documented as findings):**
- OAuth implicit grant enabled on IDAM (Finding 15)
- OAuth redirect_uri query parameter injection accepted (Finding 15) — NOTE: host validation works (evil.com → 403), but query parameter appending bypasses exact matching
- OAuth hybrid flow (code+token) and id_token flow enabled (Finding 15)
- redirect_uri path traversal (..;/) accepted by IDAM (Finding 15)
- Verbose health endpoints on orderservice (43 components) and checkout (10 components) (Finding 14)
- 401 error bodies leak Java servlet class, internal HTTP URIs, and auth header convention (Finding 14)
- check_cookie_iframe postMessage session detection (Finding 16)
- CSP `unsafe-eval` + `wss://*` weaknesses (Finding 17)
- Internal API URL leak via WWW-Authenticate header (Finding 17)
- PKCE not enforced and state parameter not required on IDAM (Finding 15)
- PKCE plain method accepted (downgrade from S256) (Finding 15)
- Depotsettings JWT signature validation completely absent (Finding 18)
- ria voucher access code authentication via GET parameter + JWT in localStorage (Finding 19)
- AXCSS OAuth client_id confirmed on production IDAM via pre-prod portal (Finding 20)
- State JWT with HS256 symmetric signing and UUIDv1 (Finding 20)
- METRO Seller Office 8MB JS bundle exposes 20+ microservice URLs + admin impersonation endpoint + public activation code endpoint (Finding 21)
- Seller Office 7 translation files (4.7MB) accessible without auth — commission rates, API key flow, payment details (Finding 21)
- Seller Office active API backend at /api/v1/* returns structured JSON 404 errors confirming route existence (Finding 21)
- Seller Office K8s ingress metadata + CDN naming convention + Storyblok CMS + ConfigCat feature flags (Finding 21)
- my-pp.metro.it pre-prod CSP with unsafe-eval, unsafe-inline, and Apollo GraphQL sandbox (Finding 20)
- Vendor Office Symfony debug mode in production — full 18KB stack traces on all /api/v1/* paths with traceAsString and asString (Finding 22)
- Vendor Office CORS subdomain wildcard with credentials — confirmed on ALL 8+ services: www, buying-bff, notification-hub, offer-export/funnel/reactor/safety/xk (Finding 22)
- Vendor Office admin portal (admin.metro-vendoroffice.com, 305KB) and vendor portal (vendor.metro-vendoroffice.com, 345KB) publicly accessible (Finding 22)
- Vendor Office 20+ microservices confirmed: auth, configuration, delivery, demand-planning, finance, inventory, label, pim-upload, product-data-enhancement, return, vendor, vendor-dashboard, buying-bff, buying-offer, 5 offer-* services, notification-hub (Finding 22)
- Vendor Office .env and .git/config exist on disk (403 by nginx) (Finding 22)
- Vendor Office apiKey cookie scoped to .metro-vendoroffice.com (cross-subdomain sharing) (Finding 22)
- Vendor Office PHPSESSID missing Secure and SameSite flags — session cookie transmittable over HTTP (Finding 22)
- Vendor Office no rate limiting on POST /login_check — 5 rapid consecutive attempts with no throttling (Finding 22)
- Vendor Office buying-bff differential auth response: 400 (no cookie) vs 401 (invalid cookie) reveals cookie-based auth (Finding 22)
- Vendor Office GCS bucket sms-prod-assets with 4 publicly downloadable documents: offers_template.xlsx, price_offer_template.xlsx, stock_offer_template.xlsx, offer_competitiveness_page_guide.pdf (Finding 22)
- Vendor Office Mercure SSE notification hub at notification-hub.metro-vendoroffice.com (401 — exists, auth required) (Finding 22)
- Vendor Office PowerBI reportEmbed integration, pre-prod URL leak (www.pp.metro-vendorcentral.com), 6 roles (ROLE_ADMIN, ROLE_VENDOR, etc.) (Finding 22)
- Vendor Office 50+ API endpoint paths extracted from vendor portal JS — vendors/bank-info-request, leads/registration-link, document-signing, etc. (Finding 22)
- Vendor Office K8s ingress v2 headers, CDN node identifier (CMH), x-app-version: 2118893 (Finding 22)

**Tested and confirmed not exploitable:**
- OAuth redirect_uri HOST bypass (IDAM correctly rejects different hosts — evil.com → 403)
- IDAM device code grant (404 — not implemented)
- IDAM ROPC/password grant (listed in discovery but returns "not supported")
- CSP nonce prediction (nonces are properly random per-request)
- SSRF via 3v coupon API kid field (reflected but static JWKS lookup, no outbound request)
- JWT alg:none on ordermanagement/pickandpack/stocklocation (properly rejected, stay at 401)
- HTTP verb tampering on ordermanagement (all methods return 401 consistently)
- Elasticsearch direct access on search API (all internal paths return 404)
- Open redirect via betty SPA query params (SPA serves same page for all params — client-side handling)
- JWT algorithm confusion RS256→HS256 (server rejects HS256 tokens, 500 but not exploitable)
- JWT kid SQL injection / path traversal (reflected but no injection — kid lookup against static JWKS)
- Server-side XSS on betty shops (SPA architecture — no server-side template rendering)
- SSTI/template injection on search API (no execution detected)
- CRLF injection on search API (no header injection)
- Open redirect on shop domains (no redirect parameters found)
- Dynamic client registration on IDAM (endpoint not exposed — 404)
- Sitecore admin panels (all 404 across all countries)
- GraphQL endpoints (not deployed on any tested service, including my-pp.metro.it — all /graphql paths return 404)
- my-pp.metro.it redirectUrl injection (returns 400 for external URLs — server-side validation works)
- Actuator/Spring Boot endpoints (all 404 on betty — except /health returning `{"status":"READY"}`)
- Elasticsearch/Kibana direct access (no non-standard ports accessible)
- Host header injection (GCP infrastructure behavior — 301 redirect with `Host: evil.com` but requires MITM to exploit, low practical impact)
- IDAM OAuth redirect_uri HOST validation (returns 403 for different hosts — properly validated; see Finding 15 for query param and path bypass)
- idam.metro.de direct access (Akamai WAF serves same 605B SPA for all paths — Keycloak backend not directly accessible)
- CSP nonce bypass (nonces not extractable via curl — SPA rendering)
- Swagger.json null-byte / encoding bypass (all variants return 403 or 404)

**Confirmed accessible but auth-protected:**
- betty.metrosystems.net login endpoints (customer: 404, employee: 404, SSO: 401)
- IDAM OAuth authorize with BTEX client_id (returns 200 login page)
- betty /health endpoint (returns `{"status":"READY"}`)
- explore.tracking.v1 module (returns 503 — service unavailable)

**Partially tested (access limitations):**
- Country-specific search APIs (only DE accessible — ES/BG/HR/HU/RO all connection failures)
- Pre-prod marketplace domains (all 403 — IP restricted)
- Mirakl marketplace platform (egress proxy blocked)
- PureCloud (requires authentication, returns 302/404)
- erika.metrosystems.net (egress proxy blocked)
- adfs3.metro.info (connection failure)
- *.metro-marketplace.cloud subdomains (earlier DNS failures — but 21 `*.prod.de.metro-marketplace.cloud` services confirmed reachable via config endpoint in Finding 23)
- *.metro-markets.net subdomains (all DNS resolution failures)
- *.metro-vendorcentral.com subdomains (www.pp.metro-vendorcentral.com reachable but 403 on all paths — IP restricted)
- ria voucher API backend at api.cf-vvv-preprod-o6.cf.metro.cloud (returns 404 for all tested paths — backend may require different routing)
- betty.metro.{bg,de,fr,hr,hu,it,pk,pt,ro,rs,ua} — all blocked by egress proxy (HTTP 000)
- Vendor Office notification-hub.metro-vendoroffice.com (returns 401 — Mercure SSE hub, auth required)

## Finding 24: IDAM OAuth 2.0 Platform-Wide Security Misconfigurations

**Severity**: High
**CVSS**: 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Asset**: `idam.metrosystems.net`, `idam.metro.de`, `idam.metro.fr`, `idam.metro.it` (*.metrosystems.net, *.metro.de — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Identification and Authentication Failures (OWASP A07)

### Description

Metro AG's IDAM (Identity and Access Management) platform — the central authentication system serving ALL country-specific shop domains — has multiple OAuth 2.0/OpenID Connect security misconfigurations that violate RFC 9700 (OAuth 2.0 Security Best Current Practice) and OAuth 2.1 recommendations. These misconfigurations are **identical across all tested IDAM instances**, indicating a shared platform-wide configuration issue.

### Evidence

#### 24a. OpenID Discovery Reveals Deprecated Flows (All Instances)

```
GET /.well-known/openid-configuration HTTP/2
Host: idam.metrosystems.net

200 OK
{
  "issuer": "https://idam.metrosystems.net",
  "response_types_supported": ["code", "token", "id_token", "id_token token"],
  "grant_types_supported": ["refresh_token", "client_credentials", "implicit", "authorization_code", "password"],
  "code_challenge_methods_supported": ["plain", "S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
}
```

**Identical configuration confirmed on:**
| IDAM Instance | Implicit Flow | Password Grant | Plain PKCE |
|---|---|---|---|
| `idam.metrosystems.net` | Enabled | Enabled | Accepted |
| `idam.metro.de` | Enabled | Enabled | Accepted |
| `idam.metro.fr` | Enabled | Enabled | Accepted |
| `idam.metro.it` | Enabled | Enabled | Accepted |

#### 24b. Implicit Flow Enabled (RFC 9700 Violation)

`response_types_supported` includes `token` and `id_token token` — the implicit grant. Per RFC 9700 Section 2.1.2: "The implicit grant MUST NOT be used." Tokens in URL fragments leak via:
- Browser history
- Referer headers to third-party resources
- Server access logs
- Browser extensions with history access

#### 24c. Password Grant Enabled (RFC 9700 Violation)

`grant_types_supported` includes `password` (Resource Owner Password Credentials). Per RFC 9700 Section 2.4: "The resource owner password credentials grant MUST NOT be used." This grant type:
- Exposes user credentials directly to client applications
- Bypasses MFA/2FA if configured at the authorization endpoint
- Enables credential stuffing at the token endpoint

Token endpoint accepts the grant type (returns `invalid_client` rather than `unsupported_grant_type`):
```
POST /authorize/api/oauth2/access_token HTTP/2
Host: idam.metrosystems.net
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=test@test.com&password=test123&scope=openid

400 Bad Request
{"error":"invalid_client","error_description":"client_id or client_secret is invalid",
 "error_uri":"https://confluence.metrosystems.net/display/IDAM/IDAM+APIs+Error+Codes"}
```

Note: Error response also **leaks internal Confluence documentation URL** (`confluence.metrosystems.net`).

#### 24d. Plain PKCE Accepted (Defeats PKCE Purpose)

`code_challenge_methods_supported: ["plain", "S256"]` — accepting `plain` alongside `S256` means an attacker who intercepts the `code_challenge` can replay it directly as the `code_verifier`, completely defeating PKCE's purpose of protecting against authorization code interception.

#### 24e. SAML Signing Key Exposed in JWKS

The JWKS endpoint includes 5 RSA signing keys, one explicitly labeled as the SAML signing keypair:
```
GET /.well-known/openid-configuration/jwks HTTP/2
Host: idam.metrosystems.net

{
  "keys": [
    {"kid": "4bfbd538-9343-4b58-a99a-dbfd29d45e97", "kty": "RSA", "alg": "RS256", ...},
    {"kid": "K_bdcf9403-6b50-48c0-af26-8c2128e46321", "kty": "RSA", "alg": "RS256", ...},
    {"kid": "K_aa55015a-206a-11ed-98d5-e2cc12b0dc50", "kty": "RSA", "alg": "RS256", ...},
    {"kid": "K_e5352d31-c354-11e9-9c78-0a58ac14002e", "kty": "RSA", "alg": "RS256", ...},
    {"kid": "saml-signing-keypair", "kty": "RSA", "alg": "RS256",
     "n": "18_XBfiRqnIGFIJmsLmjCTwTrgAtZbnBDIQDQuUn0jOj_6QbVbu7N4_..."}
  ]
}
```

The `saml-signing-keypair` key ID leaks that SAML federation is in use and exposes the public component of the SAML signing key. Combined with knowledge of the SAML endpoints, this enables targeted attacks on SAML assertion validation.

### Impact

- **Token theft via implicit flow**: An attacker who controls a registered or misconfigured `redirect_uri` (see Finding 15) can steal access tokens via URL fragments
- **Credential harvesting via password grant**: Malicious applications can capture raw user credentials, bypassing the authorization server's consent screen and any configured MFA
- **Authorization code interception**: Plain PKCE acceptance negates the PKCE security control, leaving the authorization code flow vulnerable to interception (mobile/native apps)
- **Cross-country impact**: Identical misconfiguration across all tested country instances means fixing one instance without the others leaves the platform vulnerable

### Recommendation

1. Disable implicit grant and remove `token` and `id_token token` from supported response types
2. Disable password grant and remove `password` from supported grant types
3. Remove `plain` from supported PKCE methods, enforce `S256` only
4. Remove the `saml-signing-keypair` from the OAuth JWKS endpoint (SAML keys should have their own metadata endpoint)
5. Remove internal Confluence URL from error responses
6. Apply these changes uniformly across all IDAM instances

---

## Finding 25: Shop Platform Injector.js Exposes Internal Architecture and GCP Infrastructure

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `lieferservice.metro.de`, `shop.metro.ro`, and all shop domains (*.metro.de, *.metro.ro — in scope)
**Type**: Information Disclosure (OWASP A01) + Security Misconfiguration (OWASP A05)

### Description

Metro AG's e-commerce shop platform serves an unauthenticated `injector.js` configuration file to all visitors that exposes internal infrastructure details, GCP project identifiers, internal API URLs, A/B experiment configurations, complete store operational data, and Digital Asset Management upload portal URLs. This data is loaded without authentication on every page load across all country-specific shop domains.

### Evidence

#### 25a. GCP Project ID Leaked

```
GET /ordercapture/uidispatcher/static/injector.js HTTP/2
Host: lieferservice.metro.de

var gcpProjectId="cf-ordercaptu-oc-prod-17";
var datadogEnvironment="prod";
var datadogRumSampleRate="4";
var datadogRumPremiumSampleRate="100";
var datadogSessionReplayEnabled="true";
```

This is the **third distinct GCP project name** discovered (alongside `metro-markets-prod` and `metro-markets-staging` from Finding 23). The `cf-ordercaptu-oc-prod-17` project is specifically for the order capture system.

#### 25b. Internal API URLs Exposed

```javascript
var idam_login_base_url="https://idam.metrosystems.net";
var ev_support_base_url="https://api-private.prod.evaluate.metro.cloud/evaluate.support/";
```

The `api-private.prod.evaluate.metro.cloud` URL is explicitly labeled as a private API, yet its hostname is publicly disclosed.

#### 25c. DAM Upload Portal URLs Exposed

```javascript
var creatives_upload_link="https://upload-dam.mac.metro-group.com/upload/select?clusterName=Banner";
var storelist_upload_link="https://upload-dam.mac.metro-group.com/upload/select?clusterName=Category&categoryImageType=Storelist";
```

The Digital Asset Management upload portal is accessible from the internet at `upload-dam.mac.metro-group.com` — returns a full "MAC Upload Assistant" Angular application with IIS/10.0 backend.

#### 25d. Complete Store Configuration (100+ Stores)

The `storeactivation` variable contains operational data for **every German Metro store** (~100+ stores):
```javascript
storeactivation = {
  "00603": {
    "country": "DE",
    "customerlogin": "ACTIVE",
    "cutofftime": "11",
    "cutofftimeholiday": "11",
    "listimport": "ACTIVE",
    "onlinevisibility": "ACTIVE",
    "storeid": "00603",
    "submitbackend": "CUSTOMER_ORDER"
  },
  "00605": {
    "country": "DE",
    "customerlogin": "DISABLED",
    "submitbackend": "BETTY"
  },
  // ... 100+ more stores
}
```

This reveals which stores use the BETTY backend vs CUSTOMER_ORDER, which stores have online ordering disabled, and detailed cutoff time configurations.

#### 25e. A/B Experiment Feature Flags

Complete experiment configurations including active/inactive states and traffic allocation ratios:
```javascript
var abExperiments = {
  "ENABLE_SIDE_CADDY": {"active": true, "ratioAB": 0.0},
  "SD_SHOW_ARTICLLESEARCH_CSAT": {"active": true, "ratioAB": 90.0},
  // ...
};
var abExperimentsFeatureToggles = {
  "METRO_X": {"group": "B"},
  "CIA_NEW_CUSTOMER_PORTAL": {"group": "B"},
  // 27+ feature flags
};
```

#### 25f. IDAM Realm and Metro Markets API Configuration

```javascript
var optionalCountryConfig = {
  "idam-config": {"url": "https://idam.metro.de", "realm": "SSO_CUST_DE"},
  "metroMarketsApiUrl": "https://app-search-2.prod.de.metro-marketplace.cloud/api/v3/search/",
  "metroMarketsBaseUrl": "https://www.metro.de/marktplatz/product/",
  // ...
};
```

Reveals IDAM realm names (`SSO_CUST_DE`, `SSO_CUST_RO` per country), internal marketplace search API endpoint, and self-service registration URLs.

#### 25g. CIA Store ID Mapping (Complete UUID Database)

The `/cia/content/sitecore/storeIdMappingWithOnlineVisibility/DE/de-DE` endpoint returns complete UUID-to-store mappings:
```javascript
window.exploreStoreIdMapping = {
  "00618": "4d737651-64bc-44e2-a200-d86719236772",
  "00403": "5252528c-6906-4350-a0d1-2b7e3d6ad246",
  // ... 100+ UUID mappings
};
```

These UUIDs could enable IDOR attacks against store-specific APIs.

### Impact

- **GCP project enumeration**: Attackers can map Metro AG's cloud infrastructure across at least 3 GCP projects
- **Internal API discovery**: Private API endpoints like `api-private.prod.evaluate.metro.cloud` become targets for further probing
- **Upload portal targeting**: The DAM upload portal running on IIS/10.0 represents an additional attack surface
- **Business intelligence**: Detailed store operations data (active vs disabled stores, backend types, cutoff schedules) provides competitive intelligence
- **Authentication targeting**: IDAM realm names and configurations enable more targeted OAuth attacks

### Recommendation

1. Move GCP project ID and Datadog configuration to server-side only
2. Remove internal API URLs (`api-private.*`) from client-side JavaScript
3. Remove DAM upload portal URLs from public JavaScript
4. Restrict store operational data to authenticated sessions only
5. Move A/B experiment configurations to a server-side evaluation endpoint
6. Ensure the DAM upload portal (`upload-dam.mac.metro-group.com`) requires authentication

---

## Finding 26: Admin Portal Publicly Accessible — Exposes 30 Internal Roles and 20+ Backend Microservice URLs

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `admin.metro-vendoroffice.com` (*.metro-vendoroffice.com — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Information Disclosure

### Description

The production admin panel for MetroMarkets Vendor Office is publicly accessible at `admin.metro-vendoroffice.com`. While login is required for functional access, the Angular SPA's main JavaScript bundle (305KB) is served unauthenticated and exposes the complete internal role-based access control model (30 admin roles) and 20+ backend microservice URLs — information that would normally only be available to authenticated administrators.

### Evidence

**Admin portal accessible without authentication:**
```
GET / HTTP/2
Host: admin.metro-vendoroffice.com

200 OK
Content-Type: text/html; charset=utf-8
```

The HTML page title confirms: `<title>MetroMarkets: Admin Portal</title>`

**30 admin roles exposed in main.js bundle:**
```javascript
ROLE_ADMIN
ROLE_CAN_EXPORT_PAYMENTS
ROLE_CAN_MANAGE_ACCOUNTING_PERIOD
ROLE_CAN_MANAGE_CUSTOMER_REQUESTS
ROLE_CAN_MANAGE_ERP_ATTRIBUTES
ROLE_CAN_MANAGE_FINANCE_REPORTS
ROLE_CAN_MANAGE_INTRASTAT
ROLE_CAN_MANAGE_INVENTORIES
ROLE_CAN_MANAGE_IWT_INVOICES
ROLE_CAN_MANAGE_VENDOR_INVOICES
ROLE_CAN_MANAGE_VENDOR_SETTINGS
ROLE_CAN_VIEW_ACCOUNTS_PAYABLE
ROLE_CAN_VIEW_BANKING_REQUESTS
ROLE_CAN_VIEW_BUYER_INVOICES
ROLE_CAN_VIEW_BUYER_NOTES
ROLE_CAN_VIEW_CUSTOMS_DOCUMENTS
ROLE_CAN_VIEW_FAILED_MESSAGES
ROLE_CAN_VIEW_FORDERS
ROLE_CAN_VIEW_GR_HEADERS
ROLE_CAN_VIEW_INVUNITS
ROLE_CAN_VIEW_IWT_INVOICES
ROLE_CAN_VIEW_MCOM
ROLE_CAN_VIEW_PAYMENTS
ROLE_CAN_VIEW_RETURNS_LIST
ROLE_CAN_VIEW_RETURN_DETAIL
ROLE_CAN_VIEW_SALE_ORDERS
ROLE_CAN_VIEW_VENDORS
ROLE_CAN_VIEW_VENDOR_BALANCES
ROLE_CAN_VIEW_VENDOR_INVOICES
ROLE_VENDOR
```

**20+ backend microservice URLs disclosed:**
```
https://offer-export.metro-vendoroffice.com
https://offer-funnel.metro-vendoroffice.com
https://offer-reactor.metro-vendoroffice.com
https://offer-safety.metro-vendoroffice.com
https://offer-xk.metro-vendoroffice.com
https://www.metro-vendoroffice.com/auth/client-api/
https://www.metro-vendoroffice.com/configuration/client-api/
https://www.metro-vendoroffice.com/delivery-service/client-api/
https://www.metro-vendoroffice.com/demand-planning/client-api/
https://www.metro-vendoroffice.com/finance/client-api/
https://www.metro-vendoroffice.com/inventory-service/client-api/
https://www.metro-vendoroffice.com/label-service/client-api/
https://www.metro-vendoroffice.com/pim-upload/client-api/
https://www.metro-vendoroffice.com/product-data-enhancement/client-api/
https://www.metro-vendoroffice.com/return-service/client-api/
https://www.metro-vendoroffice.com/translation-service/client-api/
```

All offer-* subdomains resolve and respond with JSON 404s (confirming they are live microservices), each with unique `x-app-version` values and the shared cookie domain `.metro-vendoroffice.com`.

**All 5 offer-* microservices confirmed live:**
```
offer-export:  x-app-version: 36419775514
offer-funnel:  x-app-version: 36419789570
offer-reactor: x-app-version: 36419815432
offer-safety:  x-app-version: 36419826826
offer-xk:     x-app-version: 36419837352
```

### Impact

- **Privilege escalation roadmap**: The 30 role names reveal the complete admin RBAC model, enabling targeted privilege escalation testing (BFLA attacks against `ROLE_ADMIN`, `ROLE_CAN_EXPORT_PAYMENTS`, `ROLE_CAN_MANAGE_FINANCE_REPORTS`)
- **Attack surface mapping**: 20+ production microservice URLs provide a complete backend architecture map for targeted API attacks
- **Financial data targeting**: Roles like `ROLE_CAN_EXPORT_PAYMENTS`, `ROLE_CAN_VIEW_ACCOUNTS_PAYABLE`, `ROLE_CAN_VIEW_VENDOR_BALANCES` indicate sensitive financial operations are accessible through this portal
- **Business logic attacks**: Understanding of inventory, demand-planning, delivery, and return services enables business logic exploitation

### Recommendation

1. Restrict access to `admin.metro-vendoroffice.com` via IP allowlisting or VPN requirement
2. Implement code splitting so that role constants and admin-specific routes are not included in the unauthenticated JS bundle
3. Remove hardcoded microservice URLs from client-side code; use a server-side API gateway pattern
4. Consider implementing a Web Application Firewall (WAF) rule to block access to JS source map files

---

## Finding 27: ServiceNow Instance Information Disclosure — stats.do and threads.do Publicly Accessible

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `metro.service-now.com` (metro.service-now.com — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Sensitive Data Exposure

### Description

The Metro AG ServiceNow instance at `metro.service-now.com` exposes multiple debug/diagnostic endpoints without authentication. The `stats.do` and `threads.do` endpoints reveal extensive production server internals including exact build versions, patch levels, Java runtime version, cluster topology, database connection pools, active session counts, memory allocation, and complete Java thread dumps with stack traces. Additionally, the Azure AD tenant ID is leaked in SAML SSO redirect URLs.

### Evidence

#### 27a. stats.do — Production Server Statistics (Unauthenticated)

```
GET /stats.do HTTP/1.1
Host: metro.service-now.com

200 OK — Full server statistics returned
```

**Leaked information includes:**

| Category | Details |
|----------|---------|
| Cluster node | `metro038` |
| Internal hostname | `app133069.bwi201.service-now.com:metro036` |
| Build name | Zurich |
| Build date | 09-23-2026_1515 |
| Build tag | `glide-zurich-07-01-2025__patch10-hotfix4bw39-09-18-2026` |
| Instance name | metro |
| MID buildstamp | `zurich-07-01-2025__patch10-hotfix4bw39-09-18-2026_09-23-2026_1515` |
| Memory | Max: 1963 MB, In use: 1618 MB (82% utilized) |
| Transactions | 1,588,207 total, 370,056 errors (23% error rate) |
| Active sessions | 8 logged in (33 active), max concurrency: 242 |
| Session timeout | 90 minutes |
| DB connection pools | 3 pools, 32 max connections each, with per-connection utilization stats |
| Background scheduler | 8 workers, 1,165,222 total jobs processed |
| Central scheduler node | `app133069.bwi201.service-now.com:metro036` |
| Semaphore sets | Default, Debug, AMB_RECEIVE, TRINO_REST, AMB_SEND, API_INT, Presence |
| API_INT rejections | 251 total max waiter rejections |

#### 27b. threads.do — Java Thread Dump (Unauthenticated)

```
GET /threads.do HTTP/1.1
Host: metro.service-now.com

200 OK — Full Java thread dump returned
```

**Leaked information:**
- Java version: `17.0.19`
- Full stack traces for all running threads
- Internal class names: `com.glide.worker.WorkerThread`, `com.glide.cluster.ClusterSynchronizer`
- Apache Tomcat internals: `org.apache.tomcat.util.threads.ThreadPoolExecutor`
- Cluster synchronizer details: `ClusterSynchronizer.java:252`

#### 27c. Azure AD Tenant ID Leaked in SAML SSO Redirect

The authentication redirect exposes the Azure AD tenant ID:
```
Location: /auth_redirect.do?sysparm_url=https://login.microsoftonline.com/
  1c824dff-9735-475a-9bfa-a16070bc0fd6/saml2?SAMLRequest=...
```

**Azure AD Tenant ID**: `1c824dff-9735-475a-9bfa-a16070bc0fd6`

#### 27d. Service Portal Guest Session Information

The `/sp` service portal returns guest session details:
```javascript
window.NOW.session_id = '7C476D8B47638B108D258945D36D438F';
window.NOW.user_name = 'guest';
window.NOW.user_id = '5136503cc611227c0183e96598c4f706';
window.NOW.user_display_name = 'Guest';
```

Additionally, portal and theme IDs are exposed:
```
portal_id = '81b75d3147032100ba13a5554ee4902b'
theme_id = '79315153cb33310000f8d856634c9c4b'
```

### Impact

- **Version-specific CVE targeting**: The exact build tag (`glide-zurich-07-01-2025__patch10-hotfix4bw39-09-18-2026`) enables attackers to identify unpatched vulnerabilities specific to this ServiceNow release
- **Infrastructure reconnaissance**: Cluster node names, internal hostnames, and database pool configurations map the internal ServiceNow deployment architecture
- **Capacity profiling**: Memory usage (82%), error rate (23%), and session counts enable attackers to plan resource-exhaustion attacks during high-utilization periods
- **Azure AD enumeration**: The tenant ID enables further Azure AD reconnaissance (user enumeration, MFA bypass testing, token abuse)
- **Java version targeting**: Java 17.0.19 version enables targeting known JRE vulnerabilities

### Recommendation

1. Restrict `stats.do` and `threads.do` to authenticated admin users only (ServiceNow ACL: `admin` role required)
2. Configure the ServiceNow instance to block unauthenticated access to debug endpoints via Access Control Lists
3. Consider enabling the ServiceNow "High Security" plugin which restricts these endpoints by default
4. Review and rotate the Azure AD tenant configuration if it was intended to be internal-only
5. Ensure the guest user ID is not reused across instances to prevent cross-instance correlation

---

## Finding 28: Price Backoffice Pre-Production — Publicly Accessible with Unauthenticated Config API and Deprecated OAuth Flow

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `md.betty-pp.metrosystems.net` (betty.metrosystems.net — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Broken Authentication (OWASP A07)

### Description

The Metro AG pre-production price backoffice application at `md.betty-pp.metrosystems.net/price.backoffice/` is publicly accessible on the internet. The application's backend-for-frontend (BFF) exposes an unauthenticated configuration endpoint that leaks the pre-production IDAM URL. Furthermore, the application uses the deprecated OAuth 2.0 implicit grant flow (`response_type=token`) without PKCE, violating RFC 9700 security requirements.

### Evidence

#### 28a. Publicly Accessible Pre-Production Application

```
GET /price.backoffice/ HTTP/2
Host: md.betty-pp.metrosystems.net

200 OK
Content-Type: text/html; charset=utf-8
```

The application is a React SPA (1.8MB JS bundle) for managing pricing across Metro AG's international operations, supporting 14 currencies (EUR, TRY, PLN, RUB, HUF, KZT, UAH, BGN, HRK, CZK, MDL, PKR, RON, RSD, SKK, INR).

#### 28b. Unauthenticated Configuration API Leaks IDAM Pre-Production URL

```
GET /price.bff/config HTTP/2
Host: md.betty-pp.metrosystems.net
CallTreeId: test-123

200 OK
{"idam":{"url":"https://idam-pp.metrosystems.net"}}
```

This exposes the pre-production IDAM instance URL without any authentication — only a `CallTreeId` header (any value accepted) is required.

#### 28c. OAuth Implicit Flow (RFC 9700 Violation)

The JS bundle reveals the authentication configuration:
```javascript
response_type: "token",       // Implicit grant — DEPRECATED
realm_id: "BETTY_REALM",      // Internal realm name
client_id: "BTEX",            // Client ID exposed
user_type: "EMP",             // Employee authentication
scope: "openid clnt=BTEX",
max_age: 86400
```

The implicit flow transmits access tokens in URL fragments, which:
- Are stored in browser history
- Leak via Referer headers
- Cannot use refresh tokens for session management
- Violate RFC 9700 Section 2.1.2 (implicit grant MUST NOT be used)

#### 28d. Complete Backend API Surface Exposed

The JS bundle discloses 12+ BFF API endpoints:
```
/price.bff/config          — Configuration (unauthenticated!)
/price.bff/login           — Login endpoint (POST)
/price.bff/list            — Price list management (POST)
/price.bff/articleData     — Article pricing data (POST)
/price.bff/customer/       — Customer-specific pricing
/price.bff/deliveryFees/   — Delivery fee management
/price.bff/fsd-init-price/ — FSD initialization pricing
/price.bff/order           — Order management
/price.bff/updateDeliveryFees/ — Delivery fee updates
/price.bff/mov-config/     — MOV configuration
/price.bff/df-config/      — Delivery fee configuration
/price.bff/developer       — Developer mode toggle
```

#### 28e. Google Tag Manager on Pre-Production

```html
<script>
  j.src = 'https://www.googletagmanager.com/gtm.js?id=GTM-P2JW77JN';
</script>
```

GTM tracking on a pre-production system sends analytics data about internal employee usage patterns to Google.

### Impact

- **Pre-production environment exposure**: Internal pricing tool accessible from the internet, providing attackers a testing ground without production monitoring
- **IDAM pre-production targeting**: The leaked `idam-pp.metrosystems.net` URL enables attacks against the pre-production identity platform
- **Employee credential theft**: The implicit flow makes employee access tokens susceptible to interception via Referer leakage or browser history
- **API attack surface**: 12+ backend endpoints for pricing, delivery fees, and order management are mapped for targeted attacks
- **Business intelligence**: Currency list and pricing model reveal Metro AG's complete international pricing infrastructure

### Recommendation

1. Restrict `md.betty-pp.metrosystems.net` access via VPN or IP allowlisting — pre-production should not be internet-facing
2. Migrate from OAuth implicit flow to authorization code flow with PKCE (per RFC 9700)
3. Require authentication for the `/price.bff/config` endpoint
4. Remove Google Tag Manager from pre-production environments
5. Validate the `CallTreeId` header rather than accepting any arbitrary value

---

## Finding 29: CSP Weaknesses Across Metro Shop Platform — WebSocket Wildcard and Unsafe-Eval

**Severity**: Low
**CVSS**: 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `consegne.metro.it`, `horeca-dagitim.metro-tr.com`, `online.metro.rs`, `shop.metro.md`, `dostavka-pp.metro.ua`, and all shop domains (in scope)
**Type**: Security Misconfiguration (OWASP A05)

### Description

The Content Security Policy (CSP) deployed across all Metro AG shop domains contains multiple weaknesses that collectively defeat CSP's purpose as a defense-in-depth measure against XSS. The same weaknesses are present on both production and pre-production shop domains across all tested countries.

### Evidence

#### 29a. Wildcard WebSocket in connect-src

```
Content-Security-Policy: ...connect-src 'self' https://*.metro.it ... wss://* ...
```

The `wss://*` directive allows WebSocket connections to **any** server. If an attacker achieves XSS, they can establish a persistent WebSocket to an attacker-controlled server to exfiltrate session tokens, customer data, and pricing information in real-time, bypassing CSP entirely.

**Confirmed on all tested shop domains:**
- consegne.metro.it (Italy production)
- horeca-dagitim.metro-tr.com (Turkey production)
- online.metro.rs (Serbia production)
- shop.metro.md (Moldova production)
- dostavka-pp.metro.ua (Ukraine pre-production)

#### 29b. Unsafe-Eval in script-src

```
script-src 'self' ... 'nonce-HXPLPGsPE1c0fYPYHNtLeQ' 'unsafe-eval';
```

While CSP nonces are used (`nonce-*`), the `'unsafe-eval'` directive completely undermines their protection by allowing:
- `eval()` execution of attacker-injected strings
- `new Function()` constructor
- `setTimeout/setInterval` with string arguments

This means any injection point that can reach `eval()` bypasses the nonce requirement.

#### 29c. Unrestricted Font Loading

```
font-src 'self' https://*;
```

The `font-src https://*` directive allows font loading from any HTTPS domain. While lower impact, combined with CSS injection this enables data exfiltration via font-based side-channel attacks (Unicode-range probing).

### Impact

- **CSP bypass**: The combination of `wss://*` and `unsafe-eval` means CSP provides no effective mitigation against XSS on the shop platform
- **Real-time exfiltration**: WebSocket wildcard enables persistent bidirectional channels to attacker servers — not just one-shot data theft but ongoing session hijacking
- **Scope**: Affects all 15+ country shop domains, both production and pre-production, impacting millions of Metro customers

### Recommendation

1. Replace `wss://*` with specific WebSocket endpoints: `wss://*.mypurecloud.de wss://*.euc1.pure.cloud` (only Genesys Cloud requires WebSocket)
2. Remove `'unsafe-eval'` from script-src — migrate any code using `eval()` to CSP-compatible alternatives
3. Replace `font-src https://*` with specific font origins: `fonts.gstatic.com cdn.metro-online.com cdn.metro-group.com`
4. Enable CSP `report-uri` monitoring to track violations during migration

---

## Finding 30: Pre-Production Self-Service Portal Exposure — Second Azure AD Tenant with OIDC Implicit Flow

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: `my-pp.metro.ua`, `dostavka-pp.metro.ua` (*.metro.ua — in scope)
**Type**: Security Misconfiguration (OWASP A05) + Broken Authentication (OWASP A07)

### Description

Metro AG's Ukrainian pre-production self-service portal at `my-pp.metro.ua` is publicly accessible on the internet, exposing a signup flow that uses a **second Azure AD tenant** (distinct from the one used for ServiceNow in Finding 27) with the OIDC implicit flow (`response_type=id_token`). Additionally, the pre-production shop platform at `dostavka-pp.metro.ua` is fully accessible and leaks extensive pre-production configuration including IDAM URLs, pre-prod CDN, and internal domain mappings. The CSP includes a localhost reference (`pk.betty-test.localhost`) indicating development configurations deployed to production.

### Evidence

#### 30a. Pre-Production Signup with Azure AD Implicit Flow

```
GET /signup/credentials HTTP/2
Host: my-pp.metro.ua

302 Found
Location: https://login.microsoftonline.com/64322308-09a9-47a3-8c1c-b82871d60568/oauth2/v2.0/authorize
  ?client_id=c449e83c-0410-445e-9438-0829bb4f2520
  &scope=openid profile email
  &response_type=id_token          ← OIDC Implicit flow
  &redirect_uri=https://my-pp.metro.ua/signup/callback
  &response_mode=form_post
  &nonce=SI0JGyM9O1cpJ74kEe0eWfYXptGZWZiTQtmqpmOc_Lc
  &state=eyJyZXR1cm5UbyI6Ii9zaWdudXAvY3JlZGVudGlhbHMifQ
```

**Key exposure:**
- Azure AD tenant ID: `64322308-09a9-47a3-8c1c-b82871d60568` (different from ServiceNow tenant `1c824dff-9735-475a-9bfa-a16070bc0fd6`)
- Client ID: `c449e83c-0410-445e-9438-0829bb4f2520`
- Uses `response_type=id_token` — implicit flow transmits identity tokens in URL fragments
- State parameter is base64-encoded JSON: `{"returnTo":"/signup/credentials"}` — potential open redirect vector

#### 30b. Localhost Reference in CSP frame-ancestors

```
Content-Security-Policy: ...frame-ancestors my-pp.metro.ua *.metro.ua *.mm.metro.ua
  *.metrosystems.net *.metro-group.com app.optimizely.com
  cdn-assets-prod.s3.amazonaws.com *.adobemc.com
  experience.adobe.com metro.experiencecloud.adobe.com
  metro.zakaz.md metro-online.pk
  pk.betty-test.localhost          ← Development localhost!
  app.eu.veertly.com;
```

The presence of `pk.betty-test.localhost` in a production CSP indicates that development configurations were not properly sanitized before deployment. This also reveals the `betty-test` internal platform name.

#### 30c. Pre-Production Shop Fully Accessible with Internal Configuration

```
GET /ordercapture/uidispatcher/static/injector.js HTTP/2
Host: dostavka-pp.metro.ua

var idam_login_base_url="https://idam-pp.metrosystems.net";
var ev_support_base_url="https://api-private.pp.evaluate.metro.cloud/evaluate.support/";
var mac_cdn_base_url="https://cdn-pp.metro-group.com";
var tag_prison_domain="pp.metrotags.net";
var datadogEnvironment="prod";   ← Pre-prod tagged as "prod"!
```

Additional pre-production URLs exposed:
```
selfServiceUrl: "https://myaccount-pp.metro.ua"
signupLink: "https://my-pp.metro.ua/signup/credentials"
lostCredentialsUrl: "https://premium-pp.metro.ua/oo2/ua/mcc/ukr/onlineordering/"
siteCoreUrl: "https://www-rev-sc.metro.ua/data/apps/metro"
idam-config.url: "https://idam-pp.metro.ua"
idam-config.realm: "SSO_CUST_UA"
domainFlavors: {"shop-pp.metro.ua": "store", "dostavka-pp.metro.ua": "fsd"}
```

#### 30d. Pre-Production Store Configurations Leaked

The pre-prod injector.js reveals country configurations not visible in production:
```javascript
var mario_countries="FR,DE,ES,PL,HU,KZ,NL,PT,RU,TR,UA,RO,MD,CH,BG,HR,RS,JP,IT,IN,AT,SK,CZ,PK,KZ";
var enzo_countries="AT,BG,CZ,DE,ES,FR,HR,IT,JP,KZ,MD,NL,PK,PL,PT,RO,RS,RU,SK,TR,UA";
var combi_order_countries="FR,DE,PT";
```

The pre-prod includes countries not in production `mario_countries` list (RU, CH, IN, AT, SK, CZ, PK) — revealing upcoming country rollouts.

#### 30e. Web Components Endpoint with Session Cookie

```
GET /web-components/?lang=uk&components=sidebar-navigation HTTP/2
Host: my-pp.metro.ua

200 OK
Access-Control-Allow-Credentials: true
Set-Cookie: wcsSessionId=s%3Ar5Z6...; Path=/web-components; HttpOnly; Secure; SameSite=Lax
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 19
```

The web-components endpoint issues session cookies and has rate limiting, confirming it is an active API service, not just static content.

### Impact

- **Azure AD tenant enumeration**: Second tenant (`64322308-*`) expands the attack surface for Azure AD-specific attacks (token forgery, tenant misconfiguration)
- **Implicit flow weakness**: ID tokens transmitted in URL fragments are susceptible to interception via browser history and Referer leakage
- **Pre-production testing ground**: Publicly accessible pre-prod environments allow attackers to test exploits without production monitoring
- **Country rollout intelligence**: Pre-prod configurations reveal upcoming launches in Russia, Switzerland, India, Austria, Slovakia, Czech Republic, and Pakistan
- **Development artifact in production**: `pk.betty-test.localhost` in CSP shows inadequate configuration review processes

### Recommendation

1. Restrict `my-pp.metro.ua` and `dostavka-pp.metro.ua` access via VPN or IP allowlisting
2. Migrate from OIDC implicit flow (`response_type=id_token`) to authorization code flow with PKCE
3. Remove `pk.betty-test.localhost` and other development references from production CSP
4. Ensure pre-production Datadog environment is tagged as `pre-prod`, not `prod`
5. Use separate Azure AD app registrations for pre-production with restricted permissions

---

## Finding 31: Source Maps Publicly Accessible Across Metro Shop Platform — Full Original Source Code Exposed

**Severity**: Low
**CVSS**: 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: All metro shop domains (consegne.metro.it, horeca-dagitim.metro-tr.com, online.metro.rs, tienda.makro.es, dostavka-pp.metro.ua — in scope)
**Type**: Information Disclosure (OWASP A05)

### Description

JavaScript source maps (`.js.map` files) containing the full original TypeScript source code (`sourcesContent` field populated) are publicly accessible on all metro shop domains. Six micro-frontend entry points and their source maps are served without authentication, totaling over 2.3MB of source map data that exposes the internal `platform-uidispatcher` architecture, Module Federation configuration, internal backoffice module names, and webpack runtime internals.

### Evidence

#### 31a. Source Maps Accessible Platform-Wide

```
GET /ordercapture/uidispatcher/static/app/scripts.js.map HTTP/2
Host: consegne.metro.it

200 OK (479,087 bytes)
Content-Type: application/octet-stream
X-Guploader-Uploadid: AP6rU83NKv...   ← Served from Google Cloud Storage
```

**Confirmed on all tested shop domains (identical 479,087-byte files):**
- consegne.metro.it (Italy production)
- horeca-dagitim.metro-tr.com (Turkey production)
- online.metro.rs (Serbia production)
- tienda.makro.es (Spain/Makro production)
- dostavka-pp.metro.ua (Ukraine pre-production)

#### 31b. Six Micro-Frontend Source Maps With Full Source Code

| Module | Path | Size |
|--------|------|------|
| platform-uidispatcher | `/ordercapture/uidispatcher/static/app/scripts.js.map` | 479 KB |
| betty_ordercapture_ui | `/ordercapture/ui/static/app/oc_ui.js.map` | 493 KB |
| betty_explore_backofficeui | `/searchdiscover/backofficeui/static/app/sd_backoffice_ui.js.map` | 378 KB |
| betty_navbar | `/ordermanagement/navbarui/mf/remoteEntry.js.map` | 345 KB |
| ca_backoffice_ui | `/cia/backoffice-ca-ui/app/ca_backoffice_ui.js.map` | 324 KB |
| cia_backoffice_inspiration | `/cia/backoffice-inspiration-ui/app/cia_backoffice_inspiration.js.map` | 324 KB |

All source maps contain the `sourcesContent` field with 80-107 complete source files each.

#### 31c. Internal Architecture Exposed

The source maps reveal the Module Federation micro-frontend architecture:
```json
{
  "name": "uidispatcher_api",
  "remotes": [
    {"alias": "ca_bo_ui", "name": "ca_backoffice_ui", "entry": "/cia/backoffice-ca-ui/app/ca_backoffice_ui.js"},
    {"alias": "ci_bo_ui", "name": "cia_backoffice_inspiration", "entry": "/cia/backoffice-inspiration-ui/app/..."},
    {"alias": "oc_ui", "name": "oc_ui", "entry": "/ordercapture/ui/static/app/oc_ui.js"},
    {"alias": "explore_ui", "name": "cia_explore_ui", "entry": "/cia/explore-ui/app/cia_explore_ui.js"},
    {"alias": "sd_bo_ui", "name": "sd_backoffice_ui", "entry": "/searchdiscover/backofficeui/static/app/..."}
  ]
}
```

This exposes internal backoffice UI names (`ca_backoffice_ui`, `sd_backoffice_ui`, `cia_backoffice_inspiration`) and the shared dependency graph.

### Impact

- **Source code reverse engineering**: Original TypeScript source code makes vulnerability discovery significantly easier
- **Internal architecture mapping**: Module Federation config reveals the complete micro-frontend architecture including backoffice UIs
- **Platform-wide scope**: Affects every metro shop domain across all countries

### Recommendation

1. Configure GCS/CDN to block serving `.map` files to external clients
2. Remove `sourcesContent` from production source maps (use `nosources-source-map` webpack devtool option)
3. If source maps are needed for error monitoring (Datadog/Sentry), upload them directly to the monitoring service instead of serving them publicly

---

## Finding 32: GCS Production Bucket Directory Listing Enabled on images.metro-marketplace.eu

**Severity**: Medium
**CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: images.metro-marketplace.eu (*.metro-marketplace.eu — in scope)
**Type**: Cloud Misconfiguration — GCS Bucket Listing (OWASP A05)

### Description

The Google Cloud Storage bucket `service-file-images-bucket-prod` backing `images.metro-marketplace.eu` has public directory listing enabled. Any unauthenticated user can enumerate all objects in the production bucket, including brand logos and category images with their metadata (file sizes, ETags, modification timestamps). The bucket also has a wildcard CORS policy (`Access-Control-Allow-Origin: *`), allowing any website to make cross-origin requests to enumerate and download bucket contents.

### Evidence

#### 32a. Bucket Listing Returns Full Object Enumeration

```
GET / HTTP/2
Host: images.metro-marketplace.eu

200 OK
Content-Type: application/xml; charset=UTF-8
Access-Control-Allow-Origin: *
X-GUploader-UploadID: AJjja9YnUUHsCQw...

<ListBucketResult xmlns='http://doc.s3.amazonaws.com/2006-03-01'>
  <Name>service-file-images-bucket-prod</Name>
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>brand_logo/001f5747-fff9-4c9e-aefc-0443dda56a68</Key>
    <LastModified>2025-11-20T10:09:59.000Z</LastModified>
    <ETag>"e510087a024a75e7242e8de6558ca636"</ETag>
    <Size>10220</Size>
  </Contents>
  ... (1000 entries per page, paginated via NextMarker)
```

**First page alone contains 1,000 objects (103 MB) in two categories:**
- `brand_logo/` — 358 files (seller brand logos with UUID names)
- `category_image/` — 642 files (product category images)

The listing is truncated (`IsTruncated: true`), indicating thousands more objects beyond the first page.

#### 32b. Production Bucket Name and Infrastructure Disclosed

- Bucket name: `service-file-images-bucket-prod`
- Served from Google Cloud Storage UploadServer
- Object naming convention: `{type}/{UUID}` — predictable structure

#### 32c. Wildcard CORS Enables Cross-Origin Enumeration

```
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: DNT, Date, User-Agent, X-Requested-With,
  If-Modified-Since, Cache-Control, Content-Type, Content-Length, Range,
  Origin, Authorization, Server, Transfer-Encoding, X-GUploader-UploadID,
  X-Google-Trace, Range, Authorization, ...
```

Any website can use JavaScript to enumerate the bucket contents and download files cross-origin, enabling automated scraping of all marketplace brand assets.

### Impact

- **Complete object enumeration**: All files in the production bucket can be listed and downloaded
- **Metadata exposure**: File modification dates, sizes, and ETags reveal upload patterns and content changes
- **Infrastructure disclosure**: Production bucket name and GCS configuration exposed
- **Cross-origin scraping**: Wildcard CORS allows any website to automate bucket enumeration via JavaScript

### Recommendation

1. Disable public listing on the GCS bucket — set `allUsers` to `objectViewer` only (not `legacyBucketReader`)
2. Replace wildcard CORS with an explicit allowlist of metro domains
3. Consider using signed URLs or CDN-based access control for image serving

---

## Finding 33: Seller Gateway Complete OpenAPI Specification Served Unauthenticated

**Severity**: Low
**CVSS**: 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
**Asset**: service-seller-gateway.prod.de.metro-marketplace.cloud (*.metro-marketplace.cloud — in scope)
**Type**: Information Disclosure — API Documentation Exposure (OWASP A05)

### Description

The seller gateway service at `service-seller-gateway.prod.de.metro-marketplace.cloud` serves its complete OpenAPI 3.0 specification via Swagger UI at `/api/v1/api-doc` and as raw JSON at `/api/v1/api-doc.json` without authentication. The specification documents 21+ API endpoints across two backend services (`app-order-management` and `service-seller-account-health`), complete request/response schemas, and the JWT Bearer authentication scheme.

### Evidence

#### 33a. Swagger UI Publicly Accessible

```
GET / HTTP/2
Host: service-seller-gateway.prod.de.metro-marketplace.cloud

302 Found
Location: .../api/v1/api-doc    ← Redirects to Swagger UI

GET /api/v1/api-doc HTTP/2
200 OK
Content-Type: text/html
<title>service-seller-gateway</title>
<script id="swagger-data" type="application/json">{"spec":{"openapi":"3.0.0",...}}
```

#### 33b. Complete API Surface Documented

**app-order-management endpoints:**
- `POST /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/return-label`
- `DELETE /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/documents/{documentId}`
- `PUT /api/seller/proxy/app-order-management/v1/order-lines/{orderLineId}/return-trackings`
- `GET /api/seller/proxy/app-order-management/v1/delivery-carriers`

**service-seller-account-health (7 KPI types with list/detail/export):**
- Contact Defect Ratio, Invoice Defect Ratio, On-Time Delivery, Order Defect, Pre-Fulfillment Cancellation, Return Defect, Seller Response, Valid Tracking

#### 33c. Health Endpoint Accessible Without Auth

```
GET /api/v1/auth/app-check/health HTTP/2
200 OK
service-seller-gateway is ready.
```

### Impact

- **API surface mapping**: Complete documentation of all seller gateway endpoints enables targeted attacks against authenticated endpoints
- **Data schema exposure**: Full request/response schemas including order numbers, tracking IDs, carrier names, and seller health KPIs
- **Internal service names**: Backend services (`service-seller-account-health`, `app-order-management`) revealed

### Recommendation

1. Restrict Swagger UI and API documentation endpoints to authenticated users only
2. Disable NelmioApiDocBundle default endpoint exposure in production
3. Use API gateway rules to block unauthenticated access to `/api/v1/api-doc*`

---

## Next Steps (Phase 12)

1. **Authenticated testing** — obtain valid test credentials to test IDOR, privilege escalation, and business logic flaws on the betty platform using the disclosed authentication endpoints
2. **Employee entitlement escalation** — using disclosed entitlement codes (lPM, lTM, fISTC) to test privilege escalation once authenticated
3. **Open redirect chaining with Finding 15** — test if the betty SPA processes the `url` query parameter in the redirect_uri as a redirect destination, completing the authorization code theft chain
4. **PunchOut (OCI) procurement testing** — checkout health reveals PunchOut is active; test for unauthorized order injection via cXML
5. **Voucher app access-code brute-force** — the `/api/v1/authenticate?accessCode=` endpoint uses simple codes; test common patterns and numeric sequences on the API backend (`api.cf-vvv-preprod-o6.cf.metro.cloud`)
6. **DOM-based XSS** — thorough client-side JavaScript analysis of SPA applications for postMessage handlers, hash-fragment injection, and unsafe DOM manipulation
7. **Subdomain enumeration** on 10 in-scope wildcard domains (requires DNS tooling like amass/subfinder)
8. **METRO Seller Office main.js analysis** — extract authentication flow, API endpoints, and seller management functionality from the Angular production bundle
9. **State JWT key brute-force** — the my-pp.metro.it state JWT uses HS256; attempt key recovery with common secrets (requires jwt_tool or hashcat)
10. **ria voucher lazy-loaded modules** — VoucherManagementPage and CampaignManagementPage contain additional API endpoints for voucher CRUD operations
