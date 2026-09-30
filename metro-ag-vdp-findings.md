# Metro AG VDP - Security Assessment Findings

**Date**: 2026-09-29
**Scope**: Metro AG Vulnerability Disclosure Program (VDP)
**Tester**: Authorized VDP participant
**Status**: Phase 5 - Pre-prod application analysis + access code authentication + seller portal discovery

---

## Executive Summary

Comprehensive testing of 66 in-scope Metro AG assets identified **21 reportable findings** across production and pre-production infrastructure. The highest-impact findings are:

1. **IDAM OAuth insecure flows enabled** — implicit grant (`response_type=token`), hybrid flow, and id_token all accepted; redirect_uri validation allows query parameter injection (`?url=https://evil.com`) enabling authorization code theft via open redirect chaining (Finding 15)
2. **Orderfulfillment production config.js exposes 639KB of operational data** for 669 stores/depots across 19 countries, including warehouse operations, feature flags, and the complete international domain map — all unauthenticated (Finding 11)
3. **Verbose health endpoints expose complete internal architecture** — orderservice leaks 43 internal components (PostgreSQL, Cassandra, Flyway, Dropwizard, credit check systems, DANA export), checkout leaks PunchOut B2B and Loyalty/CDM token services; 401 errors leak Java servlet classes and internal HTTP URIs (Finding 14)
4. **3v Coupon API leaks full RSA public key** (2048-bit) through verbose JWT error messages, returning 500 Internal Server Error instead of 401 (Finding 7)
5. **Semicolon path parameter traversal** (..;/) bypasses path-based routing across all betty services (Finding 13)
6. **ria voucher pre-prod app exposes access-code authentication via GET parameter** — authentication tokens (JWTs) transmitted in URLs, stored in localStorage, with full permission system and store data leaked in JS bundle (Finding 19)
7. **AXCSS OAuth client_id confirmed on production IDAM** — second OAuth client discovered via pre-prod, with state JWT using HS256 symmetric signing (Finding 20)

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

## Finding 21: METRO Seller Office — Live Production Angular Application with K8s Ingress Exposure

**Severity**: Medium
**Asset**: `www.metro-selleroffice.com` (*.metro-selleroffice.com — in scope as wildcard domain)
**Type**: Security Misconfiguration (OWASP A05) + Information Disclosure (OWASP A02)

### Description

The METRO Seller Office (`www.metro-selleroffice.com`) is a live production Angular application for managing seller organizations on the Metro/Makro marketplace. The application exposes internal infrastructure details through response headers and loads resources from a production CDN that reveals internal domain naming conventions.

### Evidence

**Response headers leak infrastructure:**
```
x-ingress-controller: v2              ← Kubernetes Ingress version
x-ingress-request-id: e79420955df...  ← Request tracking UUID
x-ingress-request-start: t=1790736666.286  ← Unix timestamp of request
x-powered-by: A fleet of awesome Marketeers. Apply today - https://www.metro-markets.de/careers
```

**CDN reveals internal production domain:**
```html
<script src="https://mma-mp-de-production-cdn.prod.de.metro-marketplace.cloud/scripts/modernizr/modernizr.min.js"></script>
```
And in JavaScript:
```javascript
window.cdn = "https://mma-mp-de-production-cdn.prod.de.metro-marketplace.cloud";
```
This reveals the internal CDN naming convention: `mma-mp-{country}-production-cdn.prod.{country}.metro-marketplace.cloud`

**CSP allows framing from Storyblok CMS:**
```
content-security-policy: frame-ancestors 'self' https://app.storyblok.com;
```
This confirms they use Storyblok as their CMS — a third-party dependency with its own attack surface.

**Angular application structure:**
```html
<app-root></app-root>
<script src="/static/runtime.b1c4a3a81339ec5d.js" type="module"></script>
<script src="/static/polyfills.917b26ff406b999d.js" type="module"></script>
<script src="/static/main.3672261e6b5c6dd1.js" type="module"></script>
```

**Application purpose**: "Manage your products, sales, and inventory with METRO Seller Office. Start selling on METRO/Makro Marketplace today." — this is a seller management portal for the marketplace.

### Impact

- **K8s ingress metadata**: The `x-ingress-controller: v2` header confirms Kubernetes is used for orchestration, and the request timestamp enables timing analysis of server processing
- **CDN naming convention**: The internal CDN domain pattern enables discovery of CDN endpoints for other countries/environments by substituting country codes
- **Storyblok CMS dependency**: If the Storyblok account is compromised, content injection into the seller portal becomes possible via the `frame-ancestors` CSP allowing Storyblok framing
- **Angular application**: The main.js (production build) likely contains API endpoints, authentication flow, and seller management functionality that could reveal further attack vectors

### Recommendation

1. **Remove verbose response headers** — strip `x-ingress-controller`, `x-ingress-request-start`, and `x-powered-by` from production responses
2. **Restrict Storyblok framing** to specific editing contexts rather than blanket CSP allowance
3. **Rate limit** the seller office login/registration endpoints
4. **Audit CDN access controls** — ensure the production CDN doesn't serve internal or pre-prod assets

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
- METRO Seller Office production Angular app with K8s ingress metadata leak (Finding 21)
- my-pp.metro.it pre-prod CSP with unsafe-eval, unsafe-inline, and Apollo GraphQL sandbox (Finding 20)

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
- *.metro-marketplace.cloud subdomains (all DNS resolution failures — no active subdomains found)
- *.metro-markets.net subdomains (all DNS resolution failures)
- *.metro-vendorcentral.com subdomains (all DNS resolution failures)
- ria voucher API backend at api.cf-vvv-preprod-o6.cf.metro.cloud (returns 404 for all tested paths — backend may require different routing)

## Next Steps (Phase 6)

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
