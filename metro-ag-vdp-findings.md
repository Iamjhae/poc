# Metro AG VDP - Security Assessment Findings

**Date**: 2026-09-29
**Scope**: Metro AG Vulnerability Disclosure Program (VDP)
**Tester**: Authorized VDP participant
**Status**: Phase 1 - Quick-win probes completed

---

## Executive Summary

Phase 1 reconnaissance and probing of 66 in-scope Metro AG assets identified **6 reportable findings** across production and pre-production infrastructure. The most critical finding is an unauthenticated production search API exposing ~1M product records with pricing/inventory data, combined with a wildcard CORS misconfiguration enabling cross-origin data theft from any website.

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

## Next Steps (Phase 2)

1. **Search API deep-dive**: Test with authenticated sessions, probe impersonation header behavior, test for IDOR on product/offer IDs
2. **3v Coupon API**: Attempt auth bypass with discovered IDAM client credentials, test for JWT manipulation
3. **Wildcard domain enumeration**: Run subdomain discovery on the 10 in-scope wildcard domains (needs local tooling)
4. **Akamai WAF bypass**: Attempt bypass techniques on protected marketplace domains
5. **PureCloud directory enumeration**: Explore Genesys PureCloud contact center interface
6. **Shop platform deep testing**: XSS testing on search/product parameters, CSRF on cart/order operations
