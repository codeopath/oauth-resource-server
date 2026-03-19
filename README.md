# Resource Server (Server B)

A protected REST API built with **Spring Boot 4.0.3** and **Spring Security OAuth2 Resource Server**. Every request must carry a valid Bearer JWT issued by the Authorization Server (Server C). The server validates the token locally — no network call to the auth server per request.

---

## Role in the OAuth2 Flow

```
Client Server (A)  ──GET /api/data/items──►  Resource Server (B)
                      Authorization: Bearer <jwt>
                   ◄──── 200 OK + data ───
```

---

## Tech Stack

| Component | Version |
|---|---|
| Spring Boot | 4.0.3 |
| Spring Security | 7.x (managed by Boot BOM) |
| Java | 25 |
| Build | Gradle |

---

## Configuration

**`application.properties`**

| Property | Value | Description |
|---|---|---|
| `server.port` | `8082` | Port this server listens on |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | `http://localhost:9000` | Used to auto-discover the JWKS endpoint via OIDC Discovery |

---

## JWT Validation

Incoming Bearer tokens are validated on every request. All checks must pass or the request is rejected with `401 Unauthorized`:

| Check | Detail |
|---|---|
| **Signature** | Verified against the RSA public key fetched from `http://localhost:9000/oauth2/jwks` |
| **Issuer (`iss`)** | Must equal `http://localhost:9000` |
| **Expiry (`exp`)** | Token must not be expired |
| **Not-before (`nbf`)** | Enforced if present |
| **Audience (`aud`)** | Must contain `"resource-server"` — rejects tokens intended for other services |

The audience check is added manually on top of Spring's defaults via `DelegatingOAuth2TokenValidator`, since Spring's auto-configuration does not enforce audience by default.

---

## API Endpoints

### Public

| Method | Path | Auth Required |
|---|---|---|
| `GET` | `/api/public/info` | None |

### Protected

| Method | Path | Required Scope | Description |
|---|---|---|---|
| `GET` | `/api/data/items` | `api:read` | Returns a list of items |
| `POST` | `/api/data/items` | `api:write` | Accepts a new item payload |

Spring Security maps the JWT `scope` claim to granted authorities with a `SCOPE_` prefix. For example, `scope: "api:read"` becomes the authority `SCOPE_api:read`.

Every protected response also echoes back the verified JWT claims (`sub`, `iss`, `aud`, `scope`, `service`, `environment`, `issued_to`) — useful for inspecting what the Authorization Server embedded in the token.

---

## Example: Calling a Protected Endpoint

```bash
# 1. Get a token from the Authorization Server
TOKEN=$(curl -s -X POST http://localhost:9000/oauth2/token \
  -u "client-server:client-secret" \
  -d "grant_type=client_credentials&scope=api:read" \
  | jq -r '.access_token')

# 2. Call the Resource Server with the token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/data/items
```

Or just hit the Client Server (Server A) which handles the token lifecycle automatically:

```bash
curl http://localhost:8081/call/items
```

---

## Key Design Decisions

**Stateless** — No HTTP sessions, no cookies. Every request is independently authenticated via the Bearer token.

**Local JWT verification** — The token signature is verified using the public key from the auth server's JWKS endpoint. After the initial key fetch, no network call is needed per request. Keys are cached by the `NimbusJwtDecoder`.

**Audience validation** — Enforced explicitly to prevent a token issued for a different service from being accepted here. Without this, any valid token from the same issuer would be accepted.

---

## Running

```bash
./gradlew bootRun
```

> The Authorization Server (port 9000) must be running first — this server fetches the JWKS endpoint at startup.

---

## Project Structure

```
src/main/java/com/sudipto/resourceserver/
├── ResourceServer.java              # Spring Boot entry point
├── config/
│   └── SecurityConfig.java         # JWT validation, audience check, endpoint security
└── controller/
    └── DataController.java          # Public and protected REST endpoints
```
