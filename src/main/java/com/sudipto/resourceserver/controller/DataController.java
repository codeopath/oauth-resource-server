package com.sudipto.resourceserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * Resource Server REST API (Server B)
 *
 * <p>Exposes protected and public endpoints. Access control is enforced by
 * {@link com.sudipto.resourceserver.config.SecurityConfig}:
 *
 * <ul>
 *   <li>{@code GET /api/public/info}   – No token required</li>
 *   <li>{@code GET /api/data/items}    – Requires scope {@code api:read}</li>
 *   <li>{@code POST /api/data/items}   – Requires scope {@code api:write}</li>
 * </ul>
 *
 * <p>Each protected endpoint echoes back the verified JWT claims so callers
 * can inspect what the Authorization Server embedded in the token.
 */
@RestController
@RequestMapping("/api")
public class DataController {

    /**
     * Public endpoint – no Bearer token required.
     *
     * <p>Useful for health/liveness checks and to verify the server is reachable
     * before attempting authenticated calls.
     */
    @GetMapping("/public/info")
    public ResponseEntity<Map<String, Object>> publicInfo() {
        return ResponseEntity.ok(Map.of(
                "server", "resource-server (Server B)",
                "status", "running",
                "timestamp", Instant.now().toString(),
                "message", "This endpoint is public – no token required."
        ));
    }

    /**
     * Protected read endpoint – requires scope {@code api:read}.
     *
     * <p>Returns sample data along with the verified JWT claims so the caller
     * can see exactly what was asserted by the Authorization Server.
     *
     * @param jwt the verified JWT injected by Spring Security
     */
    @GetMapping("/data/items")
    public ResponseEntity<Map<String, Object>> getItems(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "server", "resource-server (Server B)",
                "endpoint", "GET /api/data/items",
                "requiredScope", "api:read",
                "data", java.util.List.of(
                        Map.of("id", 1, "name", "Widget Alpha", "price", 9.99),
                        Map.of("id", 2, "name", "Widget Beta", "price", 14.99),
                        Map.of("id", 3, "name", "Widget Gamma", "price", 24.99)
                ),
                "tokenClaims", extractRelevantClaims(jwt)
        ));
    }

    /**
     * Protected write endpoint – requires scope {@code api:write}.
     *
     * <p>Accepts a new item payload and returns a confirmation with the
     * verified JWT claims so the caller can audit what was presented.
     *
     * @param jwt     the verified JWT injected by Spring Security
     * @param payload request body (any JSON object)
     */
    @PostMapping("/data/items")
    public ResponseEntity<Map<String, Object>> createItem(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody Map<String, Object> payload) {

        return ResponseEntity.ok(Map.of(
                "server", "resource-server (Server B)",
                "endpoint", "POST /api/data/items",
                "requiredScope", "api:write",
                "message", "Item received and would be persisted in a real application.",
                "receivedPayload", payload,
                "tokenClaims", extractRelevantClaims(jwt)
        ));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the most relevant claims from the JWT for diagnostic / audit responses.
     *
     * <p>Exposes the custom claims added by the Authorization Server's token customizer
     * (audience, service, environment, issued_to) alongside the standard OAuth2 claims.
     */
    private Map<String, Object> extractRelevantClaims(Jwt jwt) {
        return Map.of(
                "sub", jwt.getSubject(),
                "iss", jwt.getIssuer() != null ? jwt.getIssuer().toString() : "N/A",
                "aud", jwt.getAudience(),
                "scope", jwt.getClaimAsString("scope") != null ? jwt.getClaimAsString("scope") : "N/A",
                "service", jwt.getClaimAsString("service") != null ? jwt.getClaimAsString("service") : "N/A",
                "environment", jwt.getClaimAsString("environment") != null ? jwt.getClaimAsString("environment") : "N/A",
                "issued_to", jwt.getClaimAsString("issued_to") != null ? jwt.getClaimAsString("issued_to") : "N/A",
                "expiresAt", jwt.getExpiresAt() != null ? jwt.getExpiresAt().toString() : "N/A"
        );
    }
}
