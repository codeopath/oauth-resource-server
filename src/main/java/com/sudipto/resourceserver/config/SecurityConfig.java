package com.sudipto.resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * Resource Server Security Configuration (Server B)
 *
 * <p>This server accepts only requests that carry a valid Bearer JWT issued by
 * the Authorization Server (Server C). Validation checks:
 * <ol>
 *   <li><strong>Signature</strong> – verified against the JWKS published by Server C</li>
 *   <li><strong>Issuer ({@code iss})</strong> – must be {@code http://localhost:9000}</li>
 *   <li><strong>Expiry ({@code exp})</strong> – token must not be expired</li>
 *   <li><strong>Audience ({@code aud})</strong> – must contain {@code "resource-server"}</li>
 *   <li><strong>Scope</strong> – endpoint-specific scope enforcement (see filter chain)</li>
 * </ol>
 *
 * <p>The server is completely stateless – no sessions, no cookies.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // Allows @PreAuthorize on individual methods
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    /**
     * Main security filter chain.
     *
     * <p>Endpoint access rules:
     * <ul>
     *   <li>{@code GET /api/public/**}  – no authentication required</li>
     *   <li>{@code GET /api/data/**}    – requires scope {@code api:read}</li>
     *   <li>{@code POST /api/data/**}   – requires scope {@code api:write}</li>
     *   <li>All other requests         – must be authenticated (any valid token)</li>
     * </ul>
     *
     * <p>Spring Security maps JWT {@code scope} claim values to granted authorities
     * with the prefix {@code SCOPE_}. For example, scope {@code "api:read"} becomes
     * the authority {@code "SCOPE_api:read"}.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Stateless REST API – never create an HTTP session
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authorize -> authorize
                        // Public endpoint – no token needed
                        .requestMatchers(HttpMethod.GET, "/api/public/**").permitAll()
                        // Read operations require the api:read scope
                        .requestMatchers(HttpMethod.GET, "/api/data/**").hasAuthority("SCOPE_api:read")
                        // Write operations require the api:write scope
                        .requestMatchers(HttpMethod.POST, "/api/data/**").hasAuthority("SCOPE_api:write")
                        // Everything else just needs a valid token
                        .anyRequest().authenticated()
                )
                // Configure as an OAuth2 resource server validating JWT Bearer tokens
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                )
                // Disable CSRF – stateless APIs use tokens, not session cookies
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    /**
     * JWT decoder with enhanced validation.
     *
     * <p>The default decoder (auto-configured via {@code issuer-uri}) only validates
     * the issuer and expiry. We add <strong>audience validation</strong> on top:
     * the token's {@code aud} claim must contain {@code "resource-server"}.
     *
     * <p>This prevents token substitution attacks where a JWT intended for a different
     * service is replayed against this server.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        // Fetch the JWKS endpoint from the issuer's OIDC Discovery document
        // and configure RS256 signature verification
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withIssuerLocation(issuerUri)
                .build();

        // Standard validators: issuer + expiry + not-before
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuerUri);

        // Custom audience validator: aud claim must contain "resource-server"
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD,
                aud -> aud != null && aud.contains("resource-server")
        );

        // Combine all validators; any failure → 401 Unauthorized
        OAuth2TokenValidator<Jwt> combinedValidator =
                new DelegatingOAuth2TokenValidator<>(defaultValidators, audienceValidator);

        jwtDecoder.setJwtValidator(combinedValidator);
        return jwtDecoder;
    }
}
