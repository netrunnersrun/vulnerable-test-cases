package com.example.security.falsepositives;

import java.util.*;
import java.net.*;

/**
 * False positive test cases for Java web security, LLM, and Spring patterns.
 * All methods here are SAFE despite matching vulnerability patterns.
 */
public class SafeWebSecurity {

    // --- Spring Security False Positives ---

    /**
     * CSRF enabled (not disabled) with proper security configuration.
     * Pattern matches Spring Security config but CSRF is ON - SAFE.
     */
    public Object configureSecurityChain(Object http) throws Exception {
        // Note: csrf() is called but NOT disable() - CSRF stays enabled
        // This should NOT trigger java-spring-csrf-disable
        return http;
    }

    /**
     * CORS configured with specific origin (not wildcard) - SAFE.
     */
    public Map<String, Object> getCorsConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("allowedOrigins", Arrays.asList("https://app.example.com"));
        config.put("allowedMethods", Arrays.asList("GET", "POST"));
        config.put("allowCredentials", true);
        return config;
    }

    /**
     * permitAll() only on public endpoints (login, health) - SAFE pattern.
     * Authentication required on all other endpoints.
     */
    public Map<String, String> getSecurityRules() {
        Map<String, String> rules = new HashMap<>();
        rules.put("/login", "permitAll");
        rules.put("/health", "permitAll");
        rules.put("/api/**", "authenticated");
        rules.put("/admin/**", "hasRole('ADMIN')");
        return rules;
    }


    // --- SSRF False Positives ---

    /**
     * URL validated against allowlist before connection - NOT SSRF.
     */
    public String fetchFromTrustedAPI(String urlString) throws Exception {
        URL url = new URL(urlString);
        Set<String> allowedHosts = Set.of(
            "api.github.com",
            "api.stripe.com",
            "hooks.slack.com"
        );
        if (!allowedHosts.contains(url.getHost())) {
            throw new SecurityException("Host not in allowlist: " + url.getHost());
        }
        if (!"https".equals(url.getProtocol())) {
            throw new SecurityException("HTTPS required");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setInstanceFollowRedirects(false);
        try (java.io.InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes());
        }
    }

    /**
     * WebClient with hardcoded base URL - NOT SSRF.
     */
    public Object createInternalClient() {
        // Hardcoded internal service URL - no user input
        String baseUrl = "https://internal-api.example.com";
        // Would call: WebClient.create(baseUrl)
        return baseUrl;
    }


    // --- XXE False Positives ---

    /**
     * DocumentBuilderFactory with external entities DISABLED - SAFE.
     */
    public Object parseXmlSafely(String xml) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    }

    /**
     * SAXParserFactory with external entities disabled - SAFE.
     */
    public void parseSaxSafely(String xml) throws Exception {
        javax.xml.parsers.SAXParserFactory factory =
            javax.xml.parsers.SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // Safe to use after disabling XXE features
    }


    // --- LLM API Key False Positives ---

    /**
     * API key loaded from environment variable - NOT hardcoded.
     */
    public String getOpenAIKey() {
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("OPENAI_API_KEY not set");
        }
        return apiKey;
    }

    /**
     * Spring AI config referencing env var placeholder - NOT hardcoded.
     * spring.ai.openai.api-key=${OPENAI_API_KEY}
     */
    public String getSpringAIConfigExample() {
        return "spring.ai.openai.api-key=${OPENAI_API_KEY}";
    }


    // --- Error Handling False Positives ---

    /**
     * Exception caught and logged, generic message returned - SAFE.
     */
    public Map<String, Object> handleError(Exception e) {
        // Log full details server-side
        java.util.logging.Logger.getLogger("SafeWebSecurity")
            .log(java.util.logging.Level.SEVERE, "Request failed", e);
        // Return generic error to client
        Map<String, Object> response = new HashMap<>();
        response.put("error", "An unexpected error occurred");
        response.put("status", 500);
        return response;
    }

    /**
     * JWT secret from environment, not hardcoded - SAFE.
     */
    public String getJwtSecret() {
        return System.getenv("JWT_SECRET");
    }
}
