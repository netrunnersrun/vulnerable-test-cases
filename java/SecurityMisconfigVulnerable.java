public class SecurityMisconfigVulnerable {

    // Matches: java-spring-cors-allowall (pattern-regex)
    // Config: .cors().configurationSource(... allowedOrigins("*") ...)

    // Matches: java-spring-security-permitall (pattern-regex)
    // Config: .authorizeRequests().anyRequest().permitAll()

    // Matches: java-spring-h2-console-enabled (pattern-regex)
    // Properties: spring.h2.console.enabled=true

    // Matches: java-spring-csrf-disable
    public void vulnerableCsrfDisable(Object http) throws Exception {
        ((org.springframework.security.config.annotation.web.builders.HttpSecurity) http).csrf().disable();
    }

    // Safe: proper Spring Security config
    public void safeConfig() {
        // Use .csrf().csrfTokenRepository(...)
        // Set specific CORS origins
    }
}
