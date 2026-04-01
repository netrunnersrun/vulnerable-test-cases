import java.net.*;

public class SsrfVulnerable {

    // Matches: java-ssrf-url-openconnection
    public URLConnection vulnerableUrl(String userInput) throws Exception {
        return new URL(userInput).openConnection();
    }

    // Matches: java-ssrf-httpurlconnection
    public HttpURLConnection vulnerableHttp(String userInput) throws Exception {
        return (HttpURLConnection) new URL(userInput).openConnection();
    }

    // Matches: java-ssrf-resttemplate
    public Object vulnerableRestTemplate(Object template, String userInput) {
        return ((org.springframework.web.client.RestTemplate) template).getForObject(userInput, String.class);
    }

    // Matches: java-ssrf-webclient
    public Object vulnerableWebClient(String userInput) {
        return org.springframework.web.reactive.function.client.WebClient.create(userInput);
    }

    // Safe: URL allowlist validation
    public URLConnection safeUrl(String userInput) throws Exception {
        URL url = new URL(userInput);
        if (!url.getHost().endsWith(".trusted.com")) throw new SecurityException("Blocked");
        return url.openConnection();
    }
}
