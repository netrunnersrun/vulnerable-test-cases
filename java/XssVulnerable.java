import org.springframework.ui.Model;

public class XssVulnerable {

    // Matches: java-spring-model-unescaped
    public String vulnerableSpringModel(Model model, String userInput) {
        model.addAttribute("name", userInput);
        return "profile";
    }

    // Matches: java-jsp-scriptlet-output (pattern-regex)
    // This is a comment containing: <%= username %>

    // Safe: use Thymeleaf auto-escaping
    public String safeThymeleaf(Model model, String userInput) {
        String escaped = org.apache.commons.text.StringEscapeUtils.escapeHtml4(userInput);
        model.addAttribute("name", escaped);
        return "profile";
    }
}
