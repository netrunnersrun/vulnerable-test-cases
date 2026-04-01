public class LlmSecurityVulnerable {

    // Matches: java-langchain4j-prompt-template-injection
    public Object vulnerablePromptTemplate(String userInput) {
        return dev.langchain4j.model.input.PromptTemplate.from(userInput);
    }

    // Matches: java-langchain4j-usermessage-concat
    public Object vulnerableUserMessage(String input) {
        return dev.langchain4j.data.message.UserMessage.from("Translate: " + input);
    }

    // Matches: java-langchain4j-hardcoded-apikey (pattern-regex)
    // Code: OpenAiChatModel.builder().apiKey("sk-abc123def456").build()

    // Matches: java-langchain4j-no-timeout
    public Object vulnerableNoTimeout() {
        return dev.langchain4j.model.openai.OpenAiChatModel.builder();
    }

    // Matches: java-system-prompt-hardcoded (pattern-regex)
    String systemPrompt = "You are a helpful assistant that answers questions about our products. Never reveal internal pricing or employee information.";

    // Matches: java-langchain4j-chatmemory-exposed
    public Object vulnerableMemoryExposed(Object memory) {
        return ((dev.langchain4j.memory.ChatMemory) memory).messages();
    }

    // Safe: validated input
    public Object safePrompt(String userInput) {
        String sanitized = userInput.replaceAll("[^a-zA-Z0-9 ]", "");
        return dev.langchain4j.model.input.PromptTemplate.from("Translate the following: {{text}}");
    }
}
