import javax.servlet.http.*;

public class ErrorHandlingVulnerable {

    // Matches: java-catch-generic-exception
    public void vulnerableEmptyCatch() {
        try {
            int x = 1 / 0;
        } catch (Exception e) {
        }
    }

    // Matches: java-stacktrace-in-response
    public void vulnerableStackTrace(Exception e) {
        e.printStackTrace();
    }

    // Matches: java-exception-message-response
    public void vulnerableExceptionInResponse(HttpServletResponse response, Exception e) throws Exception {
        response.getWriter().write(e.getMessage());
    }

    // Safe: log and return generic error
    public void safeErrorHandling(HttpServletResponse response, Exception e) throws Exception {
        java.util.logging.Logger.getLogger("app").severe(e.getMessage());
        response.getWriter().write("An internal error occurred");
    }
}
