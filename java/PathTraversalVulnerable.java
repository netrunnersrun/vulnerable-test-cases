import java.io.*;
import java.nio.file.*;

public class PathTraversalVulnerable {

    // Matches: java-path-traversal-file
    public File vulnerableFile(String userInput) {
        return new File(userInput);
    }

    // Matches: java-path-traversal-paths
    public Path vulnerablePaths(String userInput) {
        return Paths.get(userInput);
    }

    // Matches: java-path-traversal-files-read
    public byte[] vulnerableFilesRead(String userInput) throws IOException {
        return Files.readAllBytes(Paths.get(userInput));
    }

    // Matches: java-spring-path-traversal-resource
    public Object vulnerableResource(String userInput) {
        return new org.springframework.core.io.ClassPathResource(userInput);
    }

    // Safe: canonicalize and validate
    public byte[] safeRead(String userInput) throws IOException {
        Path base = Paths.get("/safe/base/dir").toRealPath();
        Path resolved = base.resolve(userInput).normalize().toRealPath();
        if (!resolved.startsWith(base)) throw new SecurityException("Path traversal");
        return Files.readAllBytes(resolved);
    }
}
