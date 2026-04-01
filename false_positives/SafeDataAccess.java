package com.example.security.falsepositives;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * False positive test cases for Java data access and crypto.
 * All methods here are SAFE despite matching vulnerability patterns.
 */
public class SafeDataAccess {

    // --- SQL Injection False Positives ---

    /**
     * PreparedStatement with parameterized query - NOT SQL injection.
     */
    public User getUserById(Connection conn, int userId) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new User(rs.getInt("id"), rs.getString("name"));
            }
        }
        return null;
    }

    /**
     * JPA named query with bound parameter - NOT injection.
     */
    public List<Object> searchUsers(Object em, String name) {
        return ((javax.persistence.EntityManager) em)
            .createQuery("SELECT u FROM User u WHERE u.name = :name")
            .setParameter("name", name)
            .getResultList();
    }

    /**
     * Spring JdbcTemplate with parameterized query - NOT injection.
     */
    public Map<String, Object> findOrder(Object jdbcTemplate, long orderId) {
        String sql = "SELECT * FROM orders WHERE id = ?";
        return ((org.springframework.jdbc.core.JdbcTemplate) jdbcTemplate)
            .queryForMap(sql, orderId);
    }

    /**
     * Hibernate Criteria API (type-safe, no string concatenation) - SAFE.
     */
    public List<Object> getActiveUsers(Object session) {
        return ((org.hibernate.Session) session)
            .createCriteria(User.class)
            .add(org.hibernate.criterion.Restrictions.eq("active", true))
            .list();
    }


    // --- Path Traversal False Positives ---

    /**
     * File path canonicalized and validated against base directory - SAFE.
     */
    public byte[] readUploadedFile(String filename) throws IOException {
        Path baseDir = Paths.get("/data/uploads").toRealPath();
        Path requested = baseDir.resolve(filename).normalize().toRealPath();
        if (!requested.startsWith(baseDir)) {
            throw new SecurityException("Path traversal attempt blocked");
        }
        return Files.readAllBytes(requested);
    }

    /**
     * File created with integer-only name (no user string injection) - SAFE.
     */
    public File getTempReport(int reportId) {
        return new File("/tmp/reports/" + reportId + ".pdf");
    }

    /**
     * ClassPathResource with hardcoded prefix and validated extension - SAFE.
     */
    public InputStream loadTemplate(String templateName) throws IOException {
        if (!templateName.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid template name");
        }
        String path = "templates/" + templateName + ".html";
        return getClass().getClassLoader().getResourceAsStream(path);
    }


    // --- Deserialization False Positives ---

    /**
     * SnakeYAML with SafeConstructor - SAFE deserialization.
     */
    public Map<String, Object> parseYamlConfig(String yaml) {
        org.yaml.snakeyaml.Yaml safeYaml =
            new org.yaml.snakeyaml.Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor());
        return safeYaml.load(yaml);
    }

    /**
     * Jackson without defaultTyping (safe by default) - SAFE.
     */
    public Map<String, Object> parseJsonSafely(String json) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper mapper =
            new com.fasterxml.jackson.databind.ObjectMapper();
        // No enableDefaultTyping() - safe against polymorphic deserialization
        return mapper.readValue(json, Map.class);
    }


    // --- Crypto False Positives ---

    /**
     * MD5 for non-security checksum (cache key / ETag) - acceptable use.
     */
    public String computeChecksum(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * AES-GCM with proper key derivation - SAFE crypto.
     */
    public byte[] encryptData(byte[] plaintext, char[] password, byte[] salt)
            throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 310000, 256);
        SecretKey key = new SecretKeySpec(
            factory.generateSecret(spec).getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        // Prepend IV
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    /**
     * SecureRandom with default constructor (proper entropy) - SAFE.
     */
    public String generateToken() {
        SecureRandom random = new SecureRandom();
        byte[] token = new byte[32];
        random.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }


    // --- Helper class ---

    static class User {
        int id;
        String name;
        User(int id, String name) { this.id = id; this.name = name; }
    }
}
