import java.sql.*;

public class SqlInjectionVulnerable {

    // Matches: java-sqli-concat
    public ResultSet vulnerableConcat(Connection conn, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
    }

    // Matches: java-sqli-statement-execute
    public void vulnerableExecute(Connection conn, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("DELETE FROM users WHERE id = " + userInput);
    }

    // Matches: java-sqli-hibernate-createquery
    public Object vulnerableHibernate(Object session, String userInput) {
        return ((org.hibernate.Session) session).createQuery("FROM User WHERE email = '" + userInput + "'");
    }

    // Matches: java-sqli-jpa-nativequery
    public Object vulnerableJpa(Object em, String userInput) {
        return ((javax.persistence.EntityManager) em).createNativeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
    }

    // Matches: java-sqli-spring-jdbctemplate
    public Object vulnerableJdbc(Object jdbc, String userInput) {
        return ((org.springframework.jdbc.core.JdbcTemplate) jdbc).queryForObject("SELECT * FROM users WHERE id = " + userInput, Object.class);
    }

    // Safe: parameterized query
    public ResultSet safeQuery(Connection conn, String userInput) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userInput);
        return ps.executeQuery();
    }
}
