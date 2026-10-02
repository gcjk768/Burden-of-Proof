package org.owasp.benchmark.testcode;

public class BenchmarkTest00001 {
    public void handle(java.sql.Connection connection, String param) throws java.sql.SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + param + "'";
        java.sql.Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
