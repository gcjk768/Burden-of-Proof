package org.owasp.benchmark.testcode;

public class BenchmarkTest00002 {
    public void handle(java.sql.Connection connection, String param) throws java.sql.SQLException {
        int id = Integer.parseInt(param);
        String sql = "SELECT * FROM users WHERE id = " + id;
        java.sql.Statement statement = connection.createStatement();
        statement.executeQuery(sql);
    }
}
