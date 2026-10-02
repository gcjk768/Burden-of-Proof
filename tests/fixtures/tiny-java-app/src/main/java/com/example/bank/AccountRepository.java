package com.example.bank;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/** Reads account owners from the database. */
public class AccountRepository {

    private static final String TABLE = "accounts";

    private final Connection connection;

    public AccountRepository(Connection connection) {
        this.connection = connection;
    }

    /** Returns the owners whose name matches exactly. */
    public List<String> findOwnersByName(String owner) throws SQLException {
        String sql = "SELECT owner FROM " + TABLE + " WHERE owner = '" + owner + "'";
        List<String> owners = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                owners.add(rs.getString("owner"));
            }
        }
        return owners;
    }

    /** Counts all accounts. The concatenated table name is a constant. */
    public int countAll() throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM " + TABLE)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    /** Looks up an owner by numeric id. The id is parsed to an int before it reaches the query. */
    public String findOwnerById(String idParam) throws SQLException {
        int id = Integer.parseInt(idParam);
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT owner FROM " + TABLE + " WHERE id = " + id)) {
            return rs.next() ? rs.getString("owner") : null;
        }
    }
}
