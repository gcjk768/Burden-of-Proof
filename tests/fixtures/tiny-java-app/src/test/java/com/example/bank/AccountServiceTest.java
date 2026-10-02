package com.example.bank;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccountServiceTest {

    private Connection connection;
    private AccountService service;

    @BeforeEach
    void setUp() throws Exception {
        connection = DriverManager.getConnection("jdbc:h2:mem:service;DB_CLOSE_DELAY=-1");
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE accounts (id INT, owner VARCHAR(64))");
            stmt.execute("INSERT INTO accounts VALUES (1, 'alice'), (2, 'bob')");
        }
        service = new AccountService(new AccountRepository(connection));
    }

    @AfterEach
    void tearDown() throws Exception {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DROP ALL OBJECTS");
        }
        connection.close();
    }

    @Test
    void findsOwnerByExactName() throws Exception {
        assertEquals(List.of("alice"), service.search("  alice "));
    }

    @Test
    void returnsNothingForUnknownOwner() throws Exception {
        assertEquals(List.of(), service.search("mallory"));
    }

    @Test
    void countsAllAccounts() throws Exception {
        assertEquals(2, new AccountRepository(connection).countAll());
    }

    @Test
    void findsOwnerById() throws Exception {
        assertEquals("bob", new AccountRepository(connection).findOwnerById("2"));
    }
}
