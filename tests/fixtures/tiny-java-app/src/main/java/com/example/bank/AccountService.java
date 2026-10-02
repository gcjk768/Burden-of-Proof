package com.example.bank;

import java.sql.SQLException;
import java.util.List;

/** Business logic for looking up accounts. */
public class AccountService {

    private final AccountRepository repository;

    public AccountService(AccountRepository repository) {
        this.repository = repository;
    }

    /** Searches accounts by owner name, ignoring surrounding whitespace. */
    public List<String> search(String ownerQuery) throws SQLException {
        if (ownerQuery == null) {
            return List.of();
        }
        return repository.findOwnersByName(ownerQuery.strip());
    }
}
