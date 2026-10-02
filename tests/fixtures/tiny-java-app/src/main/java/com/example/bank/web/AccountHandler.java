package com.example.bank.web;

import com.example.bank.AccountService;
import java.sql.SQLException;
import java.util.Map;

/** HTTP-facing handler: query parameters come straight from the request. */
public class AccountHandler {

    private final AccountService service;

    public AccountHandler(AccountService service) {
        this.service = service;
    }

    public String handle(Map<String, String> queryParams) throws SQLException {
        String owner = queryParams.get("owner");
        return String.join(",", service.search(owner));
    }
}
