package com.example.bank.web;

import com.example.bank.ReportStore;
import java.io.IOException;
import java.util.Map;

/** HTTP-facing handler for downloading a report by name. */
public class ReportHandler {

    private final ReportStore store;

    public ReportHandler(ReportStore store) {
        this.store = store;
    }

    public String handle(Map<String, String> queryParams) throws IOException {
        return store.read(queryParams.get("report"));
    }
}
