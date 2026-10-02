package com.example.bank;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Serves monthly reports stored as files under one directory. */
public class ReportStore {

    private final Path baseDir;

    public ReportStore(Path baseDir) {
        this.baseDir = baseDir;
    }

    /** Returns the text of the named report. */
    public String read(String reportName) throws IOException {
        Path file = baseDir.resolve(reportName);
        return Files.readString(file);
    }
}
