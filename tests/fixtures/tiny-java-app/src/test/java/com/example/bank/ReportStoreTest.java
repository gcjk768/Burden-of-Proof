package com.example.bank;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void readsReportByName() throws Exception {
        Files.writeString(tempDir.resolve("2026-09.txt"), "September report");
        assertEquals("September report", new ReportStore(tempDir).read("2026-09.txt"));
    }
}
