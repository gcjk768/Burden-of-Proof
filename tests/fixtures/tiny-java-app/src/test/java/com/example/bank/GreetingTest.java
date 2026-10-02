package com.example.bank;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class GreetingTest {

    @Test
    void greetsByName() {
        assertEquals("Hello, Ada!", new Greeting().greet("Ada"));
    }
}
