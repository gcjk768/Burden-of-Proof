package com.example.bank;

import java.util.Map;
import org.apache.commons.text.StringSubstitutor;

/** Builds greeting lines from a template. */
public class Greeting {

    public String greet(String name) {
        return StringSubstitutor.replace("Hello, ${name}!", Map.of("name", name));
    }
}
