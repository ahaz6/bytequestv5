package com.bytequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
 * ByteQuest v5 - minimale Spring-Boot-App zur Demo von Insecure Deserialization.
 */
@SpringBootApplication
public class ByteQuestApplication {
    public static void main(String[] args) {
        SpringApplication.run(ByteQuestApplication.class, args);
    }
}
