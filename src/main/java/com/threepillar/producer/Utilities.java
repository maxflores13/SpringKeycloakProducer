package com.threepillar.producer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Slf4j
public class Utilities {

    @GetMapping("/operationSingleUser")
    public ResponseEntity<String> getOperation(){
        return ResponseEntity.ok().body("Hello I am a single user");
    }

    @GetMapping("/operationAdminUser")
    public ResponseEntity<String> getOperationAdmin(){
        return ResponseEntity.ok().body("Hello I am a admin user");
    }
}
