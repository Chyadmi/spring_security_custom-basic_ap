package com.example.ss_l4.controllers;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    
    
    @GetMapping("/demo")
    public String demo(){
        return "demo";
    }
}
