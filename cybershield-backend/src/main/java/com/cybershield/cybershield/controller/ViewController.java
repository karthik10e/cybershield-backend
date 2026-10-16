package com.cybershield.cybershield.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/")
    public String index() {
        return "forward:/index.html";
    }

    @GetMapping("/scanner")
    public String scanner() {
        return "forward:/scanner.html";
    }

    @GetMapping("/firewall")
    public String firewall() {
        return "forward:/firewall.html";
    }

    @GetMapping("/models")
    public String models() {
        return "forward:/models.html";
    }

    @GetMapping("/api-docs")
    public String apiDocs() {
        return "forward:/api_docs.html";
    }
}
