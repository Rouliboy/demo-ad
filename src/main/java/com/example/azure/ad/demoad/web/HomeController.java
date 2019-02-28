package com.example.azure.ad.demoad.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

  @GetMapping("group1")
  @ResponseBody
  public String group1() {
    return "group1 message";
  }
}
