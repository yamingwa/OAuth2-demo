package com.dayang.oauth2.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Hashtable;
import java.util.Map;

/**
 * Created by Administrator on 2017/11/24.
 */
@RestController
public class CustomController {
    @Autowired
    private OAuth2ClientContext oauth2Context;

    @RequestMapping("/hello")
    public String home() {
        return "This is Service B!";
    }
    @RequestMapping("/resource")
    public Map<String, String> resourceInfo(String id) {
        System.out.println("Your Access Token:" + oauth2Context.getAccessToken().getValue());
        Map<String, String> response = new Hashtable<String, String>();
        response.put("resourceID", id);
        response.put("content", "hello world!");
        return response;
    }
}
