package com.dayang.oauth2.service;


import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by Administrator on 2017/11/22.
 */
@RestController
public class CustomHandler {
    public static final String AUTH_SERVER_TOKEN_URI = "http://localhost:9090/AuthServer/oauth/token";
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "?grant_type=client_credentials";
    @RequestMapping("/hello")
    public String home() {
        return "This is Service A! Your Access Token: " + oauth2Context.getAccessToken().getValue();
    }

    @Autowired
    private OAuth2ClientContext oauth2Context;

    @RequestMapping("/callService")
    public Map<String, ?> callService() {
        //This will return authorization_code token, need to be checked. if this exists, no need to apply client token
        //TODO: check if user token exists, also need a map to store user:token
        System.out.println(oauth2Context.getAccessToken().getValue());

        String token = retriveAccessTokenValue();
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Bearer " + oauth2Context.getAccessToken().getValue());
        HttpEntity<String> request = new HttpEntity<String>(headers);

        ResponseEntity<Object> response = restTemplate.
                exchange("http://localhost:9093/service3/resource?id=test2", HttpMethod.POST, request, Object.class);
        return (LinkedHashMap<String, Object>)response.getBody();
    }

    private String retriveAccessTokenValue() {
        //Create Basic Auth Header with client credientials
        String plainClientCredentials="serviceID1:psd1";
        String base64ClientCredentials = new String(Base64.encodeBase64(plainClientCredentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Basic " + base64ClientCredentials);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> request = new HttpEntity<String>(headers);

        ResponseEntity<Object> response = restTemplate.exchange(AUTH_SERVER_TOKEN_URI + CLIENT_CREDENTIALS_GRANT_TYPE, HttpMethod.POST, request, Object.class);
        LinkedHashMap<String, Object> map = (LinkedHashMap<String, Object>)response.getBody();
        AccessTokenResponse tokenInfo = null;

        if(map!=null){
            tokenInfo = new AccessTokenResponse();
            tokenInfo.setAccessToken((String)map.get("access_token"));
            tokenInfo.setTokenType((String)map.get("token_type"));
            //Client_Credentials does NOT have a refresh_token
            //tokenInfo.setRefreshToken((String)map.get("refresh_token"));
            tokenInfo.setExpiresIn((Integer)map.get("expires_in"));
            tokenInfo.setScope((String)map.get("scope"));
            System.out.println(tokenInfo);
        }
        return tokenInfo.getAccessToken();
    }

}
