package com.dayang.oauth2.server;

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2017/11/21.
 */
public class CustomRequestValidator implements OAuth2RequestValidator {

    /*
    private static  Map<String, Set<String>> tenantServiceMap = new Hashtable<String, Set<String>>();

    public CustomRequestValidator() {
        tenantServiceMap.put("tenant1", serviceSet("serviceID1", "serviceID3"));
    }

    private Set<String> serviceSet(String... services) {
        Set<String> serviceSet = new HashSet<String>();
        for (String service : services) {
            serviceSet.add(service);
        }
        return serviceSet;
    }
    */
    @Override
    public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) {
        return ;
    }
    @Override
    public void validateScope(TokenRequest tokenRequest, ClientDetails client) {
        Set<String> scopes = tokenRequest.getScope();
        if (scopes.size() == 0) {
            return;
        }
    }


}
