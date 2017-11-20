package com.dayang.oauth2.authorizationserver;

import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * Created by Administrator on 2017/11/20.
 */
public class CustomClientCredentialsTokenEndpointFilter extends ClientCredentialsTokenEndpointFilter {
    private static final Map<String, Set<String>> tenantServiceMap = new Hashtable<String, Set<String>>();

    public CustomClientCredentialsTokenEndpointFilter() {
        tenantServiceMap.put("tenant1", serviceSet("serviceID1", "serviceID3"));
        tenantServiceMap.put("tenant2", serviceSet("serviceID2", "serviceID3"));
    }

    private Set<String> serviceSet(String... services) {
        Set<String> serviceSet = new HashSet<String>();
        for (String service : services) {
            serviceSet.add(service);
        }
        return serviceSet;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication = super.attemptAuthentication(request, response);
        System.out.println("Default result: " + authentication.isAuthenticated());
        if (!authentication.isAuthenticated()) {
            String scopeList = request.getParameter("scope");
            String scopes[] = scopeList.split(",");
            String tenant = scopes[0];
            if (scopes.length > 1) {
                for (int i = 1; i < scopes.length; i++) {
                    System.out.println(scopes[i]);
                    if (!tenantServiceMap.get(tenant).contains(scopes[i])) {
                        authentication.setAuthenticated(false);
                        String msg = tenant + " does NOT purchase service: " + scopes[i];
                        System.out.println(msg);
                        response.setHeader("NOT_PURCHASED", msg);
                        return authentication;
                    }
                }
            }
        }
        return authentication;
    }
}
