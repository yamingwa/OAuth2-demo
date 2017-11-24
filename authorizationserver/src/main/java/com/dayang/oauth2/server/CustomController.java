package com.dayang.oauth2.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2017/11/23.
 */

@RestController
public class CustomController {
    @Autowired
    private DefaultTokenServices defaultTokenServices;

    @Autowired
    private DefaultAccessTokenConverter defaultAccessTokenConverter;

    @Autowired
    private TenantManagementService tenantManagementService;

    @RequestMapping("/hello")
    public String home() {
        return "Hello World!";
    }
    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

    @RequestMapping("/oauth/check_token")
    @ResponseBody
    public Map<String, ?> checkToken(HttpServletRequest request) {

        String token = request.getParameter("token");
        String tenantID = request.getParameter("tenantID");
        String serviceID = request.getParameter("serviceID");

        Map<String, Object> errorResponse = new Hashtable<String, Object>();
        try {
            String sourceServiceID = defaultTokenServices.getClientId(token);
            OAuth2AccessToken accessToken = defaultTokenServices.readAccessToken(token);
            OAuth2Authentication authentication = defaultTokenServices.loadAuthentication(token);
            Map<String, Object> response = (Map<String, Object>) defaultAccessTokenConverter.convertAccessToken(accessToken, authentication);
            if (tenantID != null && serviceID != null) {
                Set<String> serviceSet = tenantManagementService.getTenantServiceMap().get(tenantID);
                if (serviceSet.contains(serviceID) && serviceSet.contains(sourceServiceID)) {
                    response.put("active", true);
                } else {
                    response.put("active", false);
                    response.put("error", "Tenant does NOT purchase " + serviceID + " or " + sourceServiceID);
                }
            }
            return response;
        } catch(AuthenticationException expiredException) {
            errorResponse.put("active", false);
            errorResponse.put("error", "Token is expired, token: " + token);
            return errorResponse;
        } catch(InvalidTokenException invalid) {
            errorResponse.put("active", false);
            errorResponse.put("error", "Invalid Token Value: " + token);
            return errorResponse;
        }
    }
}
