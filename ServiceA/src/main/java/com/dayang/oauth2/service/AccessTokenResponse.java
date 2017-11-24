package com.dayang.oauth2.service;

import java.util.Map;

/**
 * Created by Administrator on 2017/11/22.
 */
public class AccessTokenResponse {
    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private int expiresIn;
    private String scope;
    private Map<String, Object> additionalInfo;

    public String getAccessToken() {
        return accessToken;
    }
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public String getRefreshToken() {
        return refreshToken;
    }
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    public int getExpiresIn() {
        return expiresIn;
    }
    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }
    public String getScope() {
        return scope;
    }
    public void setScope(String scope) {
        this.scope = scope;
    }

    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }
    public void setAdditionalInfo(Map<String, Object> additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    @Override
    public String toString() {
        return "AuthTokenInfo [access_token=" + accessToken + ", token_type=" + tokenType + ", refresh_token="
                + refreshToken + ", expires_in=" + expiresIn + ", scope=" + scope +  "]";
    }
}
