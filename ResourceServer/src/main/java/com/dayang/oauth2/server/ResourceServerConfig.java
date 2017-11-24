package com.dayang.oauth2.server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * Created by Administrator on 2017/11/24.
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Bean
    @Primary
    public CustomTokenService customTokenService() {
        CustomTokenService customTokenService = new CustomTokenService();
        customTokenService.setCheckTokenEndpointUrl("http://localhost:9090/AuthServer/oauth/check_token?tenantID=tenant1&serviceID=serviceID3");
        customTokenService.setClientId("serviceID3");
        customTokenService.setClientSecret("psd3");
        return customTokenService;
    }

    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }
    @Override
    public void configure(ResourceServerSecurityConfigurer config) throws Exception {
        config.tokenServices(customTokenService()).tokenStore(tokenStore());
    }


}
