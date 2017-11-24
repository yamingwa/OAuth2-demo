package com.dayang.oauth2.server;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.SessionAttributes;

/**
 * Created by Administrator on 2017/11/17.
 */
@SpringBootApplication
@SessionAttributes("authorizationRequest")
@Controller
@EnableResourceServer
public class AuthorizationServer {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServer.class, args);
    }


    @Configuration
    @Order(-20)
    protected static class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication().withUser("user1").password("psd1").roles("USER");
        }


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .formLogin().permitAll()
                    .and()
                    .requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
                    .and()
                    .authorizeRequests().anyRequest().authenticated();
            // @formatter:on
        }


    }



    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

        @Bean
        public DefaultTokenServices defaultTokenServices() {
            DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenStore(tokenStore());
            return defaultTokenServices;
        }

        @Bean
        public DefaultAccessTokenConverter defaultAccessTokenConverter() {
            DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
            return defaultAccessTokenConverter;
        }

        @Bean
        public TokenStore tokenStore() {
            return new InMemoryTokenStore();
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients)  throws  Exception {
            clients.inMemory()
                    .withClient("serviceID1")
                    .secret("psd1")
                    .authorizedGrantTypes("authorization_code", "refresh_token", "client_credentials")
                    .authorities("ROLE_TRUSTED_CLIENT")
                    .and()
                    .withClient("serviceID3")
                    .secret("psd3")
                    .authorizedGrantTypes("authorization_code", "refresh_token", "client_credentials")
                    .authorities("ROLE_TRUSTED_CLIENT");
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenServices(defaultTokenServices()).accessTokenConverter(defaultAccessTokenConverter())
                    .requestValidator(new CustomRequestValidator());
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess(
                    "permitAll()");
        }

    }
}
