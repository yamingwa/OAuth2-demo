package com.dayang.oauth2.authorizationserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

/**
 * Created by Administrator on 2017/11/17.
 */
@SpringBootApplication
@Controller
@SessionAttributes("authorizationRequest")
@EnableAuthorizationServer
public class AuthorizationServer {

    @RequestMapping("/oauth/error")
    public String errorHandler() {
        return "Authentication Failed!";
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServer.class, args);
    }

    @Configuration
    @EnableWebSecurity
    @Order(-20)
    protected static class SecurityConfig extends WebSecurityConfigurerAdapter {

        //Register users

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser("serviceID1").password("psd1").roles("USER")
                    .and()
                    .withUser("user2").password("psd2").roles("USER")
                    .and()
                    .withUser("user3").password("psd3").roles("USER")
                    .and()
                    .withUser("admin").password("admin").roles("ADMIN");
        }


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            /**
            // @formatter:off
            http
                    .formLogin().loginPage("/login.html").permitAll()
                    .and()
                    .requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
                    .and()
                    .authorizeRequests().anyRequest().authenticated();
            // @formatter:on
            **/
            http.csrf().disable()
                    .anonymous().disable()
                    .antMatcher("/oauth/token")
                    .authorizeRequests().anyRequest().authenticated();
            CustomClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter = new CustomClientCredentialsTokenEndpointFilter();
            clientCredentialsTokenEndpointFilter.setAuthenticationManager(authenticationManagerBean());
            clientCredentialsTokenEndpointFilter.afterPropertiesSet();
            http.csrf().disable();
            http.addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class);
        }

        @Override
        @Bean
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
        protected static final int ACCESS_TOKEN_VALIDITY_SECONDS = 120;
        protected static final int REFRESH_TOKEN_VALIDITY_SECONDS = 600;

        @Autowired
        private UserApprovalHandler userApprovalHandler;

        @Autowired
        @Qualifier("authenticationManagerBean")
        private AuthenticationManager authenticationManager;

        @Autowired
        private TokenStore tokenStore;

        @Bean
        public TokenStore tokenStore() {
            return new InMemoryTokenStore();
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                        .withClient("serviceID1")
                        .secret("psd1")
                        .authorizedGrantTypes("authorization_code", "refresh_token","client_credentials")
                        .scopes("")
                        .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                        .refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS)
                        .redirectUris("test") //TODO: Add redirect URI for service A
                    .and()
                        .withClient("serviceID2")
                        .secret("psd2")
                        .authorizedGrantTypes("authorization_code", "refresh_token","client_credentials")
                        .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                        .refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS)
                        .redirectUris("TO BE ADDED") //TODO: Add redirect URI for service A
                    .and()
                        .withClient("serviceID3")
                        .secret("psd3")
                        .authorizedGrantTypes("authorization_code", "refresh_token","client_credentials")
                        .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                        .refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS)
                        .redirectUris("TO BE ADDED"); //TODO: Add redirect URI for service A

        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore)
                     .userApprovalHandler(userApprovalHandler)
                     .authenticationManager(authenticationManager);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer.tokenKeyAccess("permitAll()")
                       .checkTokenAccess("isAuthenticated()");


        }

    }

    @Configuration
    protected static class OtherConfig {
        @Autowired
        private ClientDetailsService clientDetailsService;

        @Autowired
        private TokenStore tokenStore;

        @Bean
        public ApprovalStore approvalStore() throws Exception {
            TokenApprovalStore store = new TokenApprovalStore();
            store.setTokenStore(tokenStore);
            return store;
        }

        @Bean
        @Lazy
        @Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
        public MyUserApprovalHandler userApprovalHandler() throws Exception {
            MyUserApprovalHandler handler = new MyUserApprovalHandler();
            handler.setApprovalStore(approvalStore());
            handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
            handler.setClientDetailsService(clientDetailsService);
            handler.setUseApprovalStore(true);
            return handler;
        }
    }

}
