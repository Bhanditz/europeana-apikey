package eu.europeana.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.*;

/**
 * OAuth2 authorization server.
 *
 * To issue a token run the following command:
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=client_credentials -d scope=read
 *  or
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=password -d username=user -d password=test
 *
 * Running this later will also show you the existing token for that client or user again.
 *
 * After you obtained a token you can refresh it using
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=refresh_token -d refresh_token=[insert_refresh_token]
 *
 * Created by Patrick Ehlert on 5-4-17.
 */
@SpringBootApplication
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class AuthorizationServer extends WebSecurityConfigurerAdapter {

    /**
     * Application main entry point, points to authorizationServer.yml config file
     * @param args
     */
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthorizationServer.class).properties("spring.config.name=authorizationServer").run(args);
    }




    @Configuration
    @EnableAuthorizationServer
    protected class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        AuthenticationManager authenticationManager;

        @Value("${security.oauth2.privateKey}")
        private String privateKey;
        @Value("${security.oauth2.publicKey}")
        private String publicKey;
        @Value("${security.oauth2.client.clientId}")
        private String clientId;
        @Value("${security.oauth2.client.clientSecret}")
        private String clientSecret;


        /**
         * A JSON Web Tokens (JWT) contains all user information encrypted in the token.
         * @return a new default JWT access token converter
         */
        @Bean
        public JwtAccessTokenConverter accessTokenConverter() {
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey(privateKey);
            converter.setVerifierKey(publicKey);
            return converter;
        }

        @Bean
        public TokenStore tokenStore() {
            return new JwtTokenStore(accessTokenConverter());
        }

        @Bean
        @Primary
        public DefaultTokenServices tokenServices() {
            DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenStore(tokenStore());
            defaultTokenServices.setSupportRefreshToken(true);
            return defaultTokenServices;
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            super.configure(oauthServer);
            oauthServer
                    //.sslOnly()
                    .allowFormAuthenticationForClients()
                    .tokenKeyAccess("permitAll()");


        }

//        @Bean
//        public TokenEnhancerChain tokenEnhancerChain(){
//            final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
//            List list = new ArrayList();
//            list.add(new MyTokenEnhancer());
//            list.add(accessTokenConverter());
//           // list.add(MyTokenEnhancer(), tokenEnhancer())
//            tokenEnhancerChain.setTokenEnhancers(list);
//            return tokenEnhancerChain;
//        }

        public  class MyTokenEnhancer implements TokenEnhancer {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
             //   final User user = (User) authentication.getPrincipal();
                final Map<String, Object> additionalInfo = new HashMap<>();
                additionalInfo.put("claimfromme", "erik");
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
                return accessToken;
            }
        }

        /**
         * Defines the security constraints on the token endpoints /oauth/token_key and /oauth/check_token and enables
         * the JWT tokens
         * @param endpoints
         * @throws Exception
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(
                    Arrays.asList(tokenEnhancer(), accessTokenConverter()));


            endpoints.tokenStore(tokenStore())
                    .tokenEnhancer(tokenEnhancerChain)
                    .authenticationManager(authenticationManager);
        }

        @Bean
        public TokenEnhancer tokenEnhancer() {
            return new MyTokenEnhancer();
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient(clientId)
                    .secret(clientSecret)
                    .authorizedGrantTypes("authorization_code","client_credentials", "password", "refresh_token")
                    .authorities("ROLE_TRUSTED_CLIENT")
                    .scopes("read", "write")
                    .accessTokenValiditySeconds(10000)
                    .refreshTokenValiditySeconds(10000)
                    .autoApprove(true)
                    .and()
                    .withClient("unit_test")
                    .secret("test")
                    .authorizedGrantTypes("authorization_code", "refresh_token")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "write");
        }

  }



    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        /**
         * Make sure only authorized requests can access the user details
         * @param http
         * @throws Exception
         */
        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http.authorizeRequests()
                    .antMatchers("/me").authenticated();
            // @formatter:on
        }

    }


}



