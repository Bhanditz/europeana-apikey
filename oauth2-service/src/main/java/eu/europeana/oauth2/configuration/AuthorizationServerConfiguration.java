package eu.europeana.oauth2.configuration;

import eu.europeana.oauth2.AuthorizationServer;
import eu.europeana.oauth2.utils.MyTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

/**
 * Created by erikkonijnenburg on 26/05/2017.
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private AuthorizationServer authorizationServer;

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

    public AuthorizationServerConfiguration(AuthorizationServer authorizationServer) {
        this.authorizationServer = authorizationServer;
    }


    /**
     * A JSON Web Tokens (JWT) contains all user information encrypted in the token.
     *
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
       // super.configure(oauthServer);
        oauthServer
                //.sslOnly()
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients()
                .tokenKeyAccess("permitAll()");  //maybe to open??
    }

    /**
     * Defines the security constraints on the token endpoints /oauth/token_key and /oauth/check_token and enables
     * the JWT tokens
     *
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
                .authorizedGrantTypes("authorization_code", "client_credentials", "password", "refresh_token")
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
