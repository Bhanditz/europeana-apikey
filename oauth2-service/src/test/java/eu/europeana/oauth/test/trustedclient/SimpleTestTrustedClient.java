package eu.europeana.oauth.test.trustedclient;

import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;

import static java.lang.String.format;
import static java.util.Arrays.asList;

public class SimpleTestTrustedClient {

    public static void main(String args[]) throws InterruptedException {
        RestTemplate restTemplate = new OAuth2RestTemplate(
                withOAuth2Authentication("http://localhost:8888/oauth/token", "simpleTestClient", "simpleSecret"),
                new DefaultOAuth2ClientContext()
        );

        while(true) {
            String quote = restTemplate.getForObject("http://localhost:8082/", String.class);
            System.out.println(quote);
            Thread.sleep(1000);
        }
    }

    private static OAuth2ProtectedResourceDetails withOAuth2Authentication(final String url, final String clientId, final String secret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

        resource.setAccessTokenUri(url);
        resource.setClientId(clientId);
        resource.setClientSecret(secret);
   //     resource.setAuthenticationScheme(AuthenticationScheme.header);
//        resource.setGrantType("client_credentials");
//        resource.setScope(asList("read","write"));
        // here you can provide additional properties such as scope etc.

        return resource;
    }


}
