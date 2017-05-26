package eu.europeana.oauth.test.client.components;

import org.springframework.boot.autoconfigure.security.oauth2.resource.JwtAccessTokenConverterConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import java.util.Map;

public class MyJwtAccessTokenConverter extends JwtAccessTokenConverter implements
        JwtAccessTokenConverterConfigurer {

    @Override
    public void configure(JwtAccessTokenConverter converter) {
        converter.setAccessTokenConverter(this);
    }

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        OAuth2Authentication auth = super.extractAuthentication(map);
      //  MyAppCustomUserDetails details = new MyAppCustomUserDetails();
        //populate details from the provided map, which contains the whole JWT.
        auth.setDetails("iets");
        return auth;
    }
}
