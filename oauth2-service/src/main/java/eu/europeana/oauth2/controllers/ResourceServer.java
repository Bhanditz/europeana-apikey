package eu.europeana.oauth2.controllers;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The resource server provides access to the user information
 * Created by patrick on 20-4-17.
 */
@Configuration
@EnableWebSecurity
@RestController
public class ResourceServer {

    /**
     * Handle requests for (current) user information. This url should only be available for authenticated users!
     *
     * @param principal
     * @return
     */
    @RequestMapping({"/user", "/me"})
    public Map<String, String> user(Principal principal) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("name", principal.getName());
        return map;
    }
}
