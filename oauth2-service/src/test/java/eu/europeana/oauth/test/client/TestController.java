package eu.europeana.oauth.test.client;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Created by erikkonijnenburg on 24/05/2017.
 */
@RestController
public class TestController {

    /**
     * @param user
     * @return user name of the logged-in user
     */
    @RequestMapping("/")
    @PreAuthorize("#oauth2.hasScope('read')")
    //@PreAuthorize("hasRole('USER')")
    public String userName(Principal user) {
        return "Logged in as: " +user.getName();
    }

}
