package eu.europeana.oauth.test.client;

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
    public String userName(Principal user) {
        return "Logged in as: " +user.getName();
    }

}
