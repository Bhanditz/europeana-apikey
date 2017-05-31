package testme.fennek.demo.controllers;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


@Controller
public class SecurityController {

    @RequestMapping(value = "/username", method = RequestMethod.GET)
    public String currentUserNameSimple(HttpServletRequest request, Model model) {
        Principal principal = request.getUserPrincipal();
        OAuth2Authentication d = (OAuth2Authentication)principal;
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) ((OAuth2Authentication) principal).getDetails();
        model.addAttribute("name", principal.getName());
        model.addAttribute("bearer", (details.getTokenValue()));
        return "greeting";
    }
}