/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey;

import eu.europeana.apikey.domain.Apikey;
import eu.europeana.apikey.repos.ApikeyRepo;
import eu.europeana.apikey.util.SocksProxyHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.io.IOException;

@PropertySource(value = "classpath:build.properties", ignoreResourceNotFound = true)
@SpringBootApplication
@ComponentScan("eu.europeana.apikey")
public class Application extends SpringBootServletInitializer {
    /**
     * This method is called when starting as a Spring-Boot application ('run' this class from your IDE)
     * @param args
     */
    @SuppressWarnings("squid:S2095") // to avoid sonarqube false positive (see https://stackoverflow.com/a/37073154/741249)
    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(Application.class).run(args);
    }

    /**
     * This method is called when starting a 'traditional' war deployment (e.g. in Docker of Cloud Foundry)
     * @param servletContext
     * @throws ServletException
     */
    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        try {
            SocksProxyHelper.injectSocksProxySettings();
            super.onStartup(servletContext);
        } catch (IOException e) {
            throw new ServletException("Error reading properties", e);
        }
    }

    @Component
    public static class SampleDataPopulator implements CommandLineRunner {

        @Autowired
        private ApikeyRepo apikeyRepo;

        @Override
        public void run(String... args) throws Exception {
        }
    }
}
@Configuration
class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

    @Autowired
    ApikeyRepo apikeyRepo;

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Bean
    UserDetailsService userDetailsService() {
        return new UserDetailsService() {

            @Override
            public UserDetails loadUserByUsername(String id)  {
                Apikey apikey = apikeyRepo.findOne(id);
                // && apikey.getLevel().equalsIgnoreCase("ADMIN")
                if(apikey != null) {
                    return new User(apikey.getApikey(), apikey.getPrivatekey(),
                            true, true, true, true,
                            AuthorityUtils.createAuthorityList(
                                    apikey.getLevel().equalsIgnoreCase("ADMIN") ? "ROLE_ADMIN" : "USER"));
                } else    {
                    throw new UsernameNotFoundException("could not find apikey '"  + id + "'");
                }
            }
        };
    }
}

@EnableWebSecurity
@Configuration
class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        webSecurity
                .ignoring()
                .antMatchers(HttpMethod.GET, "/apikey/**")
                .antMatchers(HttpMethod.GET, "/info");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    .authorizeRequests().anyRequest().access("hasRole('ROLE_ADMIN')")
                .and().httpBasic()
                .and().csrf().disable();
    }

}

@Component
@ConfigurationProperties("europeanamail")
class EuropeanaMailProperties {
    private String sentFrom;

    public String getSentFrom() {
        return sentFrom;
    }
    public void setSentFrom(String sentFrom) {
        this.sentFrom = sentFrom;
    }
}

@Configuration
@EnableWebMvc
class MailConfig extends WebMvcConfigurerAdapter {
    @Autowired
    private EuropeanaMailProperties europeanaMailProperties;
    @Bean
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." +
                "%n%n" +
                "These are your Europeana API keys: %n===========================%n" +
                "API key: \t\t%s %nPrivate key: \t%s %n===========================%n" +
                "%n%n" +
                "The private key is used for specific API methods that require additional user authentication while " +
                "the public key must be used by all others, see https://pro.europeana.eu/resources/apis/intro#access." +
                "%n%n" +
                "Please keep a safe record of these keys and do not share them with third parties or expose it in user " +
                "interfaces or in markup, as the " +
                "API keys are confidential and are for use by the client or user only." +
                "%n%n" +
                "Our technical documentation for all APIs is available at https://pro.europeana.eu/resources/apis which " +
                "includes an API console for testing and community developed libraries for a variety of programming languages." +
                "%n%n" +
                "Please join us in the Europeana API Forum (https://groups.google.com/forum/?pli=1#!forum/europeanaapi) " +
                "- to ask questions to us and other developers and to give us your feedback on our API. " +
                "You can also contact us directly by mailing api@europeana.eu " +
                "and we would be especially grateful if you would let us know about your implementation so that we can " +
                "feature it in our application gallery on Europeana Pro - https://pro.europeana.eu/resources/apps." +
                "%n%n" +
                "Best regards," +
                "%n" +
                "The Europeana API Team");
        message.setFrom(europeanaMailProperties.getSentFrom());
        return message;
    }
}
