package eu.europeana.oauth2.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by erikkonijnenburg on 29/05/2017.
 */
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/", "/home").permitAll()
//                .anyRequest().authenticated()
//                    .and()
//                .formLogin()
//               // .loginPage()
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll();
//    }
}
