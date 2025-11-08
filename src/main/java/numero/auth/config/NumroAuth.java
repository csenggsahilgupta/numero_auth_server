package numero.auth.config;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@CrossOrigin
public class NumroAuth {

	@Bean
	@Order(1)
	SecurityFilterChain	 AuthServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()).registeredClientRepository(registeredClientRepository());
		return http.sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).csrf(csrf->csrf.disable()).build();


	}
//	@Bean
//	 CorsConfigurationSource corsCoongigration() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//
//		CorsConfiguration config = new CorsConfiguration();
//        config.setAllowCredentials(true); // Allow sending cookies and authentication headers
//        config.setAllowedOrigins(List.of("localhost:4201")); // Specify allowed origins
//        config.setAllowedHeaders(List.of("*")); // Allow all headers
//        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Allow specified HTTP methods
//        source.registerCorsConfiguration("/oauth/token", config); // A	// TODO Auto-generated method stub
//		return source;
//	}

	@Order(2)
	@Bean
	SecurityFilterChain	 DefaultSecurityFilterChain(HttpSecurity http) throws Exception {
http.authorizeHttpRequests(a->a.anyRequest().authenticated()).formLogin(Customizer.withDefaults()).csrf(c->c.disable()) ;
return http.build();
		
		
		
		

	}


    @Bean
    UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withUsername("user")
				.password("password")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // This is for demonstration purposes only and should not be used in production.
        // It provides no password encoding and is highly insecure.
        return NoOpPasswordEncoder.getInstance();
    }
    

    @Bean
    RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("numero-client")
				.clientSecret("numer-rpaks")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:8080")
//				.postLogoutRedirectUri("http://127.0.0.1:8080/")
            	.scope("openid")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}	
	
	
	
	
	
//	
//	
	
	
	
	
	
}
