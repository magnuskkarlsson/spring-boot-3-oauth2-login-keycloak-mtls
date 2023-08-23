package se.mkk.springboot3oauth2loginkeycloak;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.util.JSONObjectUtils;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class OAuth2LoginSecurityConfig {
    @Value("${javax.net.ssl.keyStore}")
    private String keyStore;
    @Value("${javax.net.ssl.keyStorePassword}")
    private String keyStorePassword;
    @Value("${javax.net.ssl.keyStoreType:PKCS12}")
    private String keyStoreType;
    @Value("${javax.net.ssl.trustStore}")
    private String trustStore;
    @Value("${javax.net.ssl.trustStorePassword}")
    private String trustStorePassword;
    @Value("${javax.net.ssl.trustStoreType:jks}")
    private String trustStoreType;

    // https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-provide-securityfilterchain-bean
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http //
                .authorizeHttpRequests(authorize -> authorize //
                        .anyRequest().authenticated()) //
                .oauth2Login(oauth2 -> oauth2 //
                        .userInfoEndpoint(userInfo -> userInfo //
                                .oidcUserService(this.oidcUserService())))
                .oauth2Client(oauth2Client -> oauth2Client //
                        .authorizationCodeGrant(authorizationCodeGrant -> authorizationCodeGrant //
                                .accessTokenResponseClient(this.accessTokenResponseClient())));
        return http.build();
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();

        // org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient
        RestTemplate restTemplate = new RestTemplate(
                Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        try {
            // https://github.com/apache/httpcomponents-client/blob/5.2.x/httpclient5/src/test/java/org/apache/hc/client5/http/examples/ClientCustomSSL.java
            SSLContext sslContext = new SSLContextBuilder() //
                    .loadKeyMaterial(Path.of(keyStore), keyStorePassword.toCharArray(), keyStorePassword.toCharArray()) //
                    .loadTrustMaterial(Path.of(trustStore), trustStorePassword.toCharArray()) //
                    .build();

            final SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create() //
                    .setSslContext(sslContext) //
                    .build();

            final HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create() //
                    .setSSLSocketFactory(sslSocketFactory) //
                    .build();

            CloseableHttpClient httpClient = HttpClients.custom() //
                    .setConnectionManager(cm) //
                    .build();

            // "uses https://hc.apache.org/httpcomponents-client-ga Apache HttpComponents HttpClient to create requests"
            ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            restTemplate.setRequestFactory(requestFactory);
        } catch (Exception e) {
            e.printStackTrace();
        }
        accessTokenResponseClient.setRestOperations(restTemplate);
        return accessTokenResponseClient;
    }

    // https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-map-authorities-oauth2userservice
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);

            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Collection<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // 1) Fetch the authority information from the protected resource using accessToken
            // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
            try {
                String[] chunks = accessToken.getTokenValue().split("\\.");
                Base64.Decoder decoder = Base64.getUrlDecoder();
                String header = new String(decoder.decode(chunks[0]));
                String payload = new String(decoder.decode(chunks[1]));

                Map<String, Object> claims = JSONObjectUtils.parse(payload);
                mappedAuthorities = new KeycloakAuthoritiesConverter().convert(claims);
            } catch (Exception e) {
                e.printStackTrace();
            }

            // 3) Create a copy of oidcUser but use the mappedAuthorities instead
            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(),
                    "preferred_username");

            return oidcUser;
        };
    }

    // Spring OAuth2 uses default Scopes Not Roles for Authorization
    // org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
    private class KeycloakAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            return convert(jwt.getClaims());
        }

        public Collection<GrantedAuthority> convert(Map<String, Object> claims) {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            for (String authority : getAuthorities(claims)) {
                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + authority));
            }
            return grantedAuthorities;
        }

        private Collection<String> getAuthorities(Map<String, Object> claims) {
            Object realm_access = claims.get("realm_access");
            if (realm_access instanceof Map) {
                Map<String, Object> map = castAuthoritiesToMap(realm_access);
                Object roles = map.get("roles");
                if (roles instanceof Collection) {
                    return castAuthoritiesToCollection(roles);
                }
            }
            return Collections.emptyList();
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> castAuthoritiesToMap(Object authorities) {
            return (Map<String, Object>) authorities;
        }

        @SuppressWarnings("unchecked")
        private Collection<String> castAuthoritiesToCollection(Object authorities) {
            return (Collection<String>) authorities;
        }
    }
}
