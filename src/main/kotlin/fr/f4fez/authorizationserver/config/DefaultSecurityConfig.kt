package fr.f4fez.authorizationserver.config

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import fr.f4fez.authorizationserver.authorization.CustomRefreshTokenGenerator
import fr.f4fez.authorizationserver.authorization.PublicClientRefreshTokenAuthenticationConverter
import fr.f4fez.authorizationserver.authorization.PublicClientRefreshTokenAuthenticationProvider
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.net.URI
import java.util.*
import java.util.function.Consumer
import java.util.function.Function
import java.util.stream.Collectors
import javax.sql.DataSource
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Configuration
@EnableConfigurationProperties(AuthorizationProperties::class)
@EnableWebSecurity
class DefaultSecurityConfig {

    val DEF_USERS_BY_USERNAME_QUERY: String = ("select username,password,enabled "
            + "from qsp_auth_users "
            + "where username = ?")

    val DEF_AUTHORITIES_BY_USERNAME_QUERY: String = ("select username,authority "
            + "from qsp_auth_authorities "
            + "where username = ?")

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository
    ): SecurityFilterChain {
        var authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        authorizationServerConfigurer.clientAuthentication {
            it
                .authenticationConverter(PublicClientRefreshTokenAuthenticationConverter())
                .authenticationProvider(PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository))
        }
        http
            .securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .with(
                authorizationServerConfigurer,
                { authorizationServer -> authorizationServer.oidc(Customizer.withDefaults()) })
            .authorizeHttpRequests({ authorize ->
                authorize
                    .anyRequest().authenticated()
            })
            .exceptionHandling({ exceptions ->
                exceptions
                    .defaultAuthenticationEntryPointFor(
                        LoginUrlAuthenticationEntryPoint("/login"),
                        MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
            }
            )
            .cors(Customizer.withDefaults())
        return http.build()
    }


    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests { authorizeRequest ->
            authorizeRequest.anyRequest().authenticated()
        }
            .formLogin(Customizer.withDefaults())
            .cors(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun tokenGenerator(
        jwkSource: JWKSource<SecurityContext>,
        tokenCustomizer: OAuth2TokenCustomizer<JwtEncodingContext?>
    ): OAuth2TokenGenerator<*> {
        val jwtGenerator = JwtGenerator(NimbusJwtEncoder(jwkSource))
        jwtGenerator.setJwtCustomizer(tokenCustomizer)
        val refreshTokenGenerator: OAuth2TokenGenerator<OAuth2RefreshToken?> = CustomRefreshTokenGenerator()
        return DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator)
    }

    @Bean
    fun corsConfigurationSource(authorizationProperties: AuthorizationProperties): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val config = CorsConfiguration()
        config.addAllowedHeader("*")
        config.addAllowedMethod(HttpMethod.GET)
        config.addAllowedMethod(HttpMethod.POST)
        authorizationProperties.clients.values
            .flatMap(ClientProperties::redirectUri)
            .map(::originFromRedirectUri)
            .distinct()
            .forEach(config::addAllowedOrigin)
        config.allowCredentials = true
        source.registerCorsConfiguration("/**", config)
        return source
    }

    private fun originFromRedirectUri(redirectUri: String): String {
        val uri = URI.create(redirectUri)
        return URI(uri.scheme, null, uri.host, uri.port, null, null, null).toString()
    }

    @Bean
    fun users(datasource: DataSource): UserDetailsService {
        val service = JdbcDaoImpl()
        service.usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY
        service.setAuthoritiesByUsernameQuery(DEF_AUTHORITIES_BY_USERNAME_QUERY)
        service.setDataSource(datasource)
        return service
    }

    @Bean
    fun registeredClientRepository(authorizationProperties: AuthorizationProperties): RegisteredClientRepository {
        require(authorizationProperties.clients.isNotEmpty()) {
            "At least one client must be configured under qsp.authorization.clients"
        }

        val registeredClients = authorizationProperties.clients.map { (clientName, clientProperties) ->
            require(clientProperties.redirectUri.isNotEmpty()) {
                "Client '$clientName' must configure at least one redirect URI"
            }

            val tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(clientProperties.accessTokenTimeToLive.minutes.toJavaDuration())
                .refreshTokenTimeToLive(clientProperties.refreshTokenTimeToLive.minutes.toJavaDuration())
                .reuseRefreshTokens(false)
                .build()

            val clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientName)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(
                    ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build()
                )
                .tokenSettings(tokenSettings)

            clientProperties.redirectUri.forEach(clientBuilder::redirectUri)
            clientBuilder.build()
        }

        return InMemoryRegisteredClientRepository(registeredClients)
    }

    @Bean
    fun jwtTokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context: JwtEncodingContext? ->
            if (OAuth2TokenType.ACCESS_TOKEN == context!!.tokenType) {
                context.claims.claims(Consumer { claims: MutableMap<String?, Any?>? ->
                    val roles =
                        AuthorityUtils.authorityListToSet(context.getPrincipal<Authentication>().authorities)
                            .stream()
                            .map { c: String? -> c!!.replaceFirst("^ROLE_".toRegex(), "") }
                            .collect(
                                Collectors.collectingAndThen(
                                    Collectors.toSet(),
                                    Function { s: MutableSet<String?>? -> Collections.unmodifiableSet(s) })
                            )
                    claims!!["roles"] = roles
                })
            }
        }
    }
}
