package fr.f4fez.authorizationserver.config

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import fr.f4fez.authorizationserver.authentication.LoginAttemptLimiter
import fr.f4fez.authorizationserver.authentication.PasswordExpirationAwareJdbcDao
import fr.f4fez.authorizationserver.authentication.ThrottledDaoAuthenticationProvider
import fr.f4fez.authorizationserver.authorization.CurrentUserTokenCustomizer
import fr.f4fez.authorizationserver.authorization.CustomRefreshTokenGenerator
import fr.f4fez.authorizationserver.authorization.PublicClientRefreshTokenAuthenticationConverter
import fr.f4fez.authorizationserver.authorization.PublicClientRefreshTokenAuthenticationProvider
import fr.f4fez.authorizationserver.password.ExpiredPasswordAuthenticationFailureHandler
import fr.f4fez.authorizationserver.user.UserService
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtClaimValidator
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.net.URI
import java.time.Clock
import java.util.UUID
import javax.sql.DataSource
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

@Configuration
@EnableConfigurationProperties(
    AuthorizationProperties::class,
    PasswordPolicyProperties::class,
    LoginThrottlingProperties::class,
)
@EnableWebSecurity
@EnableMethodSecurity
class DefaultSecurityConfig {
    companion object {
        private const val DEF_USERS_BY_USERNAME_QUERY =
            "select username,password,enabled,password_expiration from qsp_auth_users where username = ?"

        private const val DEF_AUTHORITIES_BY_USERNAME_QUERY =
            "select u.username,a.authority from qsp_auth_user_authorities a " +
                "join qsp_auth_users u on u.id = a.user_id where u.username = ?"
    }

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
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
                { authorizationServer ->
                    authorizationServer
                        .oidc(Customizer.withDefaults())
                        .authorizationEndpoint { it.consentPage("/oauth2/consent") }
                },
            ).authorizeHttpRequests({ authorize ->
                authorize
                    .anyRequest()
                    .authenticated()
            })
            .exceptionHandling(
                { exceptions ->
                    exceptions
                        .defaultAuthenticationEntryPointFor(
                            LoginUrlAuthenticationEntryPoint("/login"),
                            MediaTypeRequestMatcher(MediaType.TEXT_HTML),
                        )
                },
            ).cors(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(
        http: HttpSecurity,
        jwkSource: JWKSource<SecurityContext>,
        authorizationProperties: AuthorizationProperties,
    ): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorizeRequest ->
                authorizeRequest
                    .requestMatchers(
                        "/v3/api-docs/**",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/password-expired",
                        "/css/**",
                        "/login",
                        "/error",
                    ).permitAll()
                    .requestMatchers("/users/@me", "/users/@me/password")
                    .authenticated()
                    .requestMatchers(HttpMethod.GET, "/users/search")
                    .hasAnyRole("ADMIN", "USER")
                    .requestMatchers(HttpMethod.GET, "/logout")
                    .authenticated()
                    .requestMatchers("/oauth2/consent")
                    .authenticated()
                    .anyRequest()
                    .hasRole("ADMIN")
            }.formLogin { formLogin ->
                formLogin
                    .loginPage("/login")
                    .failureHandler(ExpiredPasswordAuthenticationFailureHandler())
                    .permitAll()
            }.oauth2ResourceServer { resourceServer ->
                resourceServer.jwt {
                    it
                        .decoder(userApiJwtDecoder(jwkSource, authorizationProperties))
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                }
            }.cors(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder = accessTokenDecoder(jwkSource)

    /**
     * Decodes access tokens only: ID tokens are signed with the same key but carry no scope.
     */
    private fun accessTokenDecoder(
        jwkSource: JWKSource<SecurityContext>,
        vararg validators: OAuth2TokenValidator<Jwt>,
    ): JwtDecoder {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>()
        jwtProcessor.jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)
        val scopeValidator =
            JwtClaimValidator<Any>(OAuth2TokenIntrospectionClaimNames.SCOPE) { scope ->
                (scope is Collection<*> && scope.isNotEmpty()) || (scope is String && scope.isNotBlank())
            }
        return NimbusJwtDecoder(jwtProcessor).apply {
            setJwtValidator(JwtValidators.createDefaultWithValidators(scopeValidator, *validators))
        }
    }

    private fun userApiJwtDecoder(
        jwkSource: JWKSource<SecurityContext>,
        authorizationProperties: AuthorizationProperties,
    ): JwtDecoder {
        val allowedAudiences =
            authorizationProperties.clients
                .filterValues(ClientProperties::userApiAccess)
                .keys
        val audienceValidator =
            JwtClaimValidator<List<String>>(JwtClaimNames.AUD) { audience ->
                audience.orEmpty().any(allowedAudiences::contains)
            }
        return accessTokenDecoder(jwkSource, audienceValidator)
    }

    private fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val authoritiesConverter = JwtGrantedAuthoritiesConverter()
        authoritiesConverter.setAuthoritiesClaimName("roles")
        authoritiesConverter.setAuthorityPrefix("ROLE_")
        val converter = JwtAuthenticationConverter()
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter)
        return converter
    }

    @Bean
    fun tokenGenerator(
        jwkSource: JWKSource<SecurityContext>,
        tokenCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>,
    ): OAuth2TokenGenerator<*> {
        val jwtGenerator = JwtGenerator(NimbusJwtEncoder(jwkSource))
        jwtGenerator.setJwtCustomizer(tokenCustomizer)
        val refreshTokenGenerator: OAuth2TokenGenerator<OAuth2RefreshToken> = CustomRefreshTokenGenerator()
        return DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator)
    }

    @Bean
    fun corsConfigurationSource(authorizationProperties: AuthorizationProperties): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        val config = CorsConfiguration()
        config.addAllowedHeader("*")
        config.addAllowedMethod(HttpMethod.GET)
        config.addAllowedMethod(HttpMethod.POST)
        config.addAllowedMethod(HttpMethod.PUT)
        config.addAllowedMethod(HttpMethod.DELETE)
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
    fun clock(): Clock = Clock.systemUTC()

    @Bean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun users(datasource: DataSource): UserDetailsService {
        val service = PasswordExpirationAwareJdbcDao()
        service.usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY
        service.setAuthoritiesByUsernameQuery(DEF_AUTHORITIES_BY_USERNAME_QUERY)
        service.setDataSource(datasource)
        return service
    }

    @Bean
    fun authenticationProvider(
        users: UserDetailsService,
        passwordEncoder: PasswordEncoder,
        loginAttemptLimiter: LoginAttemptLimiter,
    ): AuthenticationProvider = ThrottledDaoAuthenticationProvider(users, passwordEncoder, loginAttemptLimiter)

    @Bean
    fun registeredClientRepository(authorizationProperties: AuthorizationProperties): RegisteredClientRepository {
        require(authorizationProperties.clients.isNotEmpty()) {
            "At least one client must be configured under qsp.authorization.clients"
        }

        val registeredClients =
            authorizationProperties.clients.map { (clientName, clientProperties) ->
                require(clientProperties.redirectUri.isNotEmpty()) {
                    "Client '$clientName' must configure at least one redirect URI"
                }

                val tokenSettings =
                    TokenSettings
                        .builder()
                        .accessTokenTimeToLive(clientProperties.accessTokenTimeToLive.minutes.toJavaDuration())
                        .refreshTokenTimeToLive(clientProperties.refreshTokenTimeToLive.minutes.toJavaDuration())
                        .reuseRefreshTokens(false)
                        .build()

                val clientBuilder =
                    RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId(clientName)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(
                            ClientSettings
                                .builder()
                                .requireAuthorizationConsent(true)
                                .requireProofKey(true)
                                .build(),
                        ).tokenSettings(tokenSettings)

                clientProperties.redirectUri.forEach(clientBuilder::redirectUri)
                clientProperties.postLogoutRedirectUris.forEach(clientBuilder::postLogoutRedirectUri)
                clientBuilder.build()
            }

        return InMemoryRegisteredClientRepository(registeredClients)
    }

    @Bean
    fun jwtTokenCustomizer(userService: UserService): OAuth2TokenCustomizer<JwtEncodingContext> =
        CurrentUserTokenCustomizer(userService)
}
