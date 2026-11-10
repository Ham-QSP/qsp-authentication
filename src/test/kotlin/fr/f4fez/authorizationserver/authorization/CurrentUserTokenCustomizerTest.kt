/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>
 */
package fr.f4fez.authorizationserver.authorization

import fr.f4fez.authorizationserver.user.ChangePasswordRequest
import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UpdateUserRequest
import fr.f4fez.authorizationserver.user.User
import fr.f4fez.authorizationserver.user.UserService
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import java.time.LocalDateTime
import java.util.Optional
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * A refresh token replays the authentication saved at login, so every access token must be checked
 * against the current state of the user.
 */
@SpringBootTest
class CurrentUserTokenCustomizerTest {
    @Autowired
    lateinit var tokenCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>

    @Autowired
    lateinit var authenticationProvider: AuthenticationProvider

    @Autowired
    lateinit var registeredClientRepository: RegisteredClientRepository

    @Autowired
    lateinit var userService: UserService

    private fun createUser(username: String): User =
        userService.create(CreateUserRequest(username = username, password = "secret", email = "$username@localhost"))

    private fun login(username: String): Authentication =
        requireNotNull(
            authenticationProvider.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(username, "secret"),
            ),
        )

    private fun refreshedAccessTokenClaims(principal: Authentication): Map<String, Any> {
        val claims = JwtClaimsSet.builder().subject(principal.name)
        val context =
            JwtEncodingContext
                .with(JwsHeader.with(SignatureAlgorithm.RS256), claims)
                .registeredClient(requireNotNull(registeredClientRepository.findByClientId("portal")))
                .principal(principal)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build()
        tokenCustomizer.customize(context)
        return claims.build().claims
    }

    private fun assertRefreshRejected(principal: Authentication) {
        val exception = assertFailsWith<OAuth2AuthenticationException> { refreshedAccessTokenClaims(principal) }
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.error.errorCode)
    }

    private fun update(
        user: User,
        enabled: Boolean = true,
        roles: Set<String>? = null,
        passwordExpiration: LocalDateTime? = null,
    ) = userService.update(
        user.id!!,
        UpdateUserRequest(
            email = user.email,
            enabled = enabled,
            roles = roles,
            passwordExpiration = passwordExpiration?.let { Optional.of(it) },
        ),
    )

    @Test
    fun `roles come from the current user, not from the login`() {
        val user = createUser("refresh_demoted")
        update(user, roles = setOf("ROLE_ADMIN"))
        val principal = login("refresh_demoted")

        update(user, roles = setOf("ROLE_USER"))

        assertEquals(setOf("USER"), refreshedAccessTokenClaims(principal)["roles"])
    }

    @Test
    fun `disabled user cannot refresh`() {
        val user = createUser("refresh_disabled")
        val principal = login("refresh_disabled")

        update(user, enabled = false)

        assertRefreshRejected(principal)
    }

    @Test
    fun `user whose password expired cannot refresh`() {
        val user = createUser("refresh_expired")
        val principal = login("refresh_expired")

        update(user, passwordExpiration = LocalDateTime.now().minusMinutes(1))

        assertRefreshRejected(principal)
    }

    @Test
    fun `unknown user cannot refresh`() {
        assertRefreshRejected(UsernamePasswordAuthenticationToken.authenticated("refresh_ghost", null, emptyList()))
    }

    @Test
    fun `password change revokes logins made before it`() {
        createUser("refresh_changed")
        val principal = login("refresh_changed")

        userService.changePassword("refresh_changed", ChangePasswordRequest("secret", "new_password"))

        assertRefreshRejected(principal)
    }

    @Test
    fun `login made after a password change can refresh`() {
        createUser("refresh_after_change")
        userService.changePassword("refresh_after_change", ChangePasswordRequest("secret", "new_password"))
        userService.changePassword("refresh_after_change", ChangePasswordRequest("new_password", "secret"))

        val principal = login("refresh_after_change")

        assertEquals(setOf("USER"), refreshedAccessTokenClaims(principal)["roles"])
    }

    companion object {
        var postgres: PostgreSQLContainer<*> = PostgreSQLContainer("postgres:17-alpine")

        @BeforeAll
        @JvmStatic
        fun beforeAll() {
            postgres.start()
        }

        @AfterAll
        @JvmStatic
        fun afterAll() {
            postgres.stop()
        }

        @DynamicPropertySource
        @JvmStatic
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
        }
    }
}
