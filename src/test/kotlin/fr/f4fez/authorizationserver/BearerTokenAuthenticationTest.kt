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
package fr.f4fez.authorizationserver

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsInAnyOrder
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.testcontainers.containers.PostgreSQLContainer
import java.time.Instant
import java.util.UUID
import kotlin.test.assertTrue

@SpringBootTest
@WebAppConfiguration
class BearerTokenAuthenticationTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(
                context,
            ).addFilters<org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jwkSource: JWKSource<SecurityContext>

    private fun token(
        subject: String,
        vararg roles: String,
    ): String = signedToken(subject, roles.toSet(), audience = "portal", scope = setOf("openid"))

    private fun signedToken(
        subject: String,
        roles: Set<String>,
        audience: String,
        scope: Set<String>?,
    ): String {
        val claims =
            JwtClaimsSet
                .builder()
                .subject(subject)
                .audience(listOf(audience))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("roles", roles)
                .apply { scope?.let { claim("scope", it) } }
                .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).build()
        return NimbusJwtEncoder(jwkSource).encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }

    private fun adminUpdate(
        id: UUID,
        json: String,
    ) = mockMvc.perform(
        put("/users/$id")
            .contentType(MediaType.APPLICATION_JSON)
            .content(json)
            .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("someone", "ADMIN")}"),
    )

    @Test
    fun `admin update without passwordExpiration keeps it`() {
        val user =
            userService.create(
                CreateUserRequest(username = "json-keep", password = "secret", email = "json-keep@localhost"),
            )
        adminUpdate(
            user.id!!,
            """{"email":"json-keep@localhost","enabled":true,"passwordExpiration":"2030-01-02T03:04:05"}""",
        ).andExpect(status().isOk)

        adminUpdate(user.id!!, """{"email":"json-keep@localhost","enabled":false}""")
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.passwordExpiration").value("2030-01-02T03:04:05"))
    }

    @Test
    fun `admin update with a null passwordExpiration clears it`() {
        val user =
            userService.create(
                CreateUserRequest(username = "json-clear", password = "secret", email = "json-clear@localhost"),
            )
        adminUpdate(
            user.id!!,
            """{"email":"json-clear@localhost","enabled":true,"passwordExpiration":"2030-01-02T03:04:05"}""",
        ).andExpect(status().isOk)

        adminUpdate(user.id!!, """{"email":"json-clear@localhost","enabled":true,"passwordExpiration":null}""")
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.passwordExpiration").doesNotExist())
    }

    private fun corsPreflight(method: String) =
        mockMvc.perform(
            options("/users/@me")
                .header(HttpHeaders.ORIGIN, "http://localhost:3000")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method),
        )

    @ParameterizedTest
    @ValueSource(strings = ["GET", "POST", "PUT", "DELETE"])
    fun `client origin may call the user api with every method it exposes`(method: String) {
        corsPreflight(method)
            .andExpect(status().isOk)
            .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:3000"))
    }

    @Test
    fun `admin lists the known roles`() {
        mockMvc
            .perform(
                get("/roles")
                    .accept(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("someone", "ADMIN")}"),
            ).andExpect(status().isOk)
            .andExpect(jsonPath("$").value(containsInAnyOrder("ROLE_ADMIN", "ROLE_USER")))
    }

    @Test
    fun `non admin cannot list the roles`() {
        mockMvc
            .perform(
                get("/roles")
                    .accept(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("someone", "USER")}"),
            ).andExpect(status().isForbidden)
    }

    private fun getCurrentUser(token: String) =
        mockMvc.perform(
            get("/users/@me")
                .accept(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer $token"),
        )

    @Test
    fun `access token issued to a client allowed on the user api is accepted`() {
        userService.create(
            CreateUserRequest(username = "aud-portal", password = "secret", email = "aud-portal@localhost"),
        )

        getCurrentUser(signedToken("aud-portal", setOf("USER"), audience = "portal", scope = setOf("openid")))
            .andExpect(status().isOk)
    }

    @Test
    fun `token without scope, such as an ID token, is rejected`() {
        userService.create(
            CreateUserRequest(username = "aud-id-token", password = "secret", email = "aud-id-token@localhost"),
        )

        getCurrentUser(signedToken("aud-id-token", setOf("USER"), audience = "portal", scope = null))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `token issued to a client not allowed on the user api is rejected`() {
        userService.create(
            CreateUserRequest(username = "aud-other", password = "secret", email = "aud-other@localhost"),
        )

        getCurrentUser(signedToken("aud-other", setOf("ADMIN"), audience = "other", scope = setOf("openid")))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `bearer token with ADMIN role can call users api`() {
        mockMvc
            .perform(
                get("/users")
                    .accept(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("someone", "ADMIN")}"),
            ).andExpect(status().isOk)
    }

    @Test
    fun `bearer token without ADMIN role is forbidden`() {
        mockMvc
            .perform(
                get("/users")
                    .accept(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("someone", "USER")}"),
            ).andExpect(status().isForbidden)
    }

    @Test
    fun `invalid bearer token is unauthorized and not redirected to login`() {
        mockMvc
            .perform(
                get("/users")
                    .accept(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer garbage"),
            ).andExpect(status().isUnauthorized)
    }

    @Test
    fun `non admin can change own password through users me password`() {
        userService.create(
            CreateUserRequest(username = "pwd-self", password = "old-password", email = "pwd-self@localhost"),
        )

        mockMvc
            .perform(
                put("/users/@me/password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""{"currentPassword":"old-password","newPassword":"new-password"}""")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer ${token("pwd-self", "USER")}"),
            ).andExpect(status().isNoContent)

        assertTrue(passwordEncoder.matches("new-password", userService.findByUsername("pwd-self").password))
    }

    @Test
    fun `change password with an invalid bearer token is unauthorized`() {
        mockMvc
            .perform(
                put("/users/@me/password")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""{"currentPassword":"a","newPassword":"b"}""")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer garbage"),
            ).andExpect(status().isUnauthorized)
    }

    private fun searchByEmail(
        email: String?,
        bearer: String,
    ) = mockMvc.perform(
        get("/users/search")
            .apply { if (email != null) param("email", email) }
            .accept(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.AUTHORIZATION, "Bearer $bearer"),
    )

    private fun createSearchableUser(username: String) {
        userService.create(
            CreateUserRequest(username = username, password = "old-password", email = "$username@localhost"),
        )
    }

    @Test
    fun `user role can search by email and only gets id and username`() {
        createSearchableUser("search-user-role")

        searchByEmail("SEARCH-USER-ROLE@localhost", token("someone", "USER"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].username").value("search-user-role"))
            .andExpect(jsonPath("$[0].keys()").value(containsInAnyOrder("id", "username")))
    }

    @Test
    fun `admin role can search by email`() {
        createSearchableUser("search-admin-role")

        searchByEmail("search-admin-role@localhost", token("someone", "ADMIN"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$[0].username").value("search-admin-role"))
    }

    @Test
    fun `search without any known role is forbidden`() {
        searchByEmail("someone@localhost", token("someone")).andExpect(status().isForbidden)
    }

    @Test
    fun `search with an invalid bearer token is unauthorized`() {
        searchByEmail("someone@localhost", "garbage").andExpect(status().isUnauthorized)
    }

    @Test
    fun `search with an invalid email is rejected`() {
        searchByEmail("%", token("someone", "USER")).andExpect(status().isBadRequest)
    }

    @Test
    fun `search without email is rejected`() {
        searchByEmail(null, token("someone", "USER")).andExpect(status().isBadRequest)
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
