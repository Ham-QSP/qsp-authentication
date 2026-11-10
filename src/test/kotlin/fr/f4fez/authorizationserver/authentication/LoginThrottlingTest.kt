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
package fr.f4fez.authorizationserver.authentication

import fr.f4fez.authorizationserver.user.ChangePasswordRequest
import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(properties = ["qsp.login-throttling.max-failures=3"])
@WebAppConfiguration
class LoginThrottlingTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var loginAttemptLimiter: LoginAttemptLimiter

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    private fun createUser(username: String) {
        userService.create(CreateUserRequest(username = username, password = "secret", email = "$username@localhost"))
    }

    private fun csrfToken(session: MockHttpSession): String {
        val html =
            mockMvc
                .perform(get("/login").session(session))
                .andReturn()
                .response.contentAsString
        val match = Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(html)
        return assertNotNull(match, "No CSRF token in /login").groupValues[1]
    }

    private fun login(
        username: String,
        password: String,
        session: MockHttpSession = MockHttpSession(),
    ) = mockMvc.perform(
        post("/login")
            .session(session)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("username", username)
            .param("password", password)
            .param("_csrf", csrfToken(session)),
    )

    @Test
    fun `correct password is rejected once too many logins failed`() {
        createUser("throttle_locked")
        repeat(3) { login("throttle_locked", "wrong") }

        login("throttle_locked", "secret").andExpect(redirectedUrl("/login?error"))
    }

    @Test
    fun `locked account shows only the generic login error`() {
        createUser("throttle_message")
        val session = MockHttpSession()
        repeat(3) { login("throttle_message", "wrong", session) }
        login("throttle_message", "secret", session)

        mockMvc
            .perform(get("/login?error").session(session))
            .andExpect(content().string(containsString("Invalid credentials")))
            .andExpect(content().string(not(containsString(ThrottledDaoAuthenticationProvider.LOCKED_MESSAGE))))
    }

    @Test
    fun `unknown username is locked the same way, so the lock does not reveal accounts`() {
        repeat(3) { login("throttle_nobody", "wrong") }

        assertTrue(loginAttemptLimiter.isLocked("THROTTLE_NOBODY"))
    }

    @Test
    fun `case variants of a username share one failure count`() {
        createUser("throttle_case")
        listOf("throttle_case", "THROTTLE_CASE", " Throttle_Case ").forEach { login(it, "wrong") }

        login("throttle_case", "secret").andExpect(redirectedUrl("/login?error"))
    }

    @Test
    fun `successful login resets the failure count`() {
        createUser("throttle_reset")
        repeat(2) { login("throttle_reset", "wrong") }
        login("throttle_reset", "secret").andExpect(redirectedUrl("/"))

        repeat(2) { login("throttle_reset", "wrong") }

        login("throttle_reset", "secret").andExpect(redirectedUrl("/"))
    }

    @Test
    fun `password change is refused once too many current passwords were wrong`() {
        createUser("throttle_change")
        repeat(3) {
            assertFailsWith<ResponseStatusException> {
                userService.changePassword("throttle_change", ChangePasswordRequest("wrong", "new_password"))
            }
        }

        val exception =
            assertFailsWith<ResponseStatusException> {
                userService.changePassword("throttle_change", ChangePasswordRequest("secret", "new_password"))
            }

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exception.statusCode)
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
