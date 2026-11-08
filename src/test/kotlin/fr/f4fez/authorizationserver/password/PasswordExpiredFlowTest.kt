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
package fr.f4fez.authorizationserver.password

import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UpdateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.testcontainers.containers.PostgreSQLContainer
import java.time.LocalDateTime
import java.util.Optional
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest
@WebAppConfiguration
class PasswordExpiredFlowTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    private fun createUser(
        username: String,
        passwordExpiration: LocalDateTime? = LocalDateTime.now().minusDays(1),
    ) {
        val user =
            userService.create(
                CreateUserRequest(username = username, password = "old-password", email = "$username@localhost"),
            )
        userService.update(
            user.id!!,
            UpdateUserRequest(
                email = user.email,
                enabled = true,
                passwordExpiration = Optional.ofNullable(passwordExpiration),
            ),
        )
    }

    private fun csrfToken(
        page: String,
        session: MockHttpSession,
    ): String {
        val html =
            mockMvc
                .perform(get(page).session(session))
                .andReturn()
                .response.contentAsString
        val match = Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(html)
        return assertNotNull(match, "No CSRF token in $page").groupValues[1]
    }

    private fun login(
        username: String,
        password: String,
        session: MockHttpSession,
    ) = mockMvc.perform(
        post("/login")
            .session(session)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("username", username)
            .param("password", password)
            .param("_csrf", csrfToken("/login", session)),
    )

    private fun submitNewPassword(
        session: MockHttpSession,
        newPassword: String,
        confirmPassword: String = newPassword,
    ) = mockMvc.perform(
        post("/password")
            .session(session)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("newPassword", newPassword)
            .param("confirmPassword", confirmPassword)
            .param("_csrf", csrfToken("/password", session)),
    )

    private fun storedPasswordMatches(
        username: String,
        password: String,
    ) = passwordEncoder.matches(password, userService.findByUsername(username).password)

    @Test
    fun `login with an expired password redirects to the password change page`() {
        createUser("flow-redirect")

        login("flow-redirect", "old-password", MockHttpSession())
            .andExpect(redirectedUrl("/password"))
    }

    @Test
    fun `login with a wrong password still shows the login error`() {
        createUser("flow-wrong")
        val session = MockHttpSession()

        login("flow-wrong", "not-the-password", session).andExpect(redirectedUrl("/login?error"))

        mockMvc
            .perform(get("/login?error").session(session))
            .andExpect(content().string(containsString("Invalid credentials")))
    }

    @Test
    fun `anonymous password change page redirects to login`() {
        mockMvc
            .perform(get("/password").header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
            .andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `new password replaces the expired one and clears the expiration`() {
        createUser("flow-change")
        val session = MockHttpSession()
        login("flow-change", "old-password", session)

        submitNewPassword(session, "new-password").andExpect(status().isOk)

        assertTrue(storedPasswordMatches("flow-change", "new-password"))
        assertNull(userService.findByUsername("flow-change").passwordExpiration)
    }

    @Test
    fun `password change cannot be replayed after success`() {
        createUser("flow-replay")
        val session = MockHttpSession()
        login("flow-replay", "old-password", session)
        submitNewPassword(session, "new-password")

        mockMvc
            .perform(get("/password").session(session).header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
            .andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `password change page is rendered from the shared layout`() {
        createUser("flow-layout")
        val session = MockHttpSession()
        login("flow-layout", "old-password", session)

        mockMvc
            .perform(get("/password").session(session))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("The password of flow-layout has expired")))
    }

    @Test
    fun `expired password change does not ask for the current password`() {
        createUser("flow-no-current")
        val session = MockHttpSession()
        login("flow-no-current", "old-password", session)

        mockMvc
            .perform(get("/password").session(session))
            .andExpect(content().string(containsString("Password expired")))
            .andExpect(content().string(not(containsString("name=\"currentPassword\""))))
    }

    @Test
    fun `mismatching passwords show the error in the shared layout`() {
        createUser("flow-mismatch-page")
        val session = MockHttpSession()
        login("flow-mismatch-page", "old-password", session)

        submitNewPassword(session, "new-password", "other-password")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("auth-alert--error")))
            .andExpect(content().string(containsString("The passwords do not match")))
    }

    @Test
    fun `success page links back to login`() {
        createUser("flow-success-page")
        val session = MockHttpSession()
        login("flow-success-page", "old-password", session)

        submitNewPassword(session, "new-password")
            .andExpect(content().string(containsString("Your password has been changed.")))
            .andExpect(content().string(containsString("href=\"/login\"")))
            .andExpect(content().string(containsString("class=\"auth-card\"")))
    }

    @Test
    fun `username is escaped on the password change page`() {
        createUser("flow-<script>x</script>")
        val session = MockHttpSession()
        login("flow-<script>x</script>", "old-password", session)

        mockMvc
            .perform(get("/password").session(session))
            .andExpect(content().string(containsString("flow-&lt;script&gt;x&lt;/script&gt;")))
            .andExpect(content().string(not(containsString("<script>x</script>"))))
    }

    @Test
    fun `saved request resumes after logging in with the new password`() {
        createUser("flow-resume")
        val session = MockHttpSession()
        mockMvc.perform(get("/users").session(session).header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
        login("flow-resume", "old-password", session)
        submitNewPassword(session, "new-password")

        val redirect =
            login("flow-resume", "new-password", session)
                .andReturn()
                .response.redirectedUrl

        assertTrue(redirect.orEmpty().contains("/users"), "Redirected to $redirect")
    }

    @Test
    fun `mismatching confirmation keeps the old password`() {
        createUser("flow-mismatch")
        val session = MockHttpSession()
        login("flow-mismatch", "old-password", session)

        submitNewPassword(session, "new-password", "other-password").andExpect(status().isBadRequest)

        assertTrue(storedPasswordMatches("flow-mismatch", "old-password"))
    }

    @Test
    fun `reusing the expired password is rejected`() {
        createUser("flow-reuse")
        val session = MockHttpSession()
        login("flow-reuse", "old-password", session)

        submitNewPassword(session, "old-password").andExpect(status().isBadRequest)

        assertNotNull(userService.findByUsername("flow-reuse").passwordExpiration)
    }

    @Test
    fun `new password longer than the bcrypt limit is rejected`() {
        createUser("flow-long")
        val session = MockHttpSession()
        login("flow-long", "old-password", session)

        submitNewPassword(session, "x".repeat(73)).andExpect(status().isBadRequest)

        assertFalse(storedPasswordMatches("flow-long", "x".repeat(73)))
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
