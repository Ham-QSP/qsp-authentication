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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Password change requested by a signed-in user, as opposed to the expired password flow.
 */
@SpringBootTest
@WebAppConfiguration
class PasswordChangeFlowTest {
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

    private fun createUser(username: String) {
        userService.create(
            CreateUserRequest(username = username, password = "old_password", email = "$username@localhost"),
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
        session: MockHttpSession,
    ) = mockMvc.perform(
        post("/login")
            .session(session)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("username", username)
            .param("password", "old_password")
            .param("_csrf", csrfToken("/login", session)),
    )

    private fun loggedInSession(username: String): MockHttpSession {
        createUser(username)
        val session = MockHttpSession()
        login(username, session)
        return session
    }

    private fun submitChange(
        session: MockHttpSession,
        currentPassword: String,
        newPassword: String,
        confirmPassword: String = newPassword,
    ) = mockMvc.perform(
        post("/password")
            .session(session)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .param("currentPassword", currentPassword)
            .param("newPassword", newPassword)
            .param("confirmPassword", confirmPassword)
            .param("_csrf", csrfToken("/password", session)),
    )

    private fun storedPasswordMatches(
        username: String,
        password: String,
    ) = passwordEncoder.matches(password, userService.findByUsername(username).password)

    @Test
    fun `signed-in user sees the change form with the current password field`() {
        val session = loggedInSession("change_form")

        mockMvc
            .perform(get("/password").session(session))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("Change password")))
            .andExpect(content().string(containsString("name=\"currentPassword\"")))
            .andExpect(content().string(not(containsString("has expired"))))
    }

    @Test
    fun `anonymous user signs in first and comes back to the change form`() {
        createUser("change_resume")
        val session = MockHttpSession()
        mockMvc
            .perform(get("/password").session(session).header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
            .andExpect(redirectedUrl("/login"))

        val redirect =
            login("change_resume", session)
                .andReturn()
                .response.redirectedUrl

        assertTrue(redirect.orEmpty().contains("/password"), "Redirected to $redirect")
    }

    @Test
    fun `correct current password changes the password and shows a confirmation`() {
        val session = loggedInSession("change_ok")

        submitChange(session, "old_password", "new_password")
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("Your password has been changed.")))
            .andExpect(content().string(not(containsString("href=\"/login\""))))

        assertTrue(storedPasswordMatches("change_ok", "new_password"))
    }

    @Test
    fun `wrong current password is rejected and keeps the old password`() {
        val session = loggedInSession("change_wrong")

        submitChange(session, "not_the_password", "new_password")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("auth-alert--error")))
            .andExpect(content().string(containsString("Current password is incorrect")))

        assertTrue(storedPasswordMatches("change_wrong", "old_password"))
    }

    @Test
    fun `mismatching confirmation is rejected and keeps the old password`() {
        val session = loggedInSession("change_mismatch")

        submitChange(session, "old_password", "new_password", "other_password")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("The passwords do not match")))

        assertFalse(storedPasswordMatches("change_mismatch", "new_password"))
    }

    @Test
    fun `missing current password is rejected`() {
        val session = loggedInSession("change_no_current")

        submitChange(session, "", "new_password")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("The current password is required")))

        assertTrue(storedPasswordMatches("change_no_current", "old_password"))
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
