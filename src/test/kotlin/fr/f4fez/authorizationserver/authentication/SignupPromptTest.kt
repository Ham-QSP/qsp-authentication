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

import org.junit.jupiter.api.AfterAll
import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.testcontainers.containers.PostgreSQLContainer

@SpringBootTest
@WebAppConfiguration
class SignupPromptTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var userService: UserService

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    private fun authorize(
        session: MockHttpSession,
        prompt: String?,
    ) = mockMvc.perform(
        get("/oauth2/authorize")
            .session(session)
            .queryParam("response_type", "code")
            .queryParam("client_id", "portal")
            .queryParam("scope", "openid")
            .queryParam("redirect_uri", "http://localhost:3000")
            .queryParam("state", "state_1")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .apply { prompt?.let { queryParam("prompt", it) } },
    )

    @Test
    fun `anonymous authorization request goes to the login page`() {
        authorize(MockHttpSession(), null).andExpect(status().isFound).andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `prompt create sends the visitor to the signup page and keeps the authorization request`() {
        val session = MockHttpSession()

        authorize(session, "create").andExpect(status().isFound).andExpect(redirectedUrl("/signup"))

        assertNotNull(session.getAttribute("SPRING_SECURITY_SAVED_REQUEST"))
    }

    @Test
    fun `signing in after the signup resumes the authorization request and returns a code`() {
        userService.create(CreateUserRequest(username = "signup_prompt", password = "secret", email = "signup_prompt@localhost"))
        val session = MockHttpSession()
        authorize(session, "create").andExpect(redirectedUrl("/signup"))

        val loginPage = mockMvc.perform(get("/login").session(session)).andReturn().response.contentAsString
        val csrf = Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(loginPage)!!.groupValues[1]
        val resumed =
            mockMvc
                .perform(
                    post("/login")
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "signup_prompt")
                        .param("password", "secret")
                        .param("_csrf", csrf),
                ).andExpect(status().isFound)
                .andReturn()
                .response.redirectedUrl!!

        assertTrue(resumed.contains("/oauth2/authorize"), "Resumed $resumed")
        val redirect = mockMvc.perform(get(resumed).session(session)).andReturn().response.redirectedUrl!!
        assertTrue(redirect.startsWith("http://localhost:3000") && redirect.contains("code="), "Redirected to $redirect")
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
