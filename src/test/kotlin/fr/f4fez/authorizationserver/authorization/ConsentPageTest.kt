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

import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
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
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.util.UriComponentsBuilder
import org.testcontainers.containers.PostgreSQLContainer
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest
@WebAppConfiguration
class ConsentPageTest {
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

    private fun csrfToken(html: String): String {
        val match = Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(html)
        return assertNotNull(match, "No CSRF token in $html").groupValues[1]
    }

    private fun loggedInSession(username: String): MockHttpSession {
        userService.create(CreateUserRequest(username = username, password = "secret", email = "$username@localhost"))
        val session = MockHttpSession()
        val loginPage =
            mockMvc
                .perform(get("/login").session(session))
                .andReturn()
                .response.contentAsString
        mockMvc
            .perform(
                post("/login")
                    .session(session)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", username)
                    .param("password", "secret")
                    .param("_csrf", csrfToken(loginPage)),
            ).andExpect(redirectedUrl("/"))
        return session
    }

    private fun authorize(session: MockHttpSession): ResultActions =
        mockMvc.perform(
            get("/oauth2/authorize")
                .session(session)
                .queryParam("response_type", "code")
                .queryParam("client_id", "portal")
                .queryParam("scope", "openid profile")
                .queryParam("redirect_uri", "http://localhost:3000")
                .queryParam("state", "state-1")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256"),
        )

    private data class ConsentPage(
        val state: String,
        val csrf: String,
    )

    private fun openConsentPage(session: MockHttpSession): ConsentPage {
        val consentUrl = authorize(session).andReturn().response.redirectedUrl!!
        val html =
            mockMvc
                .perform(get(URI.create(consentUrl)).session(session))
                .andExpect(status().isOk)
                .andReturn()
                .response.contentAsString
        val state =
            UriComponentsBuilder
                .fromUriString(consentUrl)
                .build()
                .queryParams
                .getFirst("state")
                ?.let { URLDecoder.decode(it, StandardCharsets.UTF_8) }
        return ConsentPage(assertNotNull(state, "No state in $consentUrl"), csrfToken(html))
    }

    @Test
    fun `consent page is rendered from the shared layout`() {
        val session = loggedInSession("consent-page")
        val consentUrl = authorize(session).andReturn().response.redirectedUrl!!
        assertTrue(consentUrl.contains("/oauth2/consent"), "Redirected to $consentUrl")

        mockMvc
            .perform(get(URI.create(consentUrl)).session(session))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("Read your profile")))
            .andExpect(content().string(not(containsString("type=\"checkbox\""))))
            .andExpect(content().string(containsString("name=\"_csrf\"")))
    }

    @Test
    fun `accepting consent returns an authorization code to the client`() {
        val session = loggedInSession("consent-accept")
        val page = openConsentPage(session)

        val redirect =
            mockMvc
                .perform(
                    post("/oauth2/authorize")
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", "portal")
                        .param("state", page.state)
                        .param("scope", "profile")
                        .param("_csrf", page.csrf),
                ).andReturn()
                .response.redirectedUrl!!

        assertTrue(redirect.startsWith("http://localhost:3000"), "Redirected to $redirect")
        assertTrue(redirect.contains("code="), "Redirected to $redirect")
    }

    @Test
    fun `refusing consent returns access_denied to the client`() {
        val session = loggedInSession("consent-refuse")
        val page = openConsentPage(session)

        val redirect =
            mockMvc
                .perform(
                    post("/oauth2/authorize")
                        .session(session)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", "portal")
                        .param("state", page.state)
                        .param("_csrf", page.csrf),
                ).andReturn()
                .response.redirectedUrl!!

        assertTrue(redirect.startsWith("http://localhost:3000"), "Redirected to $redirect")
        assertTrue(redirect.contains("error=access_denied"), "Redirected to $redirect")
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
