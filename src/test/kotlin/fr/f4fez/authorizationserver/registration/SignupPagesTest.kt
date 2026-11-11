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
package fr.f4fez.authorizationserver.registration

import fr.f4fez.authorizationserver.user.CreateUserRequest
import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
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
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest(
    properties = [
        "qsp.password-policy.min-length=12",
        "qsp.password-policy.min-uppercase=1",
        "qsp.password-policy.min-lowercase=1",
        "qsp.password-policy.min-digits=1",
        "qsp.password-policy.min-special=1",
        "qsp.password-policy.reject-username=true",
    ],
)
@WebAppConfiguration
class SignupPagesTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var mailer: RecordingRegistrationMailer

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    private val password = "Str0ng!Passw0rd"

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun csrf(
        path: String,
        session: MockHttpSession,
    ): String {
        val html =
            mockMvc
                .perform(get(path).session(session))
                .andReturn()
                .response.contentAsString
        return assertNotNull(Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(html)).groupValues[1]
    }

    private fun submit(
        path: String,
        formPath: String,
        vararg params: Pair<String, String>,
    ): ResultActions {
        val session = MockHttpSession()
        val token = csrf(formPath, session)
        return mockMvc.perform(
            post(path)
                .session(session)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("_csrf", token)
                .apply { params.forEach { (name, value) -> param(name, value) } },
        )
    }

    private fun signup(
        callsign: String,
        email: String,
        confirm: String = password,
    ) = submit(
        "/signup",
        "/signup",
        "callsign" to callsign,
        "email" to email,
        "password" to password,
        "confirmPassword" to confirm,
    )

    @Test
    fun `signup page is rendered from the shared layout for anonymous visitors`() {
        mockMvc
            .perform(get("/signup"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("name=\"callsign\"")))
            .andExpect(content().string(containsString("name=\"email\"")))
            .andExpect(content().string(containsString("name=\"_csrf\"")))
    }

    @Test
    fun `a valid signup redirects to the verification page and mails the code`() {
        signup("F4PGA", "pga@example.org").andExpect(redirectedUrl("/signup/verify?callsign=F4PGA"))

        assertEquals("pga@example.org", mailer.codes.single().email)
    }

    @Test
    fun `an invalid callsign shows the error and keeps the typed values`() {
        signup("F4_PGB", "pgb@example.org")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("valid callsign")))
            .andExpect(content().string(containsString("F4_PGB")))
            .andExpect(content().string(not(containsString(password))))
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `a password confirmation mismatch is reported`() {
        signup("F4PGC", "pgc@example.org", confirm = "Different!Passw0rd")
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("do not match")))
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `an email already in use gets the same answer as a normal signup`() {
        userService.create(CreateUserRequest(username = "F4PGD", password = password, email = "pgd@example.org"))

        signup("F4PGE", "pgd@example.org").andExpect(redirectedUrl("/signup/verify?callsign=F4PGE"))

        assertEquals(listOf("pgd@example.org"), mailer.notices)
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `the verification page is prefilled with the callsign`() {
        mockMvc
            .perform(get("/signup/verify").param("callsign", "F4PGF"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("value=\"F4PGF\"")))
            .andExpect(content().string(containsString("name=\"code\"")))
    }

    @Test
    fun `the right code creates the account and shows the sign in link`() {
        signup("F4PGG", "pgg@example.org")
        val code = mailer.lastCodeFor("F4PGG")!!

        submit("/signup/verify", "/signup/verify", "callsign" to "F4PGG", "code" to code)
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("href=\"/login\"")))
            .andExpect(content().string(containsString("F4PGG")))

        assertTrue(userService.findByUsername("F4PGG").emailValidated)
    }

    @Test
    fun `a wrong code and an unknown callsign get the same generic answer`() {
        signup("F4PGH", "pgh@example.org")
        val wrong = if (mailer.lastCodeFor("F4PGH") == "000000") "000001" else "000000"

        submit("/signup/verify", "/signup/verify", "callsign" to "F4PGH", "code" to wrong)
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("invalid or expired")))
        submit("/signup/verify", "/signup/verify", "callsign" to "F4PGI", "code" to wrong)
            .andExpect(status().isBadRequest)
            .andExpect(content().string(containsString("invalid or expired")))
    }

    @Test
    fun `resending from the verification page mails a new code and always answers the same`() {
        signup("F4PGJ", "pgj@example.org")
        jdbcTemplate.update(
            "update qsp_auth_registrations set last_sent_at = last_sent_at - interval '2 minutes' where upper(callsign) = 'F4PGJ'",
        )

        submit("/signup/resend", "/signup/verify", "callsign" to "F4PGJ")
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("a new code has been sent")))
        submit("/signup/resend", "/signup/verify", "callsign" to "F4PGK")
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("a new code has been sent")))

        assertEquals(2, mailer.codes.size)
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
