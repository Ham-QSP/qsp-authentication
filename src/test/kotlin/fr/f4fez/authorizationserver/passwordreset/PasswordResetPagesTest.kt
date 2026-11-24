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
package fr.f4fez.authorizationserver.passwordreset

import fr.f4fez.authorizationserver.user.UserService
import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
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
import kotlin.test.assertNotNull

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
class PasswordResetPagesTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var mailer: RecordingPasswordResetMailer

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    private val oldPassword = "Str0ng!Passw0rd"
    private val newPassword = "N3w!Passw0rd-ok"

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun account(callsign: String) =
        userService.createValidated(
            callsign,
            "${callsign.lowercase()}@example.org",
            passwordEncoder.encode(oldPassword)!!,
        )

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

    private fun verify(
        callsign: String,
        code: String,
        password: String = newPassword,
        confirm: String = password,
    ) = submit(
        "/password/forgot/verify",
        "/password/forgot/verify",
        "callsign" to callsign,
        "code" to code,
        "password" to password,
        "confirmPassword" to confirm,
    )

    @Test
    fun `the login page links to the forgot password page`() {
        mockMvc
            .perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("/password/forgot")))
    }

    @Test
    fun `the forgot form is rendered anonymously`() {
        mockMvc
            .perform(get("/password/forgot"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("name=\"callsign\"")))
            .andExpect(content().string(containsString("name=\"_csrf\"")))
    }

    @Test
    fun `asking for a code answers the same for a known and an unknown callsign`() {
        account("F4RPA")

        submit("/password/forgot", "/password/forgot", "callsign" to "f4rpa")
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/password/forgot/verify?callsign=F4RPA"))
        submit("/password/forgot", "/password/forgot", "callsign" to "f4none")
            .andExpect(status().isFound)
            .andExpect(redirectedUrl("/password/forgot/verify?callsign=F4NONE"))
    }

    @Test
    fun `the verify page rejects mismatching passwords and a wrong code with 400`() {
        account("F4RPB")
        submit("/password/forgot", "/password/forgot", "callsign" to "F4RPB")
        val code = mailer.lastCodeFor("F4RPB")!!

        verify("F4RPB", code, confirm = "different").andExpect(status().isBadRequest)
        verify("F4RPB", if (code == "000000") "000001" else "000000").andExpect(status().isBadRequest)
    }

    @Test
    fun `the full flow changes the password and the new one signs in`() {
        account("F4RPC")
        submit("/password/forgot", "/password/forgot", "callsign" to "F4RPC")
        val code = mailer.lastCodeFor("F4RPC")!!

        verify("F4RPC", code)
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("/login")))

        val session = MockHttpSession()
        mockMvc
            .perform(
                post("/login")
                    .session(session)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", "F4RPC")
                    .param("password", newPassword)
                    .param("_csrf", csrf("/login", session)),
            ).andExpect(redirectedUrl("/"))
    }

    @Test
    fun `a resend answers with the info message whether or not a request is pending`() {
        account("F4RPD")

        submit("/password/forgot/resend", "/password/forgot/verify?callsign=F4RPD", "callsign" to "F4RPD")
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("a new code has been sent")))
        submit("/password/forgot/resend", "/password/forgot/verify?callsign=F4NONE", "callsign" to "F4NONE")
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("a new code has been sent")))
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
