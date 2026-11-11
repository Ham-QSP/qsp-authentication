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
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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
class RegistrationVerifyTest {
    @Autowired
    lateinit var service: RegistrationService

    @Autowired
    lateinit var registrations: RegistrationRepository

    @Autowired
    lateinit var mailer: RecordingRegistrationMailer

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    private val password = "Str0ng!Passw0rd"

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun register(
        callsign: String,
        email: String = "${callsign.lowercase()}@example.org",
    ): String {
        service.request(callsign, email, password)
        return mailer.lastCodeFor(callsign)!!
    }

    private fun wrongCode(code: String) = if (code == "000000") "000001" else "000000"

    @Test
    fun `the right code creates an enabled and validated user with the chosen password`() {
        val code = register("F4VFA")

        assertEquals(VerifyResult.Created("F4VFA"), service.verify("F4VFA", code))

        val user = userService.findByUsername("F4VFA")
        assertTrue(user.enabled)
        assertTrue(user.emailValidated)
        assertEquals(setOf("ROLE_USER"), user.roles)
        assertEquals("f4vfa@example.org", user.email)
        assertTrue(passwordEncoder.matches(password, user.password))
        assertNull(registrations.findByNormalizedCallsign("F4VFA"))
    }

    @Test
    fun `a code is single use`() {
        val code = register("F4VFB")
        service.verify("F4VFB", code)

        assertEquals(VerifyResult.Invalid, service.verify("F4VFB", code))
    }

    @Test
    fun `callsign and code are accepted in any case and with surrounding spaces`() {
        val code = register("F4VFC")

        assertEquals(VerifyResult.Created("F4VFC"), service.verify(" f4vfc ", " $code "))
    }

    @Test
    fun `a wrong code is invalid and counted`() {
        val code = register("F4VFD")

        assertEquals(VerifyResult.Invalid, service.verify("F4VFD", wrongCode(code)))

        assertEquals(1, registrations.findByNormalizedCallsign("F4VFD")!!.failedAttempts)
    }

    @Test
    fun `five wrong codes cancel the registration even for the right code afterwards`() {
        val code = register("F4VFE")

        repeat(5) { service.verify("F4VFE", wrongCode(code)) }

        assertNull(registrations.findByNormalizedCallsign("F4VFE"))
        assertEquals(VerifyResult.Invalid, service.verify("F4VFE", code))
    }

    @Test
    fun `an unknown callsign is invalid`() {
        assertEquals(VerifyResult.Invalid, service.verify("F4VFF", "123456"))
    }

    @Test
    fun `an expired code is invalid`() {
        val code = register("F4VFG")
        jdbcTemplate.update(
            "update qsp_auth_registrations set code_expires_at = code_expires_at - interval '1 hour' where upper(callsign) = 'F4VFG'",
        )

        assertEquals(VerifyResult.Invalid, service.verify("F4VFG", code))
        assertNull(userService.findByUsernameOrNull("F4VFG"))
    }

    @Test
    fun `a callsign taken meanwhile makes the validation fail and removes the registration`() {
        val code = register("F4VFH")
        userService.create(CreateUserRequest(username = "F4VFH", password = password, email = "admin.vfh@example.org"))

        assertEquals(VerifyResult.Invalid, service.verify("F4VFH", code))

        assertNull(registrations.findByNormalizedCallsign("F4VFH"))
        assertEquals("admin.vfh@example.org", userService.findByUsername("F4VFH").email)
    }

    @Test
    fun `an email taken meanwhile makes the validation fail and removes the registration`() {
        val code = register("F4VFI", "vfi@example.org")
        userService.create(CreateUserRequest(username = "F4VFJ", password = password, email = "vfi@example.org"))

        assertEquals(VerifyResult.Invalid, service.verify("F4VFI", code))

        assertNull(registrations.findByNormalizedCallsign("F4VFI"))
        assertNull(userService.findByUsernameOrNull("F4VFI"))
    }

    @Test
    fun `a resent code replaces the previous one`() {
        val first = register("F4VFK")
        jdbcTemplate.update(
            "update qsp_auth_registrations set last_sent_at = last_sent_at - interval '2 minutes' where upper(callsign) = 'F4VFK'",
        )
        service.resend("F4VFK")
        val second = mailer.lastCodeFor("F4VFK")!!

        if (first != second) {
            assertEquals(VerifyResult.Invalid, service.verify("F4VFK", first))
        }
        assertNotNull(registrations.findByNormalizedCallsign("F4VFK"))
        assertEquals(VerifyResult.Created("F4VFK"), service.verify("F4VFK", second))
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
