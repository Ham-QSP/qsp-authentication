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

import fr.f4fez.authorizationserver.authentication.LoginAttemptLimiter
import fr.f4fez.authorizationserver.config.LoginThrottlingProperties
import fr.f4fez.authorizationserver.user.UserService
import fr.f4fez.authorizationserver.user.Usernames
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
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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
class PasswordResetVerifyTest {
    @Autowired
    lateinit var service: PasswordResetService

    @Autowired
    lateinit var resets: PasswordResetRepository

    @Autowired
    lateinit var mailer: RecordingPasswordResetMailer

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    lateinit var loginAttemptLimiter: LoginAttemptLimiter

    @Autowired
    lateinit var throttling: LoginThrottlingProperties

    private val oldPassword = "Str0ng!Passw0rd"
    private val newPassword = "N3w!Passw0rd-ok"

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun ask(callsign: String): String {
        userService.createValidated(
            callsign,
            "${callsign.lowercase()}@example.org",
            passwordEncoder.encode(oldPassword)!!,
        )
        service.request(callsign)
        return mailer.lastCodeFor(callsign)!!
    }

    private fun wrongCode(code: String) = if (code == "000000") "000001" else "000000"

    private fun storedPasswordMatches(
        callsign: String,
        password: String,
    ) = passwordEncoder.matches(password, userService.findByUsername(callsign).password)

    @Test
    fun `the right code changes the password and is single use`() {
        val code = ask("F4RVA")

        assertEquals(ResetResult.Done, service.reset("F4RVA", code, newPassword))

        assertTrue(storedPasswordMatches("F4RVA", newPassword))
        assertNull(resets.findByNormalizedUsername("F4RVA"))
        assertEquals(ResetResult.Invalid, service.reset("F4RVA", code, "An0ther!Passw0rd"))
        assertTrue(storedPasswordMatches("F4RVA", newPassword))
    }

    @Test
    fun `the code is accepted in any callsign case and with surrounding spaces`() {
        val code = ask("F4RVB")

        assertEquals(ResetResult.Done, service.reset("  f4rvb ", " $code ", newPassword))
    }

    @Test
    fun `a wrong code is invalid and counted`() {
        val code = ask("F4RVC")

        assertEquals(ResetResult.Invalid, service.reset("F4RVC", wrongCode(code), newPassword))

        assertEquals(1, resets.findByNormalizedUsername("F4RVC")!!.failedAttempts)
        assertTrue(storedPasswordMatches("F4RVC", oldPassword))
    }

    @Test
    fun `five wrong codes cancel the request even for the right code afterwards`() {
        val code = ask("F4RVD")

        repeat(5) { assertEquals(ResetResult.Invalid, service.reset("F4RVD", wrongCode(code), newPassword)) }

        assertNull(resets.findByNormalizedUsername("F4RVD"))
        assertEquals(ResetResult.Invalid, service.reset("F4RVD", code, newPassword))
        assertTrue(storedPasswordMatches("F4RVD", oldPassword))
    }

    @Test
    fun `an unknown callsign, an expired code and an ineligible account are all invalid`() {
        val expired = ask("F4RVE")
        jdbcTemplate.update(
            "update qsp_auth_password_resets set code_expires_at = code_expires_at - interval '1 hour' where upper(username) = 'F4RVE'",
        )
        val disabled = ask("F4RVF")
        jdbcTemplate.update("update qsp_auth_users set enabled = false where upper(username) = 'F4RVF'")

        assertEquals(ResetResult.Invalid, service.reset("F4NONE", "123456", newPassword))
        assertEquals(ResetResult.Invalid, service.reset("F4RVE", expired, newPassword))
        assertEquals(ResetResult.Invalid, service.reset("F4RVF", disabled, newPassword))
        assertTrue(storedPasswordMatches("F4RVE", oldPassword))
        assertTrue(storedPasswordMatches("F4RVF", oldPassword))
    }

    @Test
    fun `a weak new password is refused and the code stays usable`() {
        val code = ask("F4RVG")

        assertFailsWith<ResponseStatusException> { service.reset("F4RVG", code, "weak") }

        assertEquals(0, resets.findByNormalizedUsername("F4RVG")!!.failedAttempts)
        assertEquals(ResetResult.Done, service.reset("F4RVG", code, newPassword))
    }

    @Test
    fun `parallel wrong codes cannot exceed the attempt limit`() {
        val code = ask("F4RVH")
        val pool =
            java.util.concurrent.Executors
                .newFixedThreadPool(20)
        try {
            (1..40)
                .map { pool.submit { service.reset("F4RVH", wrongCode(code), newPassword) } }
                .forEach { it.get() }
        } finally {
            pool.shutdown()
        }

        assertNull(resets.findByNormalizedUsername("F4RVH"))
        assertEquals(ResetResult.Invalid, service.reset("F4RVH", code, newPassword))
    }

    @Test
    fun `a successful reset clears the login lockout and mails the notice`() {
        val code = ask("F4RVI")
        val key = Usernames.normalize("F4RVI")
        repeat(throttling.maxFailures) { loginAttemptLimiter.recordFailure(key) }
        assertTrue(loginAttemptLimiter.isLocked(key))

        service.reset("F4RVI", code, newPassword)

        assertFalse(loginAttemptLimiter.isLocked(key))
        assertEquals(listOf("f4rvi@example.org"), mailer.changedNotices)
    }

    @Test
    fun `a reset also clears a password expiration`() {
        val code = ask("F4RVJ")
        jdbcTemplate.update(
            "update qsp_auth_users set password_expiration = now() - interval '1 day' where upper(username) = 'F4RVJ'",
        )

        service.reset("F4RVJ", code, newPassword)

        assertNull(userService.findByUsername("F4RVJ").passwordExpiration)
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
