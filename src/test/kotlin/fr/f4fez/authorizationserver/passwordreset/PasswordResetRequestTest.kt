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

@SpringBootTest
class PasswordResetRequestTest {
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

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun account(
        callsign: String,
        email: String = "${callsign.lowercase()}@example.org",
    ) = userService.createValidated(callsign, email, passwordEncoder.encode("Str0ng!Passw0rd")!!)

    private fun backdateLastSend(callsign: String) =
        jdbcTemplate.update(
            "update qsp_auth_password_resets set last_sent_at = last_sent_at - interval '2 minutes' where upper(username) = ?",
            callsign,
        )

    private fun pendingRows(callsign: String) =
        jdbcTemplate.queryForObject(
            "select count(*) from qsp_auth_password_resets where upper(username) = ?",
            Int::class.java,
            callsign,
        )!!

    @Test
    fun `an eligible account gets a code mailed to its address`() {
        account("F4RQA")

        service.request("F4RQA")

        val code = mailer.lastCodeFor("F4RQA")
        assertNotNull(code)
        assertTrue(Regex("\\d{6}").matches(code))
        assertEquals("f4rqa@example.org", mailer.codes.single().email)
        assertEquals(1, pendingRows("F4RQA"))
    }

    @Test
    fun `callsign in lowercase and with spaces reaches the same account`() {
        account("F4RQB")

        service.request("  f4rqb ")

        assertEquals("F4RQB", mailer.codes.single().callsign)
    }

    @Test
    fun `unknown, disabled and unvalidated accounts get nothing`() {
        account("F4RQC")
        jdbcTemplate.update("update qsp_auth_users set enabled = false where upper(username) = 'F4RQC'")
        account("F4RQD")
        jdbcTemplate.update("update qsp_auth_users set email_validated = false where upper(username) = 'F4RQD'")

        service.request("F4RQC")
        service.request("F4RQD")
        service.request("F4NONE")

        assertTrue(mailer.codes.isEmpty())
        assertEquals(0, pendingRows("F4RQC") + pendingRows("F4RQD") + pendingRows("F4NONE"))
    }

    @Test
    fun `a mail server failure does not surface`() {
        account("F4RQE")
        mailer.failSending = true

        service.request("F4RQE")

        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `a second request replaces the first`() {
        account("F4RQF")
        service.request("F4RQF")
        val first = mailer.lastCodeFor("F4RQF")!!
        service.request("F4RQF")
        val second = mailer.lastCodeFor("F4RQF")!!

        val stored = resets.findByNormalizedUsername("F4RQF")!!
        assertEquals(1, pendingRows("F4RQF"))
        assertTrue(passwordEncoder.matches(second, stored.codeHash))
        assertTrue(first == second || !passwordEncoder.matches(first, stored.codeHash))
    }

    @Test
    fun `at most 3 codes per hour per callsign`() {
        account("F4RQG")

        repeat(4) { service.request("F4RQG") }

        assertEquals(3, mailer.codes.size)
    }

    @Test
    fun `a resend within 60 seconds of the previous send is skipped`() {
        account("F4RQH")
        service.request("F4RQH")

        service.resend("F4RQH")

        assertEquals(1, mailer.codes.size)
    }

    @Test
    fun `resend issues a new code and resets the attempt count`() {
        account("F4RQI")
        service.request("F4RQI")
        jdbcTemplate.update("update qsp_auth_password_resets set failed_attempts = 3 where upper(username) = 'F4RQI'")
        backdateLastSend("F4RQI")

        service.resend("F4RQI")

        assertEquals(2, mailer.codes.size)
        assertEquals(0, resets.findByNormalizedUsername("F4RQI")!!.failedAttempts)
    }

    @Test
    fun `resend for an unknown callsign does nothing`() {
        service.resend("F4NONE2")

        assertNull(resets.findByNormalizedUsername("F4NONE2"))
        assertTrue(mailer.codes.isEmpty())
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
