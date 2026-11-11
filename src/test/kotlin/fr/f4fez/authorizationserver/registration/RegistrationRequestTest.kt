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
import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
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
class RegistrationRequestTest {
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

    private fun failure(block: () -> Unit) = assertFailsWith<ResponseStatusException>(block = block)

    @Test
    fun `a request is stored normalized with hashed password and code, and the code is mailed`() {
        service.request(" f4rqa ", " Ham.RQA@Example.org ", password)

        val stored = assertNotNull(registrations.findByNormalizedCallsign("F4RQA"))
        assertEquals("F4RQA", stored.callsign)
        assertEquals("ham.rqa@example.org", stored.email)
        assertTrue(passwordEncoder.matches(password, stored.passwordHash))
        val mail = mailer.codes.single()
        assertEquals("ham.rqa@example.org", mail.email)
        assertTrue(Regex("[0-9]{6}").matches(mail.code))
        assertTrue(passwordEncoder.matches(mail.code, stored.codeHash))
        assertEquals(RegistrationStatus.PENDING_EMAIL, stored.status)
    }

    @Test
    fun `an invalid callsign is refused`() {
        assertEquals(
            HttpStatus.BAD_REQUEST,
            failure { service.request("F4_RQB", "rqb@example.org", password) }.statusCode,
        )
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `a weak password is refused`() {
        assertEquals(HttpStatus.BAD_REQUEST, failure { service.request("F4RQC", "rqc@example.org", "weak") }.statusCode)
        assertNull(registrations.findByNormalizedCallsign("F4RQC"))
    }

    @Test
    fun `a callsign used by an active account is refused`() {
        userService.create(CreateUserRequest(username = "F4RQD", password = password, email = "rqd@example.org"))

        val error = failure { service.request("f4rqd", "other.rqd@example.org", password) }

        assertEquals(HttpStatus.BAD_REQUEST, error.statusCode)
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `an email used by an active account gets a notice and no registration is stored`() {
        userService.create(CreateUserRequest(username = "F4RQE", password = password, email = "rqe@example.org"))

        service.request("F4RQF", "RQE@example.org", password)

        assertNull(registrations.findByNormalizedCallsign("F4RQF"))
        assertEquals(listOf("rqe@example.org"), mailer.notices)
        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `a new request for the same callsign replaces the previous registration`() {
        service.request("F4RQG", "rqg.one@example.org", password)
        val firstHash = registrations.findByNormalizedCallsign("F4RQG")!!.codeHash

        service.request("F4RQG", "rqg.two@example.org", password)

        val stored = registrations.findByNormalizedCallsign("F4RQG")!!
        assertEquals("rqg.two@example.org", stored.email)
        assertNotEquals(firstHash, stored.codeHash)
        assertEquals(
            1,
            jdbcTemplate.queryForObject(
                "select count(*) from qsp_auth_registrations where upper(callsign) = 'F4RQG'",
                Int::class.java,
            ),
        )
    }

    @Test
    fun `a new request for the same email replaces the registration of another callsign`() {
        service.request("F4RQH", "rqh@example.org", password)

        service.request("F4RQI", "rqh@example.org", password)

        assertNull(registrations.findByNormalizedCallsign("F4RQH"))
        assertNotNull(registrations.findByNormalizedCallsign("F4RQI"))
    }

    @Test
    fun `no more than three codes per hour are sent to the same email`() {
        repeat(4) { service.request("F4RQJ", "rqj@example.org", password) }

        assertEquals(3, mailer.codes.size)
    }

    @Test
    fun `no more than three codes per hour are sent for the same callsign`() {
        repeat(4) { index -> service.request("F4RQK", "rqk$index@example.org", password) }

        assertEquals(3, mailer.codes.size)
    }

    @Test
    fun `the notice mail is limited like the code mails`() {
        userService.create(CreateUserRequest(username = "F4RQL", password = password, email = "rql@example.org"))

        repeat(4) { index -> service.request("F4RQM${'A' + index}", "rql@example.org", password) }

        assertEquals(3, mailer.notices.size)
    }

    @Test
    fun `a resend within sixty seconds sends nothing`() {
        service.request("F4RQN", "rqn@example.org", password)

        service.resend("F4RQN")

        assertEquals(1, mailer.codes.size)
    }

    @Test
    fun `a resend later issues a new code and the old one stops working`() {
        service.request("F4RQO", "rqo@example.org", password)
        val oldCode = mailer.codes.single().code
        jdbcTemplate.update(
            "update qsp_auth_registrations set last_sent_at = last_sent_at - interval '2 minutes' where upper(callsign) = 'F4RQO'",
        )

        service.resend(" f4rqo ")

        assertEquals(2, mailer.codes.size)
        val stored = registrations.findByNormalizedCallsign("F4RQO")!!
        assertTrue(passwordEncoder.matches(mailer.codes.last().code, stored.codeHash))
        assertFalse(passwordEncoder.matches(oldCode, stored.codeHash) && oldCode != mailer.codes.last().code)
    }

    @Test
    fun `a resend for an unknown callsign does nothing`() {
        service.resend("F4RQP")

        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `purge deletes registrations older than a day and keeps the others`() {
        service.request("F4RQQ", "rqq@example.org", password)
        service.request("F4RQR", "rqr@example.org", password)
        jdbcTemplate.update(
            "update qsp_auth_registrations set created_at = created_at - interval '25 hours' where upper(callsign) = 'F4RQQ'",
        )

        service.purgeExpired()

        assertNull(registrations.findByNormalizedCallsign("F4RQQ"))
        assertNotNull(registrations.findByNormalizedCallsign("F4RQR"))
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
