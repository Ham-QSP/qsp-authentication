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
import fr.f4fez.authorizationserver.user.PasswordPolicy
import fr.f4fez.authorizationserver.user.UserRepository
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
import java.time.Clock
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Findings of the final review: nothing may tell an existing account from an unknown one. */
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
class PasswordResetHardeningTest {
    @Autowired
    lateinit var service: PasswordResetService

    @Autowired
    lateinit var mailer: RecordingPasswordResetMailer

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    lateinit var users: UserRepository

    @Autowired
    lateinit var passwordPolicy: PasswordPolicy

    @Autowired
    lateinit var resets: PasswordResetRepository

    @Autowired
    lateinit var loginAttemptLimiter: LoginAttemptLimiter

    @Autowired
    lateinit var properties: PasswordResetProperties

    @Autowired
    lateinit var clock: Clock

    private val oldPassword = "Str0ng!Passw0rd"
    private val newPassword = "N3w!Passw0rd-ok"

    @BeforeEach
    fun resetMailer() = mailer.reset()

    private fun account(callsign: String) =
        userService.createValidated(callsign, "${callsign.lowercase()}@example.org", passwordEncoder.encode(oldPassword)!!)

    private fun sendRows(callsign: String) =
        jdbcTemplate.queryForObject(
            "select count(*) from qsp_auth_password_reset_sends where upper(username) = ?",
            Int::class.java,
            callsign,
        )!!

    private class CountingEncoder(
        private val delegate: PasswordEncoder,
    ) : PasswordEncoder by delegate {
        val encodes = AtomicInteger()
        val matches = AtomicInteger()

        override fun encode(rawPassword: CharSequence?): String? {
            encodes.incrementAndGet()
            return delegate.encode(rawPassword)
        }

        override fun matches(
            rawPassword: CharSequence?,
            encodedPassword: String?,
        ): Boolean {
            matches.incrementAndGet()
            return delegate.matches(rawPassword, encodedPassword)
        }
    }

    private fun serviceWith(
        encoder: PasswordEncoder,
        executor: Executor,
    ) = PasswordResetService(users, userService, encoder, passwordPolicy, resets, mailer, loginAttemptLimiter, properties, clock, executor)

    @Test
    fun `the code mail goes out on the mail executor, not on the request path`() {
        account("F4RHE")
        val queued = mutableListOf<Runnable>()
        val deferred = serviceWith(passwordEncoder) { queued += it }

        deferred.request("F4RHE")

        assertTrue(mailer.codes.isEmpty())
        assertEquals(1, queued.size)
        queued.single().run()
        assertEquals(1, mailer.codes.size)
    }

    @Test
    fun `an unknown callsign costs the same hashing as a known one`() {
        val encoder = CountingEncoder(passwordEncoder)
        val counting = serviceWith(encoder) { it.run() }

        counting.reset("F4NONEX", "123456", newPassword)
        assertEquals(1, encoder.matches.get())

        val encodesBefore = encoder.encodes.get()
        counting.resend("F4NONEX")
        assertEquals(encodesBefore + 1, encoder.encodes.get())
    }

    @Test
    fun `concurrent requests for the same account never fail`() {
        account("F4RHA")
        val pool = Executors.newFixedThreadPool(20)
        try {
            (1..20).map { pool.submit { service.request("F4RHA") } }.forEach { it.get() }
        } finally {
            pool.shutdown()
        }

        assertEquals(1, jdbcTemplate.queryForObject("select count(*) from qsp_auth_password_resets where upper(username) = 'F4RHA'", Int::class.java))
    }

    @Test
    fun `a mail failure still counts toward the hourly limit`() {
        account("F4RHB")
        mailer.failSending = true

        repeat(5) { service.request("F4RHB") }

        assertEquals(3, sendRows("F4RHB"))
    }

    @Test
    fun `a checked mail exception does not surface on a request`() {
        account("F4RHC")
        mailer.failWithChecked = true

        service.request("F4RHC")

        assertTrue(mailer.codes.isEmpty())
    }

    @Test
    fun `a checked mail exception does not undo a successful reset`() {
        account("F4RHD")
        service.request("F4RHD")
        val code = mailer.lastCodeFor("F4RHD")!!
        mailer.failWithChecked = true

        assertEquals(ResetResult.Done, service.reset("F4RHD", code, newPassword))
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
