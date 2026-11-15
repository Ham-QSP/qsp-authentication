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

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.dao.DuplicateKeyException
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import java.time.LocalDateTime
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

@SpringBootTest
class RegistrationSchemaTest {
    @Autowired
    lateinit var registrations: RegistrationRepository

    private fun registration(
        callsign: String,
        email: String,
    ) = Registration(
        callsign = callsign,
        email = email,
        passwordHash = "hash",
        codeHash = "code",
        codeExpiresAt = LocalDateTime.now().plusMinutes(15),
        lastSentAt = LocalDateTime.now(),
        createdAt = LocalDateTime.now(),
    )

    @Test
    fun `a registration is stored and found by its normalized callsign`() {
        val saved = registrations.save(registration("SCHEMA_FIND", "schema_find@localhost"))

        assertNotNull(saved.id)
        assertEquals("schema_find@localhost", registrations.findByNormalizedCallsign("SCHEMA_FIND")?.email)
        assertEquals(RegistrationStatus.PENDING_EMAIL, saved.status)
    }

    @Test
    fun `database rejects callsigns differing only by case`() {
        registrations.save(registration("schema_dup", "schema_dup@localhost"))

        assertFailsWith<DuplicateKeyException> { registrations.save(registration("SCHEMA_DUP", "other_dup@localhost")) }
    }

    @Test
    fun `database rejects emails differing only by case`() {
        registrations.save(registration("SCHEMA_MAIL_A", "mixed@localhost"))

        assertFailsWith<DuplicateKeyException> { registrations.save(registration("SCHEMA_MAIL_B", "MIXED@localhost")) }
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
