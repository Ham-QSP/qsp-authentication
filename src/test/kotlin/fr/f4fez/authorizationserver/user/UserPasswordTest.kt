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
package fr.f4fez.authorizationserver.user

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@SpringBootTest
class UserPasswordTest {
    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    private fun createUser(username: String): User =
        userService.create(
            CreateUserRequest(
                username = username,
                password = "old-password",
                email = "$username@localhost",
                enabled = true,
            ),
        )

    @Test
    fun `changePassword stores the new password when the current one matches`() {
        createUser("pwd-ok")

        userService.changePassword("pwd-ok", ChangePasswordRequest("old-password", "new-password"))

        val stored = userService.findByUsername("pwd-ok").password
        assertTrue(passwordEncoder.matches("new-password", stored))
    }

    @Test
    fun `changePassword rejects a wrong current password and keeps the old one`() {
        createUser("pwd-wrong")

        val exception =
            assertFailsWith<ResponseStatusException> {
                userService.changePassword("pwd-wrong", ChangePasswordRequest("not-the-password", "new-password"))
            }

        assertEquals(HttpStatus.BAD_REQUEST, exception.statusCode)
        val stored = userService.findByUsername("pwd-wrong").password
        assertTrue(passwordEncoder.matches("old-password", stored))
    }

    @Test
    fun `changePassword clears the password expiration`() {
        createUser("pwd-expired")
        jdbcTemplate.update(
            "update qsp_auth_users set password_expiration = now() - interval '1 day' where username = ?",
            "pwd-expired",
        )
        assertNotNull(userService.findByUsername("pwd-expired").passwordExpiration)

        userService.changePassword("pwd-expired", ChangePasswordRequest("old-password", "new-password"))

        assertNull(userService.findByUsername("pwd-expired").passwordExpiration)
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
