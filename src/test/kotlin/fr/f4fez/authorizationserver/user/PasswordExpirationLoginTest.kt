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
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import java.time.LocalDateTime
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@SpringBootTest
class PasswordExpirationLoginTest {
    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var userDetailsService: UserDetailsService

    @Autowired
    lateinit var passwordEncoder: org.springframework.security.crypto.password.PasswordEncoder

    private fun authenticate(username: String) =
        DaoAuthenticationProvider(userDetailsService)
            .apply { setPasswordEncoder(passwordEncoder) }
            .authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, "secret"))

    private fun createUser(
        username: String,
        passwordExpiration: LocalDateTime?,
    ) {
        val user =
            userService.create(
                CreateUserRequest(username = username, password = "secret", email = "$username@localhost"),
            )
        userService.update(
            user.id!!,
            UpdateUserRequest(email = user.email, enabled = true, passwordExpiration = passwordExpiration),
        )
    }

    @Test
    fun `login is rejected when the password has expired`() {
        createUser("login-expired", LocalDateTime.now().minusDays(1))

        assertFailsWith<CredentialsExpiredException> { authenticate("login-expired") }
    }

    @Test
    fun `login succeeds when the password expires in the future`() {
        createUser("login-future", LocalDateTime.now().plusDays(1))

        assertTrue(authenticate("login-future").isAuthenticated)
    }

    @Test
    fun `login succeeds when the password never expires`() {
        createUser("login-never", null)

        assertTrue(authenticate("login-never").isAuthenticated)
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
