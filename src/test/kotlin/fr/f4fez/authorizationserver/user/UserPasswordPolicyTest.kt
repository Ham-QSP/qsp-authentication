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
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
class UserPasswordPolicyTest {
    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    private val strongPassword = "Correct-Horse-7"
    private val otherStrongPassword = "Battery-Staple-9"
    private val weakPassword = "weak"

    private fun createUser(username: String): User =
        userService.create(
            CreateUserRequest(username = username, password = strongPassword, email = "$username@localhost"),
        )

    private fun assertBadRequest(block: () -> Unit) {
        val exception = assertFailsWith<ResponseStatusException> { block() }
        assertEquals(HttpStatus.BAD_REQUEST, exception.statusCode)
    }

    private fun assertPasswordIs(
        username: String,
        password: String,
    ) {
        assertTrue(passwordEncoder.matches(password, userService.findByUsername(username).password))
    }

    @Test
    fun `create rejects a weak password`() {
        assertBadRequest {
            userService.create(
                CreateUserRequest(
                    username = "policy_create",
                    password = weakPassword,
                    email = "policy-create@localhost",
                ),
            )
        }
    }

    @Test
    fun `create checks the password against the new username`() {
        assertBadRequest {
            userService.create(
                CreateUserRequest(
                    username = "policyname",
                    password = "Xx-policyname-7",
                    email = "policyname@localhost",
                ),
            )
        }
    }

    @Test
    fun `update rejects a weak password and keeps the old one`() {
        val user = createUser("policy_update")

        assertBadRequest {
            userService.update(
                user.id!!,
                UpdateUserRequest(email = user.email, enabled = true, password = weakPassword),
            )
        }

        assertPasswordIs("policy_update", strongPassword)
    }

    @Test
    fun `update without a password does not apply the policy`() {
        val user = createUser("policy_nopwd")

        userService.update(user.id!!, UpdateUserRequest(email = user.email, enabled = false))

        assertPasswordIs("policy_nopwd", strongPassword)
    }

    @Test
    fun `changePassword rejects a weak password and keeps the old one`() {
        createUser("policy_change")

        assertBadRequest {
            userService.changePassword("policy_change", ChangePasswordRequest(strongPassword, weakPassword))
        }

        assertPasswordIs("policy_change", strongPassword)
    }

    @Test
    fun `changePassword accepts a strong password`() {
        createUser("policy_change_ok")

        userService.changePassword("policy_change_ok", ChangePasswordRequest(strongPassword, otherStrongPassword))

        assertPasswordIs("policy_change_ok", otherStrongPassword)
    }

    @Test
    fun `renewExpiredPassword rejects a weak password and keeps the old one`() {
        createUser("policy_renew")

        assertBadRequest { userService.renewExpiredPassword("policy_renew", weakPassword) }

        assertPasswordIs("policy_renew", strongPassword)
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
