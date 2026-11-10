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
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals

@SpringBootTest
class UserCreationTest {
    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    @Test
    fun `create grants ROLE_USER by default`() {
        userService.create(
            CreateUserRequest(
                username = "new_user",
                password = "secret",
                email = "new-user@localhost",
                enabled = true,
            ),
        )

        val authorities =
            jdbcTemplate.queryForList(
                "select a.authority from qsp_auth_user_authorities a join qsp_auth_users u on u.id = a.user_id " +
                    "where u.username = ?",
                String::class.java,
                "NEW_USER",
            )
        assertEquals(listOf("ROLE_USER"), authorities)
    }

    @Test
    fun `findByEmail returns the roles`() {
        createUser("email_roles")

        assertEquals(setOf("ROLE_USER"), userService.findByEmail("email_roles@localhost").single().roles)
    }

    private fun createUser(username: String) =
        userService.create(
            CreateUserRequest(
                username = username,
                password = "secret",
                email = "$username@localhost",
                enabled = true,
            ),
        )

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
