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
class UserServiceTest {
    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    @Test
    fun `delete removes a user that still has authorities`() {
        val user =
            userService.create(
                CreateUserRequest(
                    username = "to-delete",
                    password = "secret",
                    email = "to-delete@localhost",
                    enabled = true,
                ),
            )
        jdbcTemplate.update(
            "insert into qsp_auth_user_authorities (username, authority) values (?, ?)",
            "to-delete",
            "ROLE_ADMIN",
        )

        userService.delete(user.id!!)

        val remainingAuthorities =
            jdbcTemplate.queryForObject(
                "select count(*) from qsp_auth_user_authorities where username = ?",
                Int::class.java,
                "to-delete",
            )
        assertEquals(0, remainingAuthorities)
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
