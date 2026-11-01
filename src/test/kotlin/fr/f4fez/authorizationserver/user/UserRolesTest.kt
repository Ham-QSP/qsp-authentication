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
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@SpringBootTest
class UserRolesTest {
    @Autowired
    lateinit var userService: UserService

    private fun createUser(username: String): User =
        userService.create(
            CreateUserRequest(
                username = username,
                password = "secret",
                email = "$username@localhost",
                enabled = true,
            ),
        )

    private fun updateRequest(
        username: String,
        roles: Set<String>?,
    ) = UpdateUserRequest(email = "$username@localhost", enabled = true, roles = roles)

    @Test
    fun `findById returns the roles of the user`() {
        val user = createUser("roles-get")

        assertEquals(setOf("ROLE_USER"), userService.findById(user.id!!).roles)
    }

    @Test
    fun `findAll returns the roles of each user`() {
        createUser("roles-list")

        val listed = userService.findAll().first { it.username == "roles-list" }

        assertEquals(setOf("ROLE_USER"), listed.roles)
    }

    @Test
    fun `update replaces the roles of the user`() {
        val user = createUser("roles-replace")

        val updated = userService.update(user.id!!, updateRequest("roles-replace", setOf("ROLE_ADMIN")))

        assertEquals(setOf("ROLE_ADMIN"), updated.roles)
        assertEquals(setOf("ROLE_ADMIN"), userService.findById(user.id!!).roles)
    }

    @Test
    fun `update without roles keeps the existing roles`() {
        val user = createUser("roles-keep")

        val updated = userService.update(user.id!!, updateRequest("roles-keep", null))

        assertEquals(setOf("ROLE_USER"), updated.roles)
    }

    @Test
    fun `update with an unknown role is rejected and changes nothing`() {
        val user = createUser("roles-unknown")

        val exception =
            assertFailsWith<ResponseStatusException> {
                userService.update(user.id!!, updateRequest("roles-unknown", setOf("ROLE_DOES_NOT_EXIST")))
            }

        assertEquals(HttpStatus.BAD_REQUEST, exception.statusCode)
        assertEquals(setOf("ROLE_USER"), userService.findById(user.id!!).roles)
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
