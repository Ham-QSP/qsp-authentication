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
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@SpringBootTest
class UserSearchTest {
    @Autowired
    lateinit var userService: UserService

    private fun createUser(
        username: String,
        email: String,
    ) {
        userService.create(CreateUserRequest(username = username, password = "secret", email = email))
    }

    private fun usernamesFor(email: String) = userService.findByEmail(email).map { it.username }

    @Test
    fun `findByEmail finds the exact email`() {
        createUser("search_exact", "Search.Exact@Example.com")

        assertEquals(listOf("SEARCH_EXACT"), usernamesFor("Search.Exact@Example.com"))
    }

    @Test
    fun `findByEmail ignores the case`() {
        createUser("search_case", "Search.Case@Example.com")

        assertEquals(listOf("SEARCH_CASE"), usernamesFor("search.case@EXAMPLE.COM"))
    }

    @Test
    fun `findByEmail ignores surrounding whitespace`() {
        createUser("search_trim", "search.trim@example.com")

        assertEquals(listOf("SEARCH_TRIM"), usernamesFor("  search.trim@example.com "))
    }

    @Test
    fun `findByEmail does not match partially`() {
        createUser("search_partial", "search.partial@example.com")

        assertTrue(usernamesFor("search.partial@example").isEmpty())
        assertTrue(usernamesFor("earch.partial@example.com").isEmpty())
        assertTrue(usernamesFor("example.com").isEmpty())
        assertTrue(usernamesFor("search.partial").isEmpty())
    }

    @Test
    fun `findByEmail treats sql wildcards literally`() {
        createUser("search_wildcard", "search.wildcard@example.com")

        assertTrue(usernamesFor("%@example.com").isEmpty())
        assertTrue(usernamesFor("search_wildcard@example.com").isEmpty())
        assertTrue(usernamesFor("%").isEmpty())
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
