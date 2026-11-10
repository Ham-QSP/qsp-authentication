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
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.dao.DuplicateKeyException
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.server.ResponseStatusException
import org.testcontainers.containers.PostgreSQLContainer
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/**
 * Usernames are ASCII letters, digits and '_', stored and compared in uppercase; emails are compared in lowercase.
 */
@SpringBootTest
@WebAppConfiguration
class UserIdentifierNormalizationTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    lateinit var jdbcTemplate: JdbcTemplate

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    private fun create(
        username: String,
        email: String = "${username.trim()}@localhost",
    ) = userService.create(CreateUserRequest(username = username, password = "secret", email = email))

    private fun insertRow(
        username: String,
        email: String,
    ) {
        jdbcTemplate.update(
            "insert into qsp_auth_users (username, password, enabled, email, email_validated) " +
                "values (?, ?, true, ?, false)",
            username,
            passwordEncoder.encode("secret"),
            email,
        )
        jdbcTemplate.update(
            "insert into qsp_auth_user_authorities (user_id, authority) " +
                "select id, 'ROLE_USER' from qsp_auth_users where username = ?",
            username,
        )
    }

    private fun login(username: String): String? {
        val session = MockHttpSession()
        val html =
            mockMvc
                .perform(get("/login").session(session))
                .andReturn()
                .response.contentAsString
        val csrf = Regex("""name="_csrf"[^>]*value="([^"]+)"""").find(html)
        return mockMvc
            .perform(
                post("/login")
                    .session(session)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", username)
                    .param("password", "secret")
                    .param("_csrf", assertNotNull(csrf).groupValues[1]),
            ).andReturn()
            .response.redirectedUrl
    }

    @Test
    fun `create trims and stores the username in uppercase`() {
        assertEquals("F4ABC", create("  f4abc ").username)
    }

    @ParameterizedTest
    @ValueSource(strings = ["f4-dash", "f4.dot", "f4 space", "аdmin", "straße", "éric", "f4ı", ""])
    fun `create rejects anything but ASCII letters, digits and underscore`(username: String) {
        val error =
            assertFailsWith<ResponseStatusException> {
                create(username, "rejected${username.hashCode().toUInt()}@localhost")
            }

        assertEquals(HttpStatus.BAD_REQUEST, error.statusCode)
    }

    @Test
    fun `usernames differing only by case are the same account`() {
        create("case_dup")

        val error = assertFailsWith<ResponseStatusException> { create("CASE_DUP", "case_dup_2@localhost") }

        assertEquals(HttpStatus.CONFLICT, error.statusCode)
    }

    @Test
    fun `lowercase row in the database is found by its normalized username`() {
        insertRow("legacy_find", "legacy_find@localhost")

        assertEquals("legacy_find", userService.findByUsername(" LEGACY_FIND ").username)
    }

    @Test
    fun `login accepts the username typed in lowercase`() {
        create("login_lower")

        assertEquals("/", login(" login_lower "))
    }

    @Test
    fun `login finds a user stored in lowercase in the database`() {
        insertRow("legacy_login", "legacy_login@localhost")

        assertEquals("/", login("LEGACY_LOGIN"))
    }

    @Test
    fun `login does not fold non ASCII letters onto an ASCII account`() {
        create("strasse")

        assertEquals("/login?error", login("straße"))
    }

    @Test
    fun `create trims and stores the email in lowercase`() {
        assertEquals("mixed.case@example.org", create("mail_lower", "  Mixed.Case@Example.ORG ").email)
    }

    @Test
    fun `emails differing only by case are rejected on create`() {
        create("mail_dup_a", "dup@example.org")

        val error = assertFailsWith<ResponseStatusException> { create("mail_dup_b", "DUP@Example.org") }

        assertEquals(HttpStatus.CONFLICT, error.statusCode)
    }

    @Test
    fun `emails differing only by case are rejected on update`() {
        create("mail_upd_a", "taken@example.org")
        val other = create("mail_upd_b", "free@example.org")

        val error =
            assertFailsWith<ResponseStatusException> {
                userService.update(other.id!!, UpdateUserRequest(email = "Taken@Example.org", enabled = true))
            }

        assertEquals(HttpStatus.CONFLICT, error.statusCode)
    }

    @Test
    fun `update keeps the own email when only its case changes`() {
        val user = create("mail_same", "same@example.org")

        assertEquals(
            "same@example.org",
            userService.update(user.id!!, UpdateUserRequest(email = "SAME@example.org", enabled = true)).email,
        )
    }

    @Test
    fun `database rejects usernames differing only by case`() {
        insertRow("db_case", "db_case@localhost")

        assertFailsWith<DuplicateKeyException> { insertRow("DB_CASE", "db_case_2@localhost") }
    }

    @Test
    fun `database rejects emails differing only by case`() {
        insertRow("db_mail_a", "db_mail@localhost")

        assertFailsWith<DuplicateKeyException> { insertRow("db_mail_b", "DB_MAIL@localhost") }
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
