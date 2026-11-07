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
package fr.f4fez.authorizationserver.authentication

import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpHeaders
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.testcontainers.containers.PostgreSQLContainer

@SpringBootTest
@WebAppConfiguration
class LoginPageTest {
    @Autowired
    lateinit var context: WebApplicationContext

    @Autowired
    lateinit var securityFilterChain: FilterChainProxy

    private val mockMvc: MockMvc by lazy {
        MockMvcBuilders
            .webAppContextSetup(context)
            .addFilters<DefaultMockMvcBuilder>(securityFilterChain)
            .build()
    }

    @Test
    fun `login page is rendered from the shared layout`() {
        mockMvc
            .perform(get("/login"))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString("/css/auth.css")))
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("name=\"username\"")))
            .andExpect(content().string(containsString("name=\"password\"")))
            .andExpect(content().string(containsString("name=\"_csrf\"")))
    }

    @Test
    fun `login error shows the generic message`() {
        mockMvc
            .perform(get("/login?error"))
            .andExpect(content().string(containsString("Invalid credentials")))
    }

    @Test
    fun `logout success shows the signed out message`() {
        mockMvc
            .perform(get("/login?logout"))
            .andExpect(content().string(containsString("You have been signed out")))
    }

    @Test
    fun `unsupported language falls back to english`() {
        mockMvc
            .perform(get("/login").header(HttpHeaders.ACCEPT_LANGUAGE, "de"))
            .andExpect(content().string(containsString("Sign in")))
            .andExpect(content().string(containsString("lang=\"en\"")))
            .andExpect(content().string(not(containsString("??"))))
    }

    @Test
    fun `stylesheet is public`() {
        mockMvc.perform(get("/css/auth.css")).andExpect(status().isOk)
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
