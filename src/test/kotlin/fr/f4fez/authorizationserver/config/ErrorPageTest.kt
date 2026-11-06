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
package fr.f4fez.authorizationserver.config

import jakarta.servlet.RequestDispatcher
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.testcontainers.containers.PostgreSQLContainer

@SpringBootTest
@WebAppConfiguration
class ErrorPageTest {
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

    private fun error(
        status: Int,
        accept: MediaType,
        customize: (MockHttpServletRequestBuilder) -> MockHttpServletRequestBuilder = { it },
    ) = mockMvc.perform(
        customize(
            get("/error")
                .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, status)
                .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/missing")
                .accept(accept),
        ),
    )

    @Test
    fun `browser errors use the shared layout`() {
        error(404, MediaType.TEXT_HTML)
            .andExpect(status().isNotFound)
            .andExpect(content().string(containsString("class=\"auth-card\"")))
            .andExpect(content().string(containsString("The page you requested does not exist.")))
            .andExpect(content().string(not(containsString("Whitelabel"))))
    }

    @Test
    fun `browser errors never leak internal details`() {
        error(500, MediaType.TEXT_HTML) {
            it
                .requestAttr(RequestDispatcher.ERROR_MESSAGE, "secret internal detail")
                .requestAttr(RequestDispatcher.ERROR_EXCEPTION, IllegalStateException("secret internal detail"))
        }.andExpect(status().isInternalServerError)
            .andExpect(content().string(containsString("An unexpected error occurred. Please try again later.")))
            .andExpect(content().string(not(containsString("secret internal detail"))))
    }

    @Test
    fun `api errors stay json`() {
        error(400, MediaType.APPLICATION_JSON)
            .andExpect(status().isBadRequest)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value(400))
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
