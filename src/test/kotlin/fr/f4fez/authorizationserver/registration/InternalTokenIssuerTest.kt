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
package fr.f4fez.authorizationserver.registration

import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

@SpringBootTest(properties = ["qsp.signaling.issuer=http://issuer.test", "qsp.signaling.subject=qsp-auth-test"])
class InternalTokenIssuerTest {
    @Autowired
    lateinit var issuer: InternalTokenIssuer

    @Autowired
    lateinit var jwkSource: JWKSource<SecurityContext>

    private fun decoder(): NimbusJwtDecoder {
        val key = jwkSource.get(JWKSelector(JWKMatcher.Builder().build()), null).filterIsInstance<RSAKey>().first()
        return NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build()
    }

    @Test
    fun `the token is signed with the server key and carries the SYS_AUTH role`() {
        val jwt = decoder().decode(issuer.issue())

        assertEquals("http://issuer.test", jwt.issuer.toString())
        assertEquals("qsp-auth-test", jwt.subject)
        assertEquals(listOf("SYS_AUTH"), jwt.getClaimAsStringList("roles"))
    }

    @Test
    fun `the token lives fifteen seconds`() {
        val jwt = decoder().decode(issuer.issue())

        assertEquals(Duration.ofSeconds(15), Duration.between(jwt.issuedAt, jwt.expiresAt))
    }

    @Test
    fun `every token is unique and has no scope`() {
        val first = decoder().decode(issuer.issue())
        val second = decoder().decode(issuer.issue())

        assertNotEquals(first.id, second.id)
        assertEquals(null, first.getClaim<Any>("scope"))
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
