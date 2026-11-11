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

import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.PostgreSQLContainer
import tools.jackson.databind.json.JsonMapper
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
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
class StationProvisionerTest {
    @Autowired
    lateinit var provisioner: StationProvisioner

    @Autowired
    lateinit var issuer: InternalTokenIssuer

    @Autowired
    lateinit var registrationService: RegistrationService

    @Autowired
    lateinit var mailer: RecordingRegistrationMailer

    @Autowired
    lateinit var mapper: JsonMapper

    private data class Call(
        val method: String,
        val path: String,
        val authorization: String?,
        val body: String,
    )

    @BeforeEach
    fun reset() {
        calls.clear()
        mailer.reset()
        respond = { _, _ -> 200 to "{}" }
    }

    @Test
    fun `a missing station is created with the user as owner`() {
        assertTrue(provisioner.provision("F4PVA"))

        val call = calls.single()
        assertEquals("POST", call.method)
        assertEquals("/station", call.path)
        assertTrue(call.authorization!!.startsWith("Bearer ey"))
        val body = mapper.readTree(call.body)
        assertEquals("F4PVA", body.get("mainQRZ").asString())
        assertEquals("", body.get("description").asString())
        assertEquals(
            "F4PVA",
            body
                .get("grants")
                .get(0)
                .get("subject")
                .asString(),
        )
        assertEquals(
            "OWNER",
            body
                .get("grants")
                .get(0)
                .get("role")
                .asString(),
        )
    }

    @Test
    fun `an existing station only gets the owner grant, with a fresh token`() {
        respond =
            { method, path ->
                if (path ==
                    "/station"
                ) {
                    409 to """{"message":"exists","stationId":"3f1c0000-0000-4000-8000-000000000001"}"""
                } else {
                    200 to
                        "{}"
                }
            }

        assertTrue(provisioner.provision("F4PVB"))

        assertEquals(listOf("/station", "/station/3f1c0000-0000-4000-8000-000000000001/grant"), calls.map { it.path })
        val grant = mapper.readTree(calls[1].body)
        assertEquals("F4PVB", grant.get("subject").asString())
        assertEquals("OWNER", grant.get("role").asString())
        assertNotEquals(calls[0].authorization, calls[1].authorization)
    }

    @Test
    fun `a signaling server error is reported but never thrown`() {
        respond = { _, _ -> 500 to "{}" }

        assertFalse(provisioner.provision("F4PVC"))
    }

    @Test
    fun `an unreachable signaling server is reported but never thrown`() {
        val unreachable =
            StationProvisioner(issuer, SignalingProperties().apply { baseUrl = "http://localhost:1" }, mapper)

        assertFalse(unreachable.provision("F4PVD"))
    }

    @Test
    fun `a validated registration provisions its station`() {
        registrationService.request("F4PVE", "pve@example.org", "Str0ng!Passw0rd")

        registrationService.verify("F4PVE", mailer.lastCodeFor("F4PVE")!!)

        assertEquals("F4PVE", mapper.readTree(calls.single().body).get("mainQRZ").asString())
    }

    @Test
    fun `the account is created even when signaling is down`() {
        respond = { _, _ -> 503 to "{}" }
        registrationService.request("F4PVF", "pvf@example.org", "Str0ng!Passw0rd")

        val result = registrationService.verify("F4PVF", mailer.lastCodeFor("F4PVF")!!)

        assertEquals(VerifyResult.Created("F4PVF"), result)
    }

    companion object {
        private val calls = CopyOnWriteArrayList<Call>()

        @Volatile
        private var respond: (String, String) -> Pair<Int, String> = { _, _ -> 200 to "{}" }

        private lateinit var signaling: HttpServer

        var postgres: PostgreSQLContainer<*> = PostgreSQLContainer("postgres:17-alpine")

        @BeforeAll
        @JvmStatic
        fun beforeAll() {
            postgres.start()
            signaling =
                HttpServer.create(InetSocketAddress("localhost", 0), 0).apply {
                    createContext("/") { exchange ->
                        val body = exchange.requestBody.readAllBytes().decodeToString()
                        val path = exchange.requestURI.path
                        calls +=
                            Call(exchange.requestMethod, path, exchange.requestHeaders.getFirst("Authorization"), body)
                        val (status, response) = respond(exchange.requestMethod, path)
                        exchange.responseHeaders.add("Content-Type", "application/json")
                        exchange.sendResponseHeaders(status, response.toByteArray().size.toLong())
                        exchange.responseBody.use { it.write(response.toByteArray()) }
                    }
                    start()
                }
        }

        @AfterAll
        @JvmStatic
        fun afterAll() {
            signaling.stop(0)
            postgres.stop()
        }

        @DynamicPropertySource
        @JvmStatic
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("qsp.signaling.base-url") { "http://localhost:${signaling.address.port}" }
        }
    }
}
