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

import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import tools.jackson.databind.json.JsonMapper
import java.net.http.HttpClient
import java.time.Duration

/**
 * Makes a new user OWNER of the station that has his callsign, creating the station when it does not exist.
 * Failures are logged and reported, never thrown: the account stays valid when signaling is unavailable.
 */
@Component
class StationProvisioner(
    private val tokenIssuer: InternalTokenIssuer,
    properties: SignalingProperties,
    private val mapper: JsonMapper,
) {
    private val logger = LoggerFactory.getLogger(StationProvisioner::class.java)

    private val client =
        RestClient
            .builder()
            .baseUrl(properties.baseUrl)
            .requestFactory(
                JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(TIMEOUT).build()).apply {
                    setReadTimeout(TIMEOUT)
                },
            ).build()

    private data class Response(
        val status: Int,
        val body: String,
    )

    fun provision(callsign: String): Boolean =
        try {
            val station =
                post(
                    "/station",
                    mapOf(
                        "mainQRZ" to callsign,
                        "description" to "",
                        "grants" to listOf(grant(callsign)),
                    ),
                )
            when {
                station.status in 200..299 -> {
                    true
                }

                station.status == CONFLICT -> {
                    val stationId = mapper.readTree(station.body).get("stationId").asString()
                    success(post("/station/$stationId/grant", grant(callsign)), callsign)
                }

                else -> {
                    success(station, callsign)
                }
            }
        } catch (e: Exception) {
            logger.warn("Station of {} could not be provisioned: {}", callsign, e.message)
            false
        }

    private fun grant(callsign: String) = mapOf("subject" to callsign, "role" to "OWNER")

    private fun success(
        response: Response,
        callsign: String,
    ): Boolean {
        if (response.status !in 200..299) {
            logger.warn("Station of {} could not be provisioned: signaling answered {}", callsign, response.status)
        }
        return response.status in 200..299
    }

    private fun post(
        path: String,
        body: Any,
    ): Response =
        client
            .post()
            .uri(path)
            .header(HttpHeaders.AUTHORIZATION, "Bearer ${tokenIssuer.issue()}")
            .contentType(MediaType.APPLICATION_JSON)
            .body(mapper.writeValueAsString(body))
            .exchange { _, response ->
                Response(response.statusCode.value(), response.body.readAllBytes().decodeToString())
            }

    private companion object {
        val TIMEOUT: Duration = Duration.ofSeconds(5)
        const val CONFLICT = 409
    }
}
