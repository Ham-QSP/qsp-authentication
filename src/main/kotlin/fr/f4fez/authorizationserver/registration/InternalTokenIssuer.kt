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

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Duration
import java.util.UUID

/**
 * Forges the short-lived token this server presents to the signaling service. It is signed with the key of the
 * access tokens but has no scope and no audience, so this server's own APIs do not accept it.
 */
@Component
class InternalTokenIssuer(
    jwkSource: JWKSource<SecurityContext>,
    private val properties: SignalingProperties,
    private val clock: Clock,
) {
    companion object {
        val LIFETIME: Duration = Duration.ofSeconds(15)
        const val ROLE = "SYS_AUTH"
    }

    private val encoder = NimbusJwtEncoder(jwkSource)

    fun issue(): String {
        val now = clock.instant()
        val claims =
            JwtClaimsSet
                .builder()
                .issuer(properties.issuer)
                .subject(properties.subject)
                .id(UUID.randomUUID().toString())
                .issuedAt(now)
                .expiresAt(now.plus(LIFETIME))
                .claim("roles", listOf(ROLE))
                .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).build()
        return encoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }
}
