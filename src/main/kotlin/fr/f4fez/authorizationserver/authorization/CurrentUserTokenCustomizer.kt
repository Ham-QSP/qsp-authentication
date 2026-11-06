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
package fr.f4fez.authorizationserver.authorization

import fr.f4fez.authorizationserver.user.UserService
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import java.time.LocalDateTime
import java.time.ZoneId

/**
 * Builds access tokens from the current user rather than from the authentication saved at login, which a
 * refresh token replays for its whole lifetime. A user who was disabled, deleted, whose password expired or
 * changed since the login gets no new access token, and roles always reflect the database.
 */
class CurrentUserTokenCustomizer(
    private val userService: UserService,
) : OAuth2TokenCustomizer<JwtEncodingContext> {
    override fun customize(context: JwtEncodingContext) {
        if (OAuth2TokenType.ACCESS_TOKEN != context.tokenType) {
            return
        }
        val principal = context.getPrincipal<Authentication>() ?: throw invalidGrant()
        val user = userService.findByUsernameOrNull(principal.name) ?: throw invalidGrant()

        val now = LocalDateTime.now()
        val passwordExpired = user.passwordExpiration?.isAfter(now) == false
        val passwordChangedSinceLogin =
            user.passwordChangedAt?.let { changedAt ->
                val authenticatedAt = passwordAuthenticationTime(principal) ?: return@let false
                changedAt.atZone(ZoneId.systemDefault()).toInstant().isAfter(authenticatedAt)
            } == true
        if (!user.enabled || passwordExpired || passwordChangedSinceLogin) {
            throw invalidGrant()
        }

        context.claims.claim("roles", user.roles.map { it.removePrefix("ROLE_") }.toSet())
    }

    private fun passwordAuthenticationTime(principal: Authentication) =
        principal.authorities
            .filterIsInstance<FactorGrantedAuthority>()
            .firstOrNull { it.authority == FactorGrantedAuthority.PASSWORD_AUTHORITY }
            ?.issuedAt

    private fun invalidGrant() =
        OAuth2AuthenticationException(
            OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "The user can no longer obtain tokens", null),
        )
}
