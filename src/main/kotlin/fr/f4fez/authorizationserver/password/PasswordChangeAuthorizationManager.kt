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
package fr.f4fez.authorizationserver.password

import fr.f4fez.authorizationserver.password.ExpiredPasswordAuthenticationFailureHandler.Companion.EXPIRED_PASSWORD_USERNAME
import org.springframework.security.authorization.AuthenticatedAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationResult
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import java.util.function.Supplier

/**
 * Opens the password change page to signed-in users, and to sessions that proved they know an expired password.
 * Anonymous users are denied, so they go through the login page and come back here.
 */
class PasswordChangeAuthorizationManager : AuthorizationManager<RequestAuthorizationContext> {
    private val authenticated = AuthenticatedAuthorizationManager.authenticated<RequestAuthorizationContext>()

    override fun authorize(
        authentication: Supplier<out Authentication?>,
        context: RequestAuthorizationContext,
    ): AuthorizationResult? {
        if (context.request.getSession(false)?.getAttribute(EXPIRED_PASSWORD_USERNAME) != null) {
            return AuthorizationDecision(true)
        }
        return authenticated.authorize(authentication, context)
    }
}
