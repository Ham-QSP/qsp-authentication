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

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler

/**
 * Sends users whose password has expired to the password change page.
 * CredentialsExpiredException is only raised once the password has been verified, so the session
 * attribute proves that this session knows the expired password.
 */
class ExpiredPasswordAuthenticationFailureHandler : AuthenticationFailureHandler {
    companion object {
        const val EXPIRED_PASSWORD_USERNAME = "fr.f4fez.authorizationserver.EXPIRED_PASSWORD_USERNAME"
        private const val USERNAME_PARAMETER = "username"
    }

    private val defaultHandler = SimpleUrlAuthenticationFailureHandler("/login?error")
    private val redirectStrategy = DefaultRedirectStrategy()

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        if (exception !is CredentialsExpiredException) {
            defaultHandler.onAuthenticationFailure(request, response, exception)
            return
        }

        val session = request.getSession(true)
        request.changeSessionId()
        session.setAttribute(EXPIRED_PASSWORD_USERNAME, request.getParameter(USERNAME_PARAMETER))
        redirectStrategy.sendRedirect(request, response, "/password-expired")
    }
}
