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

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint

/**
 * Sends an anonymous authorization request to the login page, or to the signup page when the client
 * asked for it with `prompt=create` (OpenID Connect initiating user registration). The authorization
 * request is saved in the session either way, so the sign-in that follows the signup resumes it.
 */
class PromptAwareLoginUrlAuthenticationEntryPoint(
    loginFormUrl: String,
    private val signupUrl: String,
) : LoginUrlAuthenticationEntryPoint(loginFormUrl) {
    override fun determineUrlToUseForThisRequest(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ): String =
        if (request.getParameter("prompt")?.split(' ')?.contains("create") == true) {
            signupUrl
        } else {
            super.determineUrlToUseForThisRequest(request, response, exception)
        }
}
