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

import fr.f4fez.authorizationserver.user.ExpiredPasswordAuthenticationFailureHandler.Companion.EXPIRED_PASSWORD_USERNAME
import io.swagger.v3.oas.annotations.Hidden
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.util.HtmlUtils
import java.net.URI

@Hidden
@Controller
@RequestMapping("/password-expired")
class PasswordExpiredController(
    private val userService: UserService,
) {
    companion object {
        private const val BCRYPT_MAX_BYTES = 72
    }

    @GetMapping
    fun form(request: HttpServletRequest): ResponseEntity<String> {
        val username = expiredUsername(request) ?: return redirectToLogin()
        return html(HttpStatus.OK, formPage(request, username, null))
    }

    @PostMapping
    fun change(
        request: HttpServletRequest,
        @RequestParam newPassword: String,
        @RequestParam confirmPassword: String,
    ): ResponseEntity<String> {
        val username = expiredUsername(request) ?: return redirectToLogin()

        val error = validate(newPassword, confirmPassword)
        if (error != null) {
            return html(HttpStatus.BAD_REQUEST, formPage(request, username, error))
        }

        try {
            userService.renewExpiredPassword(username, newPassword)
        } catch (e: ResponseStatusException) {
            return html(HttpStatus.valueOf(e.statusCode.value()), formPage(request, username, e.reason))
        }

        request.getSession(false)?.removeAttribute(EXPIRED_PASSWORD_USERNAME)
        return html(HttpStatus.OK, page("<p>Your password has been changed.</p><a href=\"/login\">Sign in</a>"))
    }

    private fun expiredUsername(request: HttpServletRequest): String? =
        request.getSession(false)?.getAttribute(EXPIRED_PASSWORD_USERNAME) as String?

    private fun validate(
        newPassword: String,
        confirmPassword: String,
    ): String? =
        when {
            newPassword.isBlank() -> "The new password is required"
            newPassword != confirmPassword -> "The passwords do not match"
            newPassword.toByteArray().size > BCRYPT_MAX_BYTES -> "The new password is too long"
            else -> null
        }

    private fun redirectToLogin(): ResponseEntity<String> =
        ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/login"))
            .build()

    private fun html(
        status: HttpStatus,
        body: String,
    ): ResponseEntity<String> =
        ResponseEntity
            .status(status)
            .contentType(MediaType.TEXT_HTML)
            .body(body)

    private fun formPage(
        request: HttpServletRequest,
        username: String,
        error: String?,
    ): String {
        val csrf = request.getAttribute(CsrfToken::class.java.name) as CsrfToken
        val errorMessage = error?.let { "<p role=\"alert\">${HtmlUtils.htmlEscape(it)}</p>" }.orEmpty()
        return page(
            """
            <h1>Password expired</h1>
            <p>The password of ${HtmlUtils.htmlEscape(username)} has expired. Choose a new one.</p>
            $errorMessage
            <form method="post" action="/password-expired">
              <p><label>New password <input type="password" name="newPassword" autocomplete="new-password" required autofocus></label></p>
              <p><label>Confirm password <input type="password" name="confirmPassword" autocomplete="new-password" required></label></p>
              <input name="${HtmlUtils.htmlEscape(
                csrf.parameterName,
            )}" type="hidden" value="${HtmlUtils.htmlEscape(csrf.token)}">
              <button type="submit">Change password</button>
            </form>
            """.trimIndent(),
        )
    }

    private fun page(content: String): String =
        """
        <!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Password expired</title></head>
        <body>
        $content
        </body>
        </html>
        """.trimIndent()
}
