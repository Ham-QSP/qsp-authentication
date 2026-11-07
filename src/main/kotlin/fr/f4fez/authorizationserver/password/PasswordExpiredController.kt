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
import fr.f4fez.authorizationserver.user.UserService
import io.swagger.v3.oas.annotations.Hidden
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.MessageSource
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.servlet.ModelAndView

@Hidden
@Controller
@RequestMapping("/password-expired")
class PasswordExpiredController(
    private val userService: UserService,
    private val messageSource: MessageSource,
) {
    @GetMapping
    fun form(request: HttpServletRequest): ModelAndView {
        val username = expiredUsername(request) ?: return redirectToLogin()
        return formView(username, null, HttpStatus.OK)
    }

    @PostMapping
    fun change(
        request: HttpServletRequest,
        @RequestParam newPassword: String,
        @RequestParam confirmPassword: String,
    ): ModelAndView {
        val username = expiredUsername(request) ?: return redirectToLogin()

        val error = validate(newPassword, confirmPassword)
        if (error != null) {
            return formView(username, error, HttpStatus.BAD_REQUEST)
        }

        try {
            userService.renewExpiredPassword(username, newPassword)
        } catch (e: ResponseStatusException) {
            return formView(username, e.reason, HttpStatus.valueOf(e.statusCode.value()))
        }

        request.getSession(false)?.removeAttribute(EXPIRED_PASSWORD_USERNAME)
        return ModelAndView("password-changed", HttpStatus.OK)
    }

    private fun expiredUsername(request: HttpServletRequest): String? =
        request.getSession(false)?.getAttribute(EXPIRED_PASSWORD_USERNAME) as String?

    private fun validate(
        newPassword: String,
        confirmPassword: String,
    ): String? =
        when {
            newPassword.isBlank() -> message("password-expired.error.required")
            newPassword != confirmPassword -> message("password-expired.error.mismatch")
            else -> null
        }

    private fun message(code: String): String = messageSource.getMessage(code, null, LocaleContextHolder.getLocale())

    private fun redirectToLogin(): ModelAndView = ModelAndView("redirect:/login")

    private fun formView(
        username: String,
        error: String?,
        status: HttpStatus,
    ): ModelAndView =
        ModelAndView("password-expired", status).apply {
            addObject("username", username)
            addObject("error", error)
        }
}
