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
import fr.f4fez.authorizationserver.user.ChangePasswordRequest
import fr.f4fez.authorizationserver.user.UserService
import io.swagger.v3.oas.annotations.Hidden
import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.MessageSource
import org.springframework.context.i18n.LocaleContextHolder
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.server.ResponseStatusException
import org.springframework.web.servlet.ModelAndView

/**
 * Password change page, used both after a login with an expired password and by signed-in users.
 * The expired flow takes precedence: its user already proved the current password at login.
 */
@Hidden
@Controller
@RequestMapping("/password")
class PasswordChangeController(
    private val userService: UserService,
    private val messageSource: MessageSource,
) {
    private data class PasswordChange(
        val username: String,
        val expired: Boolean,
    )

    @GetMapping
    fun form(
        request: HttpServletRequest,
        authentication: Authentication?,
    ): ModelAndView {
        val change = passwordChange(request, authentication) ?: return redirectToLogin()
        return formView(change, null, HttpStatus.OK)
    }

    @PostMapping
    fun change(
        request: HttpServletRequest,
        authentication: Authentication?,
        @RequestParam(defaultValue = "") currentPassword: String,
        @RequestParam newPassword: String,
        @RequestParam confirmPassword: String,
    ): ModelAndView {
        val change = passwordChange(request, authentication) ?: return redirectToLogin()

        val error = validate(change, currentPassword, newPassword, confirmPassword)
        if (error != null) {
            return formView(change, error, HttpStatus.BAD_REQUEST)
        }

        try {
            if (change.expired) {
                userService.renewExpiredPassword(change.username, newPassword)
            } else {
                userService.changePassword(change.username, ChangePasswordRequest(currentPassword, newPassword))
            }
        } catch (e: ResponseStatusException) {
            return formView(change, e.reason, HttpStatus.valueOf(e.statusCode.value()))
        }

        if (change.expired) {
            request.getSession(false)?.removeAttribute(EXPIRED_PASSWORD_USERNAME)
        }
        return ModelAndView("password-changed", HttpStatus.OK).addObject("expired", change.expired)
    }

    private fun passwordChange(
        request: HttpServletRequest,
        authentication: Authentication?,
    ): PasswordChange? {
        val expiredUsername = request.getSession(false)?.getAttribute(EXPIRED_PASSWORD_USERNAME) as String?
        return when {
            expiredUsername != null -> PasswordChange(expiredUsername, expired = true)
            authentication != null -> PasswordChange(authentication.name, expired = false)
            else -> null
        }
    }

    private fun validate(
        change: PasswordChange,
        currentPassword: String,
        newPassword: String,
        confirmPassword: String,
    ): String? =
        when {
            !change.expired && currentPassword.isBlank() -> message("password.error.current-required")
            newPassword.isBlank() -> message("password.error.required")
            newPassword != confirmPassword -> message("password.error.mismatch")
            else -> null
        }

    private fun message(code: String): String = messageSource.getMessage(code, null, LocaleContextHolder.getLocale())

    private fun redirectToLogin(): ModelAndView = ModelAndView("redirect:/login")

    private fun formView(
        change: PasswordChange,
        error: String?,
        status: HttpStatus,
    ): ModelAndView =
        ModelAndView("password", status).apply {
            addObject("username", change.username)
            addObject("expired", change.expired)
            addObject("error", error)
        }
}
