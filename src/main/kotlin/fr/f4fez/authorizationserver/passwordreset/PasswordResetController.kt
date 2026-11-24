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
package fr.f4fez.authorizationserver.passwordreset

import fr.f4fez.authorizationserver.user.Usernames
import io.swagger.v3.oas.annotations.Hidden
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

/**
 * Forgotten password pages, opened by anonymous visitors in the authentication popup.
 */
@Hidden
@Controller
@RequestMapping("/password/forgot")
class PasswordResetController(
    private val service: PasswordResetService,
    private val messageSource: MessageSource,
) {
    @GetMapping
    fun form(): ModelAndView = ModelAndView("forgot")

    @PostMapping
    fun request(
        @RequestParam(defaultValue = "") callsign: String,
    ): ModelAndView {
        service.request(callsign)
        // Same redirect whether or not the callsign has an account
        return ModelAndView("redirect:/password/forgot/verify").addObject("callsign", Usernames.normalize(callsign))
    }

    @GetMapping("/verify")
    fun verifyForm(
        @RequestParam(defaultValue = "") callsign: String,
    ): ModelAndView = ModelAndView("forgot-verify").addObject("callsign", callsign)

    @PostMapping("/verify")
    fun verify(
        @RequestParam(defaultValue = "") callsign: String,
        @RequestParam(defaultValue = "") code: String,
        @RequestParam(defaultValue = "") password: String,
        @RequestParam(defaultValue = "") confirmPassword: String,
    ): ModelAndView {
        if (password != confirmPassword) {
            return verifyFormWithError(callsign, message("signup.error.mismatch"))
        }
        val result =
            try {
                service.reset(callsign, code, password)
            } catch (e: ResponseStatusException) {
                return verifyFormWithError(callsign, e.reason)
            }
        return when (result) {
            ResetResult.Done -> ModelAndView("forgot-done")
            ResetResult.Invalid -> verifyFormWithError(callsign, message("forgot.verify.invalid"))
        }
    }

    @PostMapping("/resend")
    fun resend(
        @RequestParam(defaultValue = "") callsign: String,
    ): ModelAndView {
        service.resend(callsign)
        // Same answer whether or not a request is pending
        return ModelAndView("forgot-verify")
            .addObject("callsign", callsign)
            .addObject("info", message("forgot.verify.resent"))
    }

    private fun verifyFormWithError(
        callsign: String,
        error: String?,
    ): ModelAndView =
        ModelAndView("forgot-verify", HttpStatus.BAD_REQUEST)
            .addObject("callsign", callsign)
            .addObject("error", error)

    private fun message(code: String): String = messageSource.getMessage(code, null, LocaleContextHolder.getLocale())
}
