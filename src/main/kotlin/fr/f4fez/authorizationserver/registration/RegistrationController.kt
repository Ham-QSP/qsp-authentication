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
 * Self-registration pages, opened by anonymous visitors in the authentication popup.
 */
@Hidden
@Controller
@RequestMapping("/signup")
class RegistrationController(
    private val registrationService: RegistrationService,
    private val messageSource: MessageSource,
) {
    @GetMapping
    fun form(): ModelAndView = ModelAndView("signup")

    @PostMapping
    fun register(
        @RequestParam(defaultValue = "") callsign: String,
        @RequestParam(defaultValue = "") email: String,
        @RequestParam(defaultValue = "") password: String,
        @RequestParam(defaultValue = "") confirmPassword: String,
    ): ModelAndView {
        if (password != confirmPassword) {
            return formWithError(callsign, email, message("signup.error.mismatch"))
        }
        try {
            registrationService.request(callsign, email, password)
        } catch (e: ResponseStatusException) {
            return formWithError(callsign, email, e.reason)
        }
        return ModelAndView("redirect:/signup/verify").addObject("callsign", Usernames.normalize(callsign))
    }

    @GetMapping("/verify")
    fun verifyForm(
        @RequestParam(defaultValue = "") callsign: String,
    ): ModelAndView = ModelAndView("signup-verify").addObject("callsign", callsign)

    @PostMapping("/verify")
    fun verify(
        @RequestParam(defaultValue = "") callsign: String,
        @RequestParam(defaultValue = "") code: String,
    ): ModelAndView =
        when (val result = registrationService.verify(callsign, code)) {
            is VerifyResult.Created -> {
                ModelAndView("signup-done").addObject("callsign", result.callsign)
            }

            VerifyResult.Invalid -> {
                ModelAndView("signup-verify", HttpStatus.BAD_REQUEST)
                    .addObject("callsign", callsign)
                    .addObject("error", message("signup.verify.invalid"))
            }
        }

    @PostMapping("/resend")
    fun resend(
        @RequestParam(defaultValue = "") callsign: String,
    ): ModelAndView {
        registrationService.resend(callsign)
        // Same answer whether or not a registration is pending
        return ModelAndView("signup-verify")
            .addObject("callsign", callsign)
            .addObject("info", message("signup.verify.resent"))
    }

    private fun formWithError(
        callsign: String,
        email: String,
        error: String?,
    ): ModelAndView =
        ModelAndView("signup", HttpStatus.BAD_REQUEST)
            .addObject("callsign", callsign)
            .addObject("email", email)
            .addObject("error", error)

    private fun message(code: String): String = messageSource.getMessage(code, null, LocaleContextHolder.getLocale())
}
