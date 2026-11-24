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

import fr.f4fez.authorizationserver.registration.MailDispatcher
import org.springframework.stereotype.Component

interface PasswordResetMailer {
    fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    )

    /** Tells the owner of the account that its password has just been changed. */
    fun sendPasswordChanged(
        email: String,
        callsign: String,
    )
}

@Component
class SmtpPasswordResetMailer(
    private val dispatcher: MailDispatcher,
) : PasswordResetMailer {
    override fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    ) = dispatcher.send(
        email,
        "mail.reset",
        "mail/reset-code",
        mapOf("callsign" to callsign, "code" to code, "validMinutes" to validMinutes),
        callsign,
        code,
        validMinutes,
    )

    override fun sendPasswordChanged(
        email: String,
        callsign: String,
    ) = dispatcher.send(
        email,
        "mail.changed",
        "mail/password-changed",
        mapOf("callsign" to callsign),
        callsign,
    )
}
