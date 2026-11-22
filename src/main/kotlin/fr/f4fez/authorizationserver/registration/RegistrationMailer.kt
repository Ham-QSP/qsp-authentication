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

import org.springframework.stereotype.Component

interface RegistrationMailer {
    fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    )

    /** Tells the owner of an existing account that someone tried to register with the address. */
    fun sendAddressInUse(email: String)
}

@Component
class SmtpRegistrationMailer(
    private val dispatcher: MailDispatcher,
) : RegistrationMailer {
    override fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    ) = dispatcher.send(
        email,
        "mail.code",
        "mail/code",
        mapOf("callsign" to callsign, "code" to code, "validMinutes" to validMinutes),
        callsign,
        code,
        validMinutes,
    )

    override fun sendAddressInUse(email: String) = dispatcher.send(email, "mail.taken", "mail/taken", emptyMap())
}
