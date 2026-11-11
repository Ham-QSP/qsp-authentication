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

import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.MessageSource
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.stereotype.Component
import java.util.Locale

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
    private val mailSender: ObjectProvider<JavaMailSender>,
    private val messages: MessageSource,
    private val properties: MailProperties,
) : RegistrationMailer {
    override fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    ) = send(email, "mail.code", callsign, code, validMinutes)

    override fun sendAddressInUse(email: String) = send(email, "mail.taken")

    private fun send(
        to: String,
        key: String,
        vararg args: Any,
    ) {
        val sender =
            mailSender.getIfAvailable()
                ?: throw IllegalStateException("No mail server configured: set spring.mail.host")
        sender.send(
            SimpleMailMessage().apply {
                from = properties.from
                setTo(to)
                subject = messages.getMessage("$key.subject", args, Locale.ENGLISH)
                text = messages.getMessage("$key.body", args, Locale.ENGLISH)
            },
        )
    }
}
