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
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.stereotype.Component
import org.thymeleaf.ITemplateEngine
import org.thymeleaf.context.Context
import java.nio.charset.StandardCharsets
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
    private val templates: ITemplateEngine,
    private val properties: MailProperties,
) : RegistrationMailer {
    override fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    ) = send(
        email,
        "mail.code",
        "mail/code",
        mapOf("callsign" to callsign, "code" to code, "validMinutes" to validMinutes),
        callsign,
        code,
        validMinutes,
    )

    override fun sendAddressInUse(email: String) = send(email, "mail.taken", "mail/taken", emptyMap())

    /** Multipart mail: the plain text of the message bundle for text-only clients, the Thymeleaf template as HTML. */
    private fun send(
        to: String,
        key: String,
        template: String,
        variables: Map<String, Any>,
        vararg args: Any,
    ) {
        val sender =
            mailSender.getIfAvailable()
                ?: throw IllegalStateException("No mail server configured: set spring.mail.host")
        val html = templates.process(template, Context(Locale.ENGLISH, variables))
        val message = sender.createMimeMessage()
        MimeMessageHelper(message, true, StandardCharsets.UTF_8.name()).apply {
            setFrom(properties.from)
            setTo(to)
            setSubject(messages.getMessage("$key.subject", args, Locale.ENGLISH))
            setText(messages.getMessage("$key.body", args, Locale.ENGLISH), html)
        }
        sender.send(message)
    }
}
