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

/** Sends the multipart mails of the authentication server, shared by the registration and password reset mailers. */
@Component
class MailDispatcher(
    private val mailSender: ObjectProvider<JavaMailSender>,
    private val messages: MessageSource,
    private val templates: ITemplateEngine,
    private val properties: MailProperties,
) {
    /** Multipart mail: the plain text of the message bundle for text-only clients, the Thymeleaf template as HTML. */
    fun send(
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
