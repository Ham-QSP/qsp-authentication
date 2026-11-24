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

import jakarta.mail.Multipart
import jakarta.mail.Part
import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import org.junit.jupiter.api.Test
import org.mockito.ArgumentCaptor
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.mail.javamail.JavaMailSender
import org.thymeleaf.spring6.SpringTemplateEngine
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver
import java.util.Properties
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SmtpRegistrationMailerTest {
    private val sender = mock(JavaMailSender::class.java)
    private val messages = ResourceBundleMessageSource().apply { setBasenames("messages") }
    private val properties = MailProperties().apply { from = "noreply@qsp.test" }
    private val templates =
        SpringTemplateEngine().apply {
            setTemplateResolver(
                ClassLoaderTemplateResolver().apply {
                    prefix = "templates/"
                    suffix = ".html"
                    characterEncoding = "UTF-8"
                },
            )
            setTemplateEngineMessageSource(messages)
        }

    init {
        `when`(sender.createMimeMessage()).thenAnswer { MimeMessage(Session.getInstance(Properties())) }
    }

    private fun mailer(available: JavaMailSender? = sender) =
        SmtpRegistrationMailer(
            MailDispatcher(
                object : ObjectProvider<JavaMailSender> {
                    override fun getObject() = available ?: throw IllegalStateException()

                    override fun getObject(vararg args: Any?) = getObject()

                    override fun getIfAvailable() = available

                    override fun getIfUnique() = available
                },
                messages,
                templates,
                properties,
            ),
        )

    private fun sent(): MimeMessage {
        val captor = ArgumentCaptor.forClass(MimeMessage::class.java)
        verify(sender).send(captor.capture())
        // What the real sender does before transport: it fixes the headers from the content
        return captor.value.apply { saveChanges() }
    }

    /** Text of the first body part of the given type, looking through nested multiparts. */
    private fun body(
        part: Part,
        type: String,
    ): String? {
        if (part.isMimeType(type)) return part.content as String
        val content = part.content as? Multipart ?: return null
        return (0 until content.count).firstNotNullOfOrNull { body(content.getBodyPart(it), type) }
    }

    @Test
    fun `the code mail contains the code, the callsign and its validity`() {
        mailer().sendCode("ham@example.org", "F4FEZ", "123456", 15)

        val mail = sent()
        assertEquals("ham@example.org", mail.allRecipients.single().toString())
        assertEquals("noreply@qsp.test", mail.from.single().toString())
        val text = body(mail, "text/plain")!!
        assertContains(text, "123456")
        assertContains(text, "F4FEZ")
        assertContains(text, "15")
    }

    @Test
    fun `the code mail also carries an HTML version rendered from the template`() {
        mailer().sendCode("ham@example.org", "F4FEZ", "123456", 15)

        val html = body(sent(), "text/html")!!
        assertContains(html, "123456")
        assertContains(html, "F4FEZ")
        assertContains(html, "15 minutes")
    }

    @Test
    fun `the HTML version escapes what it is given`() {
        mailer().sendCode("ham@example.org", "<b>F4FEZ</b>", "123456", 15)

        val html = body(sent(), "text/html")!!
        assertContains(html, "&lt;b&gt;F4FEZ&lt;/b&gt;")
    }

    @Test
    fun `the notice mail tells the owner that someone used the address`() {
        mailer().sendAddressInUse("ham@example.org")

        val mail = sent()
        assertEquals("ham@example.org", mail.allRecipients.single().toString())
        assertContains(mail.subject!!, "QSP")
        assertContains(body(mail, "text/html")!!, "already has an account")
    }

    @Test
    fun `sending without a configured mail server fails explicitly`() {
        assertFailsWith<IllegalStateException> { mailer(available = null).sendCode("a@b.c", "F4FEZ", "123456", 15) }
    }
}
