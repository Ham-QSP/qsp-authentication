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

import org.junit.jupiter.api.Test
import org.mockito.ArgumentCaptor
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SmtpRegistrationMailerTest {
    private val sender = mock(JavaMailSender::class.java)
    private val messages = ResourceBundleMessageSource().apply { setBasenames("messages") }
    private val properties = MailProperties().apply { from = "noreply@qsp.test" }

    private fun mailer(available: JavaMailSender? = sender) =
        SmtpRegistrationMailer(
            object : ObjectProvider<JavaMailSender> {
                override fun getObject() = available ?: throw IllegalStateException()

                override fun getObject(vararg args: Any?) = getObject()

                override fun getIfAvailable() = available

                override fun getIfUnique() = available
            },
            messages,
            properties,
        )

    private fun sent(): SimpleMailMessage {
        val captor = ArgumentCaptor.forClass(SimpleMailMessage::class.java)
        verify(sender).send(captor.capture())
        return captor.value
    }

    @Test
    fun `the code mail contains the code, the callsign and its validity`() {
        mailer().sendCode("ham@example.org", "F4FEZ", "123456", 15)

        val mail = sent()
        assertEquals("ham@example.org", mail.to?.single())
        assertEquals("noreply@qsp.test", mail.from)
        assertContains(mail.text!!, "123456")
        assertContains(mail.text!!, "F4FEZ")
        assertContains(mail.text!!, "15")
    }

    @Test
    fun `the notice mail tells the owner that someone used the address`() {
        mailer().sendAddressInUse("ham@example.org")

        val mail = sent()
        assertEquals("ham@example.org", mail.to?.single())
        assertContains(mail.subject!!, "QSP")
    }

    @Test
    fun `sending without a configured mail server fails explicitly`() {
        assertFailsWith<IllegalStateException> { mailer(available = null).sendCode("a@b.c", "F4FEZ", "123456", 15) }
    }
}
