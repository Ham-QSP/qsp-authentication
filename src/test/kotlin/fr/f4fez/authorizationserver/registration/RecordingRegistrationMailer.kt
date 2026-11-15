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

import org.springframework.context.annotation.Primary
import org.springframework.stereotype.Component
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Replaces SMTP in every Spring test: records what would have been sent.
 */
@Primary
@Component
class RecordingRegistrationMailer : RegistrationMailer {
    data class Code(
        val email: String,
        val callsign: String,
        val code: String,
    )

    val codes = CopyOnWriteArrayList<Code>()
    val notices = CopyOnWriteArrayList<String>()

    override fun sendCode(
        email: String,
        callsign: String,
        code: String,
        validMinutes: Long,
    ) {
        codes += Code(email, callsign, code)
    }

    override fun sendAddressInUse(email: String) {
        notices += email
    }

    fun lastCodeFor(callsign: String): String? = codes.lastOrNull { it.callsign == callsign }?.code

    fun reset() {
        codes.clear()
        notices.clear()
    }
}
