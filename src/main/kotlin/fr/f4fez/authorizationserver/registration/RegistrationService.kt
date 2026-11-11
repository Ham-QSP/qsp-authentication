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

import fr.f4fez.authorizationserver.user.Emails
import fr.f4fez.authorizationserver.user.PasswordPolicy
import fr.f4fez.authorizationserver.user.UserRepository
import fr.f4fez.authorizationserver.user.Usernames
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.server.ResponseStatusException
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime

/**
 * Self-registration: a request is kept in its own table until its email is validated with a code.
 * Rate-limited and unknown-registration cases return silently so the pages answer the same way every time.
 */
@Service
class RegistrationService(
    private val registrations: RegistrationRepository,
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val passwordPolicy: PasswordPolicy,
    private val mailer: RegistrationMailer,
    private val properties: RegistrationProperties,
    private val clock: Clock,
) {
    private val random = SecureRandom()

    @Transactional
    fun request(
        callsign: String,
        email: String,
        password: String,
    ) {
        val normalizedCallsign = Usernames.normalize(callsign)
        val normalizedEmail = Emails.normalize(email)
        if (!Callsigns.isValid(normalizedCallsign)) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "This is not a valid callsign")
        }
        if (userRepository.existsByNormalizedUsername(normalizedCallsign)) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "This callsign already has an account")
        }
        passwordPolicy.requireValid(normalizedCallsign, password)

        val now = now()
        if (userRepository.existsByNormalizedEmail(normalizedEmail)) {
            if (withinHourlyLimit(normalizedCallsign, normalizedEmail, now)) {
                mailer.sendAddressInUse(normalizedEmail)
                registrations.recordSend(normalizedEmail, normalizedCallsign, now)
            }
            return
        }
        if (!withinHourlyLimit(normalizedCallsign, normalizedEmail, now)) {
            return
        }

        registrations.deleteByCallsignOrEmail(normalizedCallsign, normalizedEmail)
        val code = newCode()
        registrations.save(
            Registration(
                callsign = normalizedCallsign,
                email = normalizedEmail,
                passwordHash = passwordEncoder.encode(password)!!,
                codeHash = passwordEncoder.encode(code)!!,
                codeExpiresAt = now.plus(properties.codeTtl),
                lastSentAt = now,
                createdAt = now,
            ),
        )
        sendCode(normalizedEmail, normalizedCallsign, code, now)
    }

    @Transactional
    fun resend(callsign: String) {
        val normalizedCallsign = Usernames.normalize(callsign)
        val registration = registrations.findByNormalizedCallsign(normalizedCallsign) ?: return
        val now = now()
        if (registration.lastSentAt.plus(properties.resendInterval).isAfter(now) ||
            !withinHourlyLimit(registration.callsign, registration.email, now)
        ) {
            return
        }

        val code = newCode()
        registrations.save(
            registration.copy(
                codeHash = passwordEncoder.encode(code)!!,
                codeExpiresAt = now.plus(properties.codeTtl),
                failedAttempts = 0,
                lastSentAt = now,
            ),
        )
        sendCode(registration.email, registration.callsign, code, now)
    }

    @Transactional
    fun purgeExpired() {
        val threshold = now().minus(properties.retention)
        registrations.deleteCreatedBefore(threshold)
        registrations.deleteSendsBefore(threshold)
    }

    private fun sendCode(
        email: String,
        callsign: String,
        code: String,
        now: LocalDateTime,
    ) {
        mailer.sendCode(email, callsign, code, properties.codeTtl.toMinutes())
        registrations.recordSend(email, callsign, now)
    }

    private fun withinHourlyLimit(
        callsign: String,
        email: String,
        now: LocalDateTime,
    ): Boolean {
        val since = now.minus(Duration.ofHours(1))
        return registrations.countSendsByEmailSince(email, since) < properties.maxSendsPerHour &&
            registrations.countSendsByCallsignSince(callsign, since) < properties.maxSendsPerHour
    }

    private fun newCode(): String = "%06d".format(random.nextInt(1_000_000))

    private fun now(): LocalDateTime = LocalDateTime.now(clock)
}
