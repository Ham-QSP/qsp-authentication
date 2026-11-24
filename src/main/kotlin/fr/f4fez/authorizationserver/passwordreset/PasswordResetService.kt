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

import fr.f4fez.authorizationserver.authentication.LoginAttemptLimiter
import fr.f4fez.authorizationserver.user.PasswordPolicy
import fr.f4fez.authorizationserver.user.UserRepository
import fr.f4fez.authorizationserver.user.UserService
import fr.f4fez.authorizationserver.user.Usernames
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.transaction.support.TransactionSynchronization
import org.springframework.transaction.support.TransactionSynchronizationManager
import java.security.SecureRandom
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

sealed interface ResetResult {
    data object Done : ResetResult

    /** Wrong code, unknown, expired, used-up or ineligible account: deliberately not told apart. */
    data object Invalid : ResetResult
}

/**
 * Password reset by emailed code. Nothing here tells an existing account from an unknown one: the unknown,
 * ineligible, throttled and mail-failing cases return silently after the same amount of work.
 */
@Service
class PasswordResetService(
    private val users: UserRepository,
    private val userService: UserService,
    private val passwordEncoder: PasswordEncoder,
    private val passwordPolicy: PasswordPolicy,
    private val resets: PasswordResetRepository,
    private val mailer: PasswordResetMailer,
    private val loginAttemptLimiter: LoginAttemptLimiter,
    private val properties: PasswordResetProperties,
    private val clock: Clock,
    @Qualifier(PasswordResetConfiguration.MAIL_EXECUTOR) private val mailExecutor: Executor,
) {
    private val logger = LoggerFactory.getLogger(PasswordResetService::class.java)
    private val random = SecureRandom()

    /** Compared against when there is nothing to check, so that a probe costs the same hashing either way. */
    private val dummyHash by lazy { passwordEncoder.encode("not-a-real-password")!! }

    @Transactional
    fun request(callsign: String) {
        val username = Usernames.normalize(callsign)
        val user = users.findByNormalizedUsername(username)
        // Same hashing cost whether or not a code is stored, so the response time does not tell
        val code = newCode()
        val codeHash = passwordEncoder.encode(code)!!
        if (user == null || !user.enabled || !user.emailValidated) {
            return
        }
        val now = now()
        if (!withinHourlyLimit(username, user.email, now)) {
            return
        }
        resets.replacePending(username, codeHash, now.plus(properties.codeTtl), now)
        sendCode(user.email, username, code, now)
    }

    @Transactional
    fun resend(callsign: String) {
        val username = Usernames.normalize(callsign)
        val reset = resets.findByNormalizedUsername(username)
        val user = users.findByNormalizedUsername(username)
        if (reset == null || user == null) {
            passwordEncoder.encode(newCode())
            return
        }
        val now = now()
        if (reset.lastSentAt.plus(properties.resendInterval).isAfter(now) ||
            !withinHourlyLimit(username, user.email, now)
        ) {
            logger.info("Password reset resend for {} skipped: throttled", username)
            return
        }

        val code = newCode()
        resets.save(
            reset.copy(
                codeHash = passwordEncoder.encode(code)!!,
                codeExpiresAt = now.plus(properties.codeTtl),
                failedAttempts = 0,
                lastSentAt = now,
            ),
        )
        sendCode(user.email, username, code, now)
    }

    /**
     * Not transactional as a whole: a wrong attempt must stay counted. The password policy is checked first,
     * so a weak password neither consumes an attempt nor gives anything away.
     */
    fun reset(
        callsign: String,
        code: String,
        newPassword: String,
    ): ResetResult {
        val username = Usernames.normalize(callsign)
        passwordPolicy.requireValid(username, newPassword)
        val reset = resets.findByNormalizedUsername(username)
        if (reset == null || reset.codeExpiresAt.isBefore(now())) {
            return invalidAfterHashing(code)
        }
        val id = reset.id!!
        if (!resets.reserveAttempt(id, properties.maxAttempts)) {
            return invalidAfterHashing(code)
        }
        if (!passwordEncoder.matches(code.trim(), reset.codeHash)) {
            resets.deleteIfAttemptsUsedUp(id, properties.maxAttempts)
            return ResetResult.Invalid
        }
        val user = users.findByNormalizedUsername(username)
        if (user == null || !user.enabled || !user.emailValidated) {
            resets.delete(reset)
            return ResetResult.Invalid
        }

        userService.resetPassword(user.username, newPassword)
        resets.delete(reset)
        loginAttemptLimiter.recordSuccess(username)
        deliver("Password changed notice for $username") { mailer.sendPasswordChanged(user.email, user.username) }
        return ResetResult.Done
    }

    private fun invalidAfterHashing(code: String): ResetResult {
        passwordEncoder.matches(code.trim(), dummyHash)
        return ResetResult.Invalid
    }

    /** Runs the mail after the surrounding transaction commits, on the mail executor; a failure only gets logged. */
    private fun deliver(
        description: String,
        send: () -> Unit,
    ) {
        val task =
            Runnable {
                try {
                    send()
                } catch (e: Exception) {
                    logger.warn("{} could not be mailed: {}", description, e.message)
                }
            }
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(
                object : TransactionSynchronization {
                    override fun afterCommit() = submit(description, task)
                },
            )
        } else {
            submit(description, task)
        }
    }

    private fun submit(
        description: String,
        task: Runnable,
    ) {
        try {
            mailExecutor.execute(task)
        } catch (e: RejectedExecutionException) {
            logger.warn("{} dropped: the mail queue is full", description)
        }
    }

    @Transactional
    fun purgeExpired() {
        val threshold = now().minus(properties.retention)
        resets.deleteCreatedBefore(threshold)
        resets.deleteSendsBefore(threshold)
    }

    private fun sendCode(
        email: String,
        username: String,
        code: String,
        now: LocalDateTime,
    ) {
        // Counted before the mail goes out: an outage must not lift the hourly limit
        resets.recordSend(email, username, now)
        deliver("Password reset code for $username") {
            mailer.sendCode(email, username, code, properties.codeTtl.toMinutes())
        }
    }

    private fun withinHourlyLimit(
        username: String,
        email: String,
        now: LocalDateTime,
    ): Boolean {
        val since = now.minus(Duration.ofHours(1))
        return resets.countSendsByEmailSince(email, since) < properties.maxSendsPerHour &&
            resets.countSendsByUsernameSince(username, since) < properties.maxSendsPerHour
    }

    private fun newCode(): String = "%06d".format(random.nextInt(1_000_000))

    private fun now(): LocalDateTime = LocalDateTime.now(clock)
}
