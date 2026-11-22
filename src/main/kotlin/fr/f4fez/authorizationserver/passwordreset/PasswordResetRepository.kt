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

import org.springframework.data.jdbc.repository.query.Modifying
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.repository.CrudRepository
import java.time.LocalDateTime
import java.util.UUID

/**
 * Lookups take the username already normalized by [fr.f4fez.authorizationserver.user.Usernames].
 * Also keeps the send history used for the hourly limits, which outlives a replaced request.
 */
interface PasswordResetRepository : CrudRepository<PasswordReset, UUID> {
    @Query("select * from qsp_auth_password_resets where upper(username) = :username")
    fun findByNormalizedUsername(username: String): PasswordReset?

    /**
     * Stores the one pending request of the account, replacing the previous one. A single statement: parallel
     * requests for the same account cannot collide on the unique index.
     */
    @Modifying
    @Query(
        "insert into qsp_auth_password_resets (username, code_hash, code_expires_at, failed_attempts, last_sent_at, created_at) " +
            "values (:username, :codeHash, :codeExpiresAt, 0, :now, :now) " +
            "on conflict (upper(username)) do update set code_hash = excluded.code_hash, " +
            "code_expires_at = excluded.code_expires_at, failed_attempts = 0, " +
            "last_sent_at = excluded.last_sent_at, created_at = excluded.created_at",
    )
    fun replacePending(
        username: String,
        codeHash: String,
        codeExpiresAt: LocalDateTime,
        now: LocalDateTime,
    )

    /**
     * Atomically takes one verification attempt; false when the attempts are used up. Taken before the code is
     * checked, so parallel guesses cannot exceed the limit.
     */
    @Modifying
    @Query(
        "update qsp_auth_password_resets set failed_attempts = failed_attempts + 1 " +
            "where id = :id and failed_attempts < :maxAttempts",
    )
    fun reserveAttempt(
        id: UUID,
        maxAttempts: Int,
    ): Boolean

    @Modifying
    @Query("delete from qsp_auth_password_resets where id = :id and failed_attempts >= :maxAttempts")
    fun deleteIfAttemptsUsedUp(
        id: UUID,
        maxAttempts: Int,
    )

    @Modifying
    @Query("delete from qsp_auth_password_resets where created_at < :threshold")
    fun deleteCreatedBefore(threshold: LocalDateTime): Int

    @Modifying
    @Query("insert into qsp_auth_password_reset_sends (email, username, sent_at) values (:email, :username, :sentAt)")
    fun recordSend(
        email: String,
        username: String,
        sentAt: LocalDateTime,
    )

    @Query("select count(*) from qsp_auth_password_reset_sends where email = :email and sent_at > :since")
    fun countSendsByEmailSince(
        email: String,
        since: LocalDateTime,
    ): Int

    @Query("select count(*) from qsp_auth_password_reset_sends where username = :username and sent_at > :since")
    fun countSendsByUsernameSince(
        username: String,
        since: LocalDateTime,
    ): Int

    @Modifying
    @Query("delete from qsp_auth_password_reset_sends where sent_at < :threshold")
    fun deleteSendsBefore(threshold: LocalDateTime): Int
}
