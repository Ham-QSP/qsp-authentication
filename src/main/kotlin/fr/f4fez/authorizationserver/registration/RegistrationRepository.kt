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

import org.springframework.data.jdbc.repository.query.Modifying
import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.repository.CrudRepository
import java.time.LocalDateTime
import java.util.UUID

/**
 * Lookups take identifiers already normalized (callsign uppercase, email lowercase).
 * Also keeps the send history used for the hourly limits, which outlives a replaced registration.
 */
interface RegistrationRepository : CrudRepository<Registration, UUID> {
    @Query("select * from qsp_auth_registrations where upper(callsign) = :callsign")
    fun findByNormalizedCallsign(callsign: String): Registration?

    @Modifying
    @Query("delete from qsp_auth_registrations where upper(callsign) = :callsign or lower(email) = :email")
    fun deleteByCallsignOrEmail(
        callsign: String,
        email: String,
    )

    /**
     * Atomically takes one verification attempt; false when the attempts are used up. Taken before the code is
     * checked, so parallel guesses cannot exceed the limit.
     */
    @Modifying
    @Query(
        "update qsp_auth_registrations set failed_attempts = failed_attempts + 1 " +
            "where id = :id and failed_attempts < :maxAttempts",
    )
    fun reserveAttempt(
        id: UUID,
        maxAttempts: Int,
    ): Boolean

    @Modifying
    @Query("delete from qsp_auth_registrations where id = :id and failed_attempts >= :maxAttempts")
    fun deleteIfAttemptsUsedUp(
        id: UUID,
        maxAttempts: Int,
    )

    @Modifying
    @Query("delete from qsp_auth_registrations where created_at < :threshold")
    fun deleteCreatedBefore(threshold: LocalDateTime): Int

    @Modifying
    @Query("insert into qsp_auth_registration_sends (email, callsign, sent_at) values (:email, :callsign, :sentAt)")
    fun recordSend(
        email: String,
        callsign: String,
        sentAt: LocalDateTime,
    )

    @Query("select count(*) from qsp_auth_registration_sends where email = :email and sent_at > :since")
    fun countSendsByEmailSince(
        email: String,
        since: LocalDateTime,
    ): Int

    @Query("select count(*) from qsp_auth_registration_sends where callsign = :callsign and sent_at > :since")
    fun countSendsByCallsignSince(
        callsign: String,
        since: LocalDateTime,
    ): Int

    @Modifying
    @Query("delete from qsp_auth_registration_sends where sent_at < :threshold")
    fun deleteSendsBefore(threshold: LocalDateTime): Int
}
