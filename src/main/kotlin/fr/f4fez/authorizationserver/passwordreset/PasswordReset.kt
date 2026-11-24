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

import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table
import java.time.LocalDateTime
import java.util.UUID

/** A pending request to reset the password of an account: the emailed code is only kept hashed. */
@Table("qsp_auth_password_resets")
data class PasswordReset(
    @Id
    val id: UUID? = null,
    val username: String,
    val codeHash: String,
    val codeExpiresAt: LocalDateTime,
    val failedAttempts: Int = 0,
    val lastSentAt: LocalDateTime,
    val createdAt: LocalDateTime,
)
