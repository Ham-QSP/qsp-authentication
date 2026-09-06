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
package fr.f4fez.authorizationserver.user

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import java.time.LocalDateTime
import java.util.UUID

data class UserResponse(
    val id: UUID,
    val username: String,
    val email: String,
    val enabled: Boolean,
    val emailValidated: Boolean,
    val passwordExpiration: LocalDateTime?
) {
    companion object {
        fun from(user: User): UserResponse = UserResponse(
            id = requireNotNull(user.id),
            username = user.username,
            email = user.email,
            enabled = user.enabled,
            emailValidated = user.emailValidated,
            passwordExpiration = user.passwordExpiration
        )
    }
}

data class CreateUserRequest(
    @field:NotBlank
    @field:Size(max = 100)
    val username: String,

    @field:NotBlank
    @field:Size(max = 100)
    val password: String,

    @field:NotBlank
    @field:Email
    @field:Size(max = 320)
    val email: String,

    val enabled: Boolean = true
)

data class UpdateUserRequest(
    @field:NotBlank
    @field:Email
    @field:Size(max = 320)
    val email: String,

    val enabled: Boolean,

    @field:Size(max = 100)
    val password: String? = null
)
