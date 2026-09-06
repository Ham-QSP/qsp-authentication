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

import org.springframework.http.HttpStatus
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import java.util.UUID

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {

    fun findAll(): List<User> = userRepository.findAll().toList()

    fun findById(id: UUID): User = userRepository.findById(id)
        .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND, "User '$id' not found") }

    fun findByUsername(username: String): User = userRepository.findByUsername(username)
        ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User '$username' not found")

    fun create(request: CreateUserRequest): User {
        if (userRepository.existsByUsername(request.username)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Username '${request.username}' is already taken")
        }
        if (userRepository.existsByEmail(request.email)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Email '${request.email}' is already used")
        }

        val user = User(
            username = request.username,
            password = passwordEncoder.encode(request.password)!!,
            enabled = request.enabled,
            email = request.email,
            emailValidated = false
        )
        return userRepository.save(user)
    }

    fun update(id: UUID, request: UpdateUserRequest): User {
        val existing = findById(id)
        if (existing.email != request.email && userRepository.existsByEmail(request.email)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Email '${request.email}' is already used")
        }

        val updated = existing.copy(
            email = request.email,
            enabled = request.enabled,
            password = request.password?.let { passwordEncoder.encode(it)!! } ?: existing.password
        )
        return userRepository.save(updated)
    }

    fun delete(id: UUID) {
        if (!userRepository.existsById(id)) {
            throw ResponseStatusException(HttpStatus.NOT_FOUND, "User '$id' not found")
        }
        userRepository.deleteById(id)
    }
}
