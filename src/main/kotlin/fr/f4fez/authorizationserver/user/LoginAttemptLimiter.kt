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

import fr.f4fez.authorizationserver.config.LoginThrottlingProperties
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Counts failed password checks per username and locks the username once too many failed in a row.
 * The lock lasts [LoginThrottlingProperties.lockDuration] after the last failure. Unknown usernames are
 * counted too, so that a lock does not reveal whether an account exists.
 */
@Component
class LoginAttemptLimiter(
    private val properties: LoginThrottlingProperties,
    private val clock: Clock,
) {
    companion object {
        private const val PURGE_THRESHOLD = 10_000
    }

    private data class Failures(
        val count: Int,
        val expiresAt: Instant,
    )

    private val failures = ConcurrentHashMap<String, Failures>()

    fun isLocked(username: String): Boolean {
        val current = failures[username] ?: return false
        return current.count >= properties.maxFailures && current.expiresAt.isAfter(clock.instant())
    }

    fun recordFailure(username: String) {
        val now = clock.instant()
        if (failures.size > PURGE_THRESHOLD) {
            failures.values.removeIf { !it.expiresAt.isAfter(now) }
        }
        failures.compute(username) { _, current ->
            val previousCount = current?.takeIf { it.expiresAt.isAfter(now) }?.count ?: 0
            Failures(previousCount + 1, now.plus(properties.lockDuration))
        }
    }

    fun recordSuccess(username: String) {
        failures.remove(username)
    }
}
