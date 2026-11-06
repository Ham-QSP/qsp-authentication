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
package fr.f4fez.authorizationserver.authentication

import fr.f4fez.authorizationserver.config.LoginThrottlingProperties
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LoginAttemptLimiterTest {
    private class MutableClock(
        var now: Instant = Instant.parse("2026-01-01T00:00:00Z"),
    ) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC

        override fun withZone(zone: ZoneId): Clock = this

        override fun instant(): Instant = now
    }

    private val clock = MutableClock()

    private val limiter =
        LoginAttemptLimiter(
            LoginThrottlingProperties().apply {
                maxFailures = 3
                lockDuration = Duration.ofMinutes(10)
            },
            clock,
        )

    private fun fail(
        username: String,
        times: Int,
    ) = repeat(times) { limiter.recordFailure(username) }

    @Test
    fun `account is not locked below the failure threshold`() {
        fail("alice", 2)

        assertFalse(limiter.isLocked("alice"))
    }

    @Test
    fun `account is locked once the failure threshold is reached`() {
        fail("alice", 3)

        assertTrue(limiter.isLocked("alice"))
    }

    @Test
    fun `lock only applies to the failing username`() {
        fail("alice", 3)

        assertFalse(limiter.isLocked("bob"))
    }

    @Test
    fun `lock is lifted after the lock duration`() {
        fail("alice", 3)

        clock.now = clock.now.plus(Duration.ofMinutes(10))

        assertFalse(limiter.isLocked("alice"))
    }

    @Test
    fun `failures older than the lock duration are forgotten`() {
        fail("alice", 2)
        clock.now = clock.now.plus(Duration.ofMinutes(10))

        fail("alice", 1)

        assertFalse(limiter.isLocked("alice"))
    }

    @Test
    fun `success resets the failure count`() {
        fail("alice", 2)
        limiter.recordSuccess("alice")

        fail("alice", 2)

        assertFalse(limiter.isLocked("alice"))
    }
}
