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

import fr.f4fez.authorizationserver.config.PasswordPolicyProperties
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.web.server.ResponseStatusException
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PasswordPolicyTest {
    private fun policy(configure: PasswordPolicyProperties.() -> Unit = {}) =
        PasswordPolicy(PasswordPolicyProperties().apply(configure))

    private fun assertRejected(
        policy: PasswordPolicy,
        password: String,
        expectedMessage: String,
    ) {
        val exception =
            assertFailsWith<ResponseStatusException> { policy.requireValid("someone", password) }

        assertEquals(HttpStatus.BAD_REQUEST, exception.statusCode)
        assertContains(exception.reason.orEmpty(), expectedMessage)
    }

    @Test
    fun `a password matching every default rule is accepted`() {
        policy().requireValid("someone", "Correct-Horse-7")
    }

    @Test
    fun `default policy rejects a short password`() {
        assertRejected(policy(), "Ab-1", "12 or more characters")
    }

    @Test
    fun `configured minimum length is applied`() {
        assertRejected(policy { minLength = 20 }, "Correct-Horse-7", "20 or more characters")
    }

    @Test
    fun `configured maximum length is applied`() {
        assertRejected(policy { maxLength = 14 }, "Correct-Horse-7", "no more than 14 characters")
    }

    @Test
    fun `a missing uppercase is rejected`() {
        assertRejected(policy(), "correct-horse-7", "uppercase")
    }

    @Test
    fun `a missing lowercase is rejected`() {
        assertRejected(policy(), "CORRECT-HORSE-7", "lowercase")
    }

    @Test
    fun `a missing digit is rejected`() {
        assertRejected(policy(), "Correct-Horse-x", "digit")
    }

    @Test
    fun `a missing special character is rejected`() {
        assertRejected(policy(), "CorrectHorse77", "special")
    }

    @Test
    fun `character rules set to zero are disabled`() {
        policy {
            minUppercase = 0
            minLowercase = 0
            minDigits = 0
            minSpecial = 0
        }.requireValid("someone", "correcthorsebattery")
    }

    @Test
    fun `every failed rule is reported`() {
        val exception = assertFailsWith<ResponseStatusException> { policy().requireValid("someone", "abc") }

        val reason = exception.reason.orEmpty()
        assertContains(reason, "uppercase")
        assertContains(reason, "digit")
    }

    @Test
    fun `a password containing the username is rejected`() {
        assertRejected(policy(), "Xx-Someone-1234", "user id")
    }

    @Test
    fun `the username rule can be disabled`() {
        policy { rejectUsername = false }.requireValid("someone", "Xx-Someone-1234")
    }

    @Test
    fun `a password over the bcrypt limit in bytes is rejected even under the maximum length`() {
        assertRejected(policy(), "Aa-1" + "\u00e9".repeat(40), "too long")
    }
}
