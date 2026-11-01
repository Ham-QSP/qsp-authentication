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
import org.passay.DefaultPasswordValidator
import org.passay.PasswordData
import org.passay.data.EnglishCharacterData
import org.passay.resolver.PropertiesMessageResolver
import org.passay.rule.CharacterRule
import org.passay.rule.LengthRule
import org.passay.rule.Rule
import org.passay.rule.UsernameRule
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ResponseStatusException

@Component
class PasswordPolicy(
    properties: PasswordPolicyProperties,
) {
    companion object {
        private const val BCRYPT_MAX_BYTES = 72
    }

    private val validator = DefaultPasswordValidator(PropertiesMessageResolver(), rules(properties))

    fun requireValid(
        username: String,
        password: String,
    ) {
        val result = validator.validate(PasswordData(username, password))
        val tooLong = password.toByteArray().size > BCRYPT_MAX_BYTES
        if (!result.isValid || tooLong) {
            val messages = result.messages + if (tooLong) listOf("Password is too long.") else emptyList()
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, messages.joinToString(" "))
        }
    }

    private fun rules(properties: PasswordPolicyProperties): List<Rule> =
        buildList {
            add(LengthRule(properties.minLength, properties.maxLength))
            addCharacterRule(EnglishCharacterData.UpperCase, properties.minUppercase)
            addCharacterRule(EnglishCharacterData.LowerCase, properties.minLowercase)
            addCharacterRule(EnglishCharacterData.Digit, properties.minDigits)
            addCharacterRule(EnglishCharacterData.Special, properties.minSpecial)
            if (properties.rejectUsername) {
                add(UsernameRule(false, true))
            }
        }

    private fun MutableList<Rule>.addCharacterRule(
        characters: EnglishCharacterData,
        minimum: Int,
    ) {
        if (minimum > 0) {
            add(CharacterRule(characters, minimum))
        }
    }
}
