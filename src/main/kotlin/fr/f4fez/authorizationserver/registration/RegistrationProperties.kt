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

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "qsp.registration")
class RegistrationProperties {
    var codeTtl: Duration = Duration.ofMinutes(15)
    var maxAttempts: Int = 5
    var maxSendsPerHour: Int = 3
    var resendInterval: Duration = Duration.ofSeconds(60)
    var retention: Duration = Duration.ofHours(24)
}
