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

package fr.f4fez.authorizationserver.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "qsp.authorization")
class AuthorizationProperties {
    var clients: Map<String, ClientProperties> = emptyMap()
}

class ClientProperties {
    var redirectUri: List<String> = emptyList()
    var accessTokenTimeToLive: Long = 3
    var refreshTokenTimeToLive: Long = 360
}
