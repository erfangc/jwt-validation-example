/*
 * This Kotlin source file was generated by the Gradle 'init' task.
 */
package com.server

import com.okta.sdk.client.Clients

fun main() {

    val client = Clients.builder()
            .setOrgUrl("https://dev-282685.okta.com")
            .build()

    client.listUsers().forEach {
        user ->
        println("${user.id}, ${user.profile.firstName}, ${user.profile.lastName}")
    }

}

