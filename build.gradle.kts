/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin application project to get you started.
 */

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.3.72"

    // Apply the application plugin to add support for building a CLI application.
    application
}

repositories {
    // Use jcenter for resolving dependencies.
    // You can declare any Maven/Ivy/file repository here.
    jcenter()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")

//    implementation("io.jsonwebtoken:jjwt-api:0.11.2")
//    implementation("io.jsonwebtoken:jjwt-impl:0.11.2")
//    implementation("io.jsonwebtoken:jjwt-jackson:0.11.2")
    implementation("com.okta.jwt:okta-jwt-verifier:0.4.0")
    implementation("com.okta.jwt:okta-jwt-verifier-impl:0.4.0")
}

application {
    // Define the main class for the application.
    mainClassName = "com.server.AppKt"
}