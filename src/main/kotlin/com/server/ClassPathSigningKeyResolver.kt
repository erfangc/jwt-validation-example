package com.server

import com.fasterxml.jackson.databind.ObjectMapper
import com.okta.jwt.impl.jjwt.models.JwkKeys
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.SigningKeyResolver
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPublicKeySpec
import java.util.*

class ClassPathSigningKeyResolver : SigningKeyResolver {

    private val objectMapper = ObjectMapper()

    private val jwkKeys: JwkKeys = objectMapper
            .readValue(
                    this::class.java.classLoader.getResourceAsStream("keys.json"),
                    JwkKeys::class.java
            )

    private val keys = jwkKeys.keys.map { jwkKey ->
        val modulus: BigInteger = base64ToBigInteger(jwkKey.publicKeyModulus)
        val exponent: BigInteger = base64ToBigInteger(jwkKey.publicKeyExponent)
        val rsaPublicKeySpec = RSAPublicKeySpec(modulus, exponent)
        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(rsaPublicKeySpec)
            jwkKey.keyId to publicKey
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Failed to parse public key")
        } catch (e: InvalidKeySpecException) {
            throw IllegalStateException("Failed to parse public key")
        }
    }.toMap()

    override fun resolveSigningKey(header: JwsHeader<out JwsHeader<*>>?, claims: Claims?): Key {
        return keys.getValue(header?.getKeyId())
    }

    override fun resolveSigningKey(header: JwsHeader<out JwsHeader<*>>?, plaintext: String?): Key {
        return keys.getValue(header?.getKeyId())
    }

    private fun base64ToBigInteger(value: String): BigInteger {
        return BigInteger(1, Base64.getUrlDecoder().decode(value))
    }

}