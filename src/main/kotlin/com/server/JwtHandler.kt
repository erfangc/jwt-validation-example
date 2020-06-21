package com.server

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwtHandlerAdapter

object JwtHandler : JwtHandlerAdapter<Claims>() {
    override fun onClaimsJws(jws: Jws<Claims>): Claims {
        return jws.body
    }
}