<?php

use \Firebase\JWT\JWT;

if(!function_exists('generateJWT')){

    function generateJWT( array | object | null $user ){
        $key = getenv('JWT_SECRET');

        $payload = array(
            "iss" => "Issuer of the JWT",
            "aud" => "Audience that the JWT",
            "sub" => "Subject of the JWT",
            "iat" => time(),
            "exp" => time() + 3600,
            "email" => $user['email'],
            "id" => $user['id']
        );

        $token = JWT::encode($payload, $key, 'HS256');
        return $token;
    }

}