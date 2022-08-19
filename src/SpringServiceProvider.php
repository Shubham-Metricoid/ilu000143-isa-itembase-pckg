<?php

namespace Spring;

class SpringServiceProvider
{

    public function generate_jwt_token()
    {
        //build the headers
        $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
        $headers_encoded = $this->base64url_encode(json_encode($headers));

        //build the payload
        $payload = ['key' => '1234567890'];
        $payload_encoded = $this->base64url_encode(json_encode($payload));

        //build the signature
        $key = 'secret';
        $signature = hash_hmac('sha256', "$headers_encoded.$payload_encoded", $key, true);
        $signature_encoded = $this->base64url_encode($signature);

        //build and return the token
        $token = "$headers_encoded.$payload_encoded.$signature_encoded";
        return $token;
    }

    public function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
