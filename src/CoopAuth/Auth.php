<?php

namespace Codewrite\CoopAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Auth
{
    private $secretKey;
    private $algorithm;

    public function __construct($secretKey, $algorithm = 'HS256')
    {
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
    }

    // Generates a JWT token for a given user
    public function generateToken(array $payload): string
    {
        return JWT::encode($payload, $this->secretKey, $this->algorithm);
    }

    // Decodes a given JWT token
    public function decodeToken(string $token)
    {
        try {
            return JWT::decode($token, new Key($this->secretKey, $this->algorithm));
        } catch (\Exception $e) {
            throw new AuthException('Invalid token: ' . $e->getMessage());
        }
    }

    // Checks if a given JWT token has a particular permission
    public function checkPermission(string $token, string $permission): bool
    {
        $decoded = $this->decodeToken($token);
        return in_array($permission, $decoded->permissions ?? []);
    }
}
