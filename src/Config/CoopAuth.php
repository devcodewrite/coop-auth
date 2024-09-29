<?php

namespace Codewrite\CoopAuth\Config;

use CodeIgniter\Config\BaseConfig;

class CoopAuth extends BaseConfig
{
    public $tokenExpiration = 3600; // JWT token expiration in seconds
    public $issuer = 'your-app';    // JWT Issuer
    public $audience = 'your-users'; // JWT Audience
}
