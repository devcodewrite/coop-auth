<?php

namespace Config;

use CodeIgniter\Config\BaseConfig;

class CoopAuth extends BaseConfig
{
    /**
     * --------------------------------------------------------------------------
     * JWT Secret
     * --------------------------------------------------------------------------
     * JWT secret provide for jwt encodeing. You can override the value here by
     * specifying coopAuth.jwtSecret in the .env file
     */
    public $jwtSecret = 'your-default-jwt-secret';

    public $tokenExpiry = 60; // Default to 60 secounds

    public $algorithm = 'HS256';

    public $userModelName = 'UserModel';

    /**
     * --------------------------------------------------------------------------
     * Resources
     * --------------------------------------------------------------------------
     *
     * List of key-value for that can be specified as resource in permissions
     * if a key is not not in this list permission will be denied for the request
     * by the authorization engine. The key is the resource name used in permission
     * and the value is the app/Model file name for database table use for the resource.
     * 
     * Here are some examples:
     *     [
     *         'users'     => 'UserModel',
     *         'resources' => 'ResourceModel',
     *     ]
     *
     * @var array<string, string>
     */
    public $resources = [
        'users' => 'UserModel',
        'resources' => 'ResourceModel'
    ];

    /**
     * --------------------------------------------------------------------------
     * Condition Keys
     * --------------------------------------------------------------------------
     *
     * @var array<string, string>
     */
    public $conditionKeys = [
        'id',
        'owner',
        'username',
        'society_id',
        'assoc_id'
    ];

    /**
     * --------------------------------------------------------------------------
     * Microservices Endpoints
     * --------------------------------------------------------------------------
     *
     * @var array<string, string>
     */
    public $services = [
        'accounts' => "http://localhost:8080",
        'cooporatives' => "http://localhost:8081",
        'transactions' => "http://localhost:8082",
        'billings' => "http://localhost:8083"
    ];
}
