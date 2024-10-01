<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\HTTP\Exceptions\HTTPException;
use CodeIgniter\Model;
use Exception;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class Auth
{
    private $request;

    public $config;

    public function __construct()
    {
        $this->config   = config('coopauth');
        $this->request  = service('request');
        $this->response = service('response');
    }

    /**
     * Generates a JWT token for a given user
     */
    public function generateToken(array $payload): string
    {
        $payload = array_merge([
            'iss' => 'localhost',
            'iat' => time(),
            'nbf' => time(),
            'exp' => $this->config->tokenExpiry,
        ], $payload);
        return JWT::encode($payload, $this->config->jwtSecret, $this->config->algorithm);
    }

    /**
     * Decodes a given JWT token
     */
    public function decodeToken(string $token): stdClass
    {
        return JWT::decode($token, new Key($this->config->jwtSecret, $this->config->algorithm));
    }

    /**
     * Refresh a given JWT token
     */
    public function refreshToken(string $refreshToken, $payload): string
    {
        $payload = $this->decodeToken($refreshToken);

        $payload = array_merge([
            'iss' => site_url(),
            'iat' => time(),
            'nbf' => time(),
            'exp' => $this->config->tokenExpiry,
        ], $payload);
        return JWT::encode($payload, $this->config->secretKey, $this->config->algorithm);
    }

    // Get the current user id
    public function user_id(): string | null
    {
        // Extract token from header and decode
        $token = $this->extractToken();
        $claims = $this->decodeToken($token);
        return $claims->sub ?? null;
    }

    // Get the current user data
    public function user(): stdClass | null
    {
        // Check if UserModel exists
        $namespace = '\\App\\Models\\' . $this->config->userModelName;
        if (!class_exists($namespace)) return null;

        $user_id = $this->user_id();
        $userModel = model($this->config->userModelName);
        return $userModel->find($user_id);
    }

    /** 
     * Check if the user has the specified permission
     * $action http request method being executed.
     * $resource The route path usually the controller that will
     * execute the request of the user. This value should be in 
     * the resource list in the config file
     * $condition a string of the form feild:value that will be check
     * on the model connected to the resource to see if it matches
     */
    public function can($action, $resource, $conditions): GuardReponse
    {
        try {
            // get token
            $token = $this->extractToken();
            // get claims
            $claims = (array)$this->decodeToken($token);

            // Retrieve permissions from the decoded JWT
            $permissions = $claims->permissions ?? [];

            if (!isset($permissions[$resource]))
                return new GuardReponse(false, CoopResponse::INVALID_PERMISSION);

            $resourcePermissions = $permissions[$resource];
            $allowedActions = $resourcePermissions['actions'] ?? [];

            if (!in_array($action, $allowedActions)) {
                return  new GuardReponse(false, CoopResponse::INVALID_PERMISSION); // Action not allowed
            }

            // Check conditions if provided
            if (!empty($resourcePermissions['conditions'])) {
                return $this->evaluateConditions($resourcePermissions['conditions'], $conditions);
            }
            return new GuardReponse(true, CoopResponse::OK);
        } catch (ExpiredException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_EXPIRED);
        } catch (HTTPException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_NOT_PROVIDED);
        } catch (Exception $e) {
            return new GuardReponse(false, CoopResponse::INVALID_TOKEN);
        }
    }

    /**
     * Evaluate the conditions for a resource
     * For example, check if a given `id` is allowed based on the `conditions`
     */
    private function evaluateConditions($permissionConditions, $requestConditions)
    {
        // 1. Evaluate "denied" conditions first
        if (!empty($permissionConditions['denied'])) {
            foreach ($permissionConditions['denied'] as $key => $deniedValues) {
                $requestValue = $requestConditions[$key] ?? null;
                if ($requestValue && in_array($requestValue, $deniedValues)) {
                    // Denied condition met, access forbidden
                    return new GuardReponse(false, CoopResponse::UNAUTHORIZED);
                }
            }
        }

        // 2. Evaluate "allowed" conditions if "denied" conditions are not met
        if (!empty($permissionConditions['allowed'])) {
            foreach ($permissionConditions['allowed'] as $key => $allowedValues) {
                $requestValue = $requestConditions[$key] ?? null;
                if ($requestValue && !in_array($requestValue, $allowedValues)) {
                    // Allowed condition not met
                    return new GuardReponse(false, CoopResponse::UNAUTHORIZED);
                }
            }
        }

        // All conditions are satisfied
        return new GuardReponse(true, CoopResponse::OK);
    }

    /**
     * Apply the permissions conditions to a model's query.
     * Dynamically modify the query builder to enforce allowed and denied conditions.
     *
     * @param Model $model
     * @param string $resource
     * @return Model
     */
    public function applyConditionsToModel(Model &$model, $resource)
    {
        try {
            // get token
            $token = $this->extractToken();
            // get claims
            $claims = (array)$this->decodeToken($token);

            // Retrieve permissions from the decoded JWT
            $permissions = $claims->permissions ?? [];

            if (!isset($permissions[$resource]))
                return $model; // No permissions for this resource, return the model unmodified


            $resourcePermissions = $permissions[$resource];
            $conditions = $resourcePermissions['conditions'] ?? [];

            // Build the query based on allowed and denied conditions
            $allowedConditions = $conditions['allowed'] ?? [];
            $deniedConditions = $conditions['denied'] ?? [];

            // Apply "denied" conditions to exclude records
            foreach ($deniedConditions as $key => $values) {
                if (is_array($values)) {
                    $model = $model->whereNotIn($key, $values);
                } else {
                    $model = $model->where("$key !=", $values);
                }
            }

            // Apply "allowed" conditions to restrict to specific records
            foreach ($allowedConditions as $key => $values) {
                if (is_array($values)) {
                    $model = $model->whereIn($key, $values);
                } else {
                    $model = $model->where($key, $values);
                }
            }
            return $model;
        } catch (Exception $e) {
        }
        return false;
    }

    /**
     * Extract JWT from the Authorization header.
     */
    public function extractToken()
    {
        // Step 1: Extract JWT from the Authorization header
        $authHeader = $this->request->header('Authorization');
        if (!$authHeader) {
            throw new HTTPException('Token not provided', 403);
        }

        if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return $matches[1]; // Return the token part
        }
        return null;
    }
}
