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

    // return array of permissions
    public function permissions(): array
    {
        $token = $this->extractToken();
        $claims = $this->decodeToken($token);

        return $claims->permissions ?? [];
    }

    // return array of roles
    public function roles(): array
    {
        $token = $this->extractToken();
        $claims = $this->decodeToken($token);

        return $claims->roles ?? [];
    }

    // return array of resources
    public function resources(): array
    {
        $token = $this->extractToken();
        $claims = $this->decodeToken($token);

        return $claims->resources ?? [];
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
    public function can($action, $resource, Model &$model = null): GuardReponse
    {
        try {
            // Retrieve permissions from the decoded JWT
            $permissions = $this->permissions();
            $check = false;

            foreach ($permissions as $key => $permission) {
                if (!$this->isValidPermission($permission))
                    return new GuardReponse(false, CoopResponse::INVALID_PERMISSION);

                if (!isset($permission->actions))
                    return new GuardReponse(true, CoopResponse::OK);

                if (!in_array($action, $permission->actions))
                    return new GuardReponse(false, CoopResponse::UNAUTHORIZED);;

                $parts = explode(':', $permission->resource);
                if (count($parts) <= 2)
                    return new GuardReponse($this->validateConditions($parts[0], $resource), CoopResponse::UNAUTHORIZED);

                if (!in_array($parts[1], $this->config->conditionKeys))
                    return new GuardReponse(false, CoopResponse::INVALID_CONDITION_KEY);

                $condition = ['key' => $parts[1], 'values' => explode(',', $parts[2])];

                $check = $check || $this->validateConditions($parts[0], $resource, $condition);

                if ($check && $model) $check = $model->whereIn($parts[1], $condition['values'])->countAllResults(false) > 0;
            }
            return new GuardReponse($check, CoopResponse::UNAUTHORIZED);
        } catch (ExpiredException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_EXPIRED);
        } catch (Exception $e) {
            return new GuardReponse(false, CoopResponse::INVALID_TOKEN);
        }
    }

    protected function validateConditions($providedResource, $reqResource, $condition = null): bool
    {
        if (!$condition)
            return $providedResource === "*" || $providedResource === $reqResource;

        $model = model($this->config->resources[$reqResource]);

        return ($providedResource === "*" || $providedResource === $reqResource)
            && $model->whereIn($condition['key'], $condition['values'])->countAllResults(false) > 0;
    }

    /**
     * Checks if a given permission string is valid.
     *
     * @param object $permission The permission object to validate.
     * @return bool True if valid, false otherwise.
     */
    protected function isValidPermission(object $permission): bool
    {
        if (
            !$permission || gettype($permission->actions) !== 'array'
            || gettype($permission->resource) !== 'string'
        )
            return false;

        // Regular expression pattern for matching `resource:field:value`, `resource:field`, or `resource::value`
        $pattern = '/^[a-zA-Z0-9_*]+(:[a-zA-Z0-9_]*)?(:[a-zA-Z0-9_,]*)?$/';
        // Validate the permission string against the pattern
        return (bool)preg_match($pattern, $permission->resource);
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
