<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\HTTP\Response;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use stdClass;

class Auth
{
    private $request;

    private $response;

    public $config;

    protected $sub;

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
            'iss' => site_url(),
            'iat' => time(),
            'nbf' => time(),
            'exp' => $this->config->tokenExpiry,
        ], $payload);
        return JWT::encode($payload, $this->config->secretKey, $this->config->algorithm);
    }

    /**
     * Decodes a given JWT token
     */
    public function decodeToken(string $token): stdClass
    {
        try {
            return JWT::decode($token, new Key($this->secretKey, $this->algorithm));
        } catch (ExpiredException $e) {
            // Handle expired token exception
            return $this->unauthorizedResponse([
                'error_code' => 3,
                'message' => 'Token has expired. Please refresh your token.'
            ]);
        } catch (\Exception $e) {
            // Handle other JWT exceptions
            return $this->unauthorizedResponse([
                'error_code' => 2,
                'message' => 'Invalid token'
            ]);
        }
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
    public function can($action, $resource, $condition = null): bool
    {
        // Retrieve permissions from the decoded JWT
        $permissions = $this->permissions();

        foreach ($permissions as $key => $permission) {
            if (!$this->isValidPermission($permission))
                throw new InvalidPermissionException();

            if (!in_array($action, $permission->actions)) return false;

            $parts = explode(':', $permission->resource);
            if (count($parts) === 2)
                return $this->validateConditions($parts[0], $resource);

            $condition = [$parts[1] => $parts[2]];

            return $this->validateConditions($parts[0], $resource, $condition);
        }
        return false;
    }

    /**
     * Return a 401 Unauthorized response.
     */
    public function unauthorizedResponse($data)
    {
        return $this->response->setJSON($data)->setStatusCode(Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Return a 403 Forbidden response.
     */
    public function forbiddenResponse($data)
    {
        return $this->response->setJSON($data)->setStatusCode(Response::HTTP_FORBIDDEN);
    }

    protected function validateConditions($providedResource, $reqResource, $condition = null): bool
    {
        if (!$condition)
            return $providedResource === "*" || $providedResource === $reqResource;

        $model = model($this->config->resources[$reqResource]);

        return ($providedResource === "*" || $providedResource === $reqResource)
            && $model->where($condition)->countAllResults() > 0;
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
        $pattern = '/^[a-zA-Z0-9_]+(:[a-zA-Z0-9_]*)?(:[a-zA-Z0-9_]*)?$/';
        // Validate the permission string against the pattern
        return (bool)preg_match($pattern, $permission->resource);
    }


    /**
     * Extract JWT from the Authorization header.
     */
    protected function extractToken()
    {
        // Step 1: Extract JWT from the Authorization header
        $authHeader = $this->request->header('Authorization');
        if (!$authHeader) {
            return $this->unauthorizedResponse([
                'error_code' => 1,
                'message' => 'Token not provided'
            ]);
        }

        // Step 2: Retrieve and validate the JWT
        $token = $this->extractToken($authHeader);
        if (!$token) {
            return $this->unauthorizedResponse([
                'error_code' => 1,
                'message' => 'Token not provided'
            ]);
        }

        if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return $matches[1]; // Return the token part
        }
        return null;
    }
}
