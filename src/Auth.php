<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\Database\RawSql;
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

    public $userModel;

    public $userRoleModel;

    public $permissionModel;

    public $resourceModel;

    public $userGroupModel;

    public $groupRoleModel;

    public $userId;


    public function __construct()
    {
        $this->config   = config('CoopAuth');
        $this->request  = service('request');
        $this->response = service('response');

        $this->userModel        = model($this->config->authModels['UserModel']);
        $this->userRoleModel    = model($this->config->authModels['UserRoleModel']);
        $this->permissionModel  = model($this->config->authModels['PermissionModel']);
        $this->resourceModel    = model($this->config->authModels['ResourceModel']);
        $this->userGroupModel   = model($this->config->authModels['UserGroupModel']);
        $this->groupRoleModel   = model($this->config->authModels['GroupRoleModel']);
    }

    /**
     * Generate permissions JSON for a given user ID.
     *
     * @param string $userId
     * @return array
     */
    public function generatePermissions($userId)
    {
        // Step 1: Get User Roles
        $roles = $this->userRoleModel->where('user_id', $userId)->findAll();
        $roleIds = array_column($roles, 'role_id');
        // getting group roles
        $userGroups = $this->userGroupModel->where('user_id', $userId)->findAll();
        $groupIds = array_column($userGroups, 'group_id');
        $groupRoles = $this->groupRoleModel->whereIn('group_id', array_merge([''], $groupIds))->findAll();
        // adding group role ids to groups id
        $roleIds = array_merge($roleIds, array_column($groupRoles, 'role_id'));

        if (empty($roleIds)) {
            return ['permissions' => []]; // No roles assigned, return empty permissions
        }

        // Step 2: Get Permissions for User Roles
        $permissionsData = $this->permissionModel
            ->whereIn('role_id', $roleIds)
            ->findAll();

        // Step 3: Get Resources Data
        $resourceIds = array_unique(array_column($permissionsData, 'resource_id'));
        $resources = $this->resourceModel->whereIn('id', $resourceIds)->findAll();
        $resourceMap = [];
        foreach ($resources as $resource) {
            $resourceMap[$resource->id] = $resource->id;
        }

        // Step 4: Build Permissions Structure
        $permissions = [];

        foreach ($permissionsData as $permission) {
            $resourceName = $resourceMap[$permission->resource_id] ?? null;
            if (!$resourceName) {
                continue; // Skip if the resource is not found
            }

            // Prepare the permission structure for the resource
            $permissionEntry = [
                'actions' => json_decode($permission->actions, true),
                'conditions' => json_decode($permission->conditions, true)
            ];

            if (!isset($permissions[$resourceName])) {
                $permissions[$resourceName] = [];
            }

            // Add the permission entry to the resource
            $permissions[$resourceName][] = $permissionEntry;
        }

        // Step 5: Format the Permission JSON
        $permissionJson = [
            'sub' => $userId,
            'permissions' => $permissions
        ];

        return $permissionJson;
    }

    /**
     * Generates a JWT token for a given user
     */
    public function generateAccessToken(array $payload): string
    {
        $payload = array_merge([
            'iss' => 'localhost',
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $this->config->tokenExpiry,
        ], $payload);
        return JWT::encode($payload, $this->config->jwtSecret, $this->config->algorithm);
    }

    /**
     * Generates a JWT token for a given user
     */
    public function generateRefreshToken(array $payload): string
    {
        $payload = array_merge([
            'iss' => 'localhost',
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $this->config->refreshTokenExpiry,
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
    public function refreshToken(string $refreshToken, array $payload): string
    {
        $payload = array_merge([
            'iss' => site_url(),
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + $this->config->tokenExpiry,
        ], $payload);
        return JWT::encode($payload, $this->config->jwtSecret, $this->config->algorithm);
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
    public function user()
    {
        if (!$this->userModel) return null;

        $user_id = $this->user_id();
        return $this->userModel->find($user_id);
    }

    public function objectToArray($obj)
    {
        return json_decode(json_encode($obj), true);
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
    public function can(string $action, string $resource, array $conditions = null): GuardReponse
    {
        try {
            // get token
            $token = $this->extractToken();
            // get claims
            $claims = $this->objectToArray($this->decodeToken($token));

            // Retrieve permissions from the decoded JWT
            $permissions = $claims['permissions'] ?? [];

            // echo json_encode($permissions); die;

            if (!isset($permissions[$resource]))
                return new GuardReponse(false, CoopResponse::UNAUTHORIZED);

            $resourcePermissions = $permissions[$resource];

            if (gettype($resourcePermissions) !== 'array')
                return new GuardReponse(false, CoopResponse::INVALID_PERMISSION);

            foreach ($resourcePermissions as $resourcePermission) {
                $allowedActions = $resourcePermission['actions'] ?? [];
                if (
                    in_array($action, $allowedActions)
                    && !empty($resourcePermission['conditions'])
                    && $this->evaluateConditions($resourcePermission['conditions'], $conditions)
                ) {
                    return new GuardReponse(true, CoopResponse::OK);
                }

                if (
                    in_array($action, $allowedActions)
                    && empty($resourcePermission['conditions'])
                ) {
                    return new GuardReponse(true, CoopResponse::OK);
                }
            }
            return new GuardReponse(false, CoopResponse::UNAUTHORIZED);
        } catch (ExpiredException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_EXPIRED);
        } catch (HTTPException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_NOT_PROVIDED);
        } catch (Exception $e) {
            return new GuardReponse(false, CoopResponse::INVALID_TOKEN);
        }
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
    public function canUser($userId, string $action, string $resource, array $conditions = null): GuardReponse
    {
        $this->userId = $userId;

        // Generate permissions
        $permissions = $this->generatePermissions($userId)['permissions'] ?? [];

        if (!isset($permissions[$resource]))
            return new GuardReponse(false, CoopResponse::UNAUTHORIZED);

        $resourcePermissions = $permissions[$resource];

        if (gettype($resourcePermissions) !== 'array')
            return new GuardReponse(false, CoopResponse::INVALID_PERMISSION);

        foreach ($resourcePermissions as $resourcePermission) {
            $allowedActions = $resourcePermission['actions'] ?? [];
            if (
                in_array($action, $allowedActions)
                && !empty($resourcePermission['conditions'])
                && $this->evaluateConditions($resourcePermission['conditions'], $conditions)
            ) {
                return new GuardReponse(true, CoopResponse::OK);
            }

            if (
                in_array($action, $allowedActions)
                && empty($resourcePermission['conditions'])
            ) {
                return new GuardReponse(true, CoopResponse::OK);
            }
        }
        return new GuardReponse(false, CoopResponse::UNAUTHORIZED);
    }

    /**
     * Evaluate the conditions for a resource
     * For example, check if a given `id` is allowed based on the `conditions`
     */
    private function evaluateConditions($permissionConditions, $requestConditions)
    {
        if ($requestConditions === null || count($requestConditions ?? []) === 0)
            return true;

    
        // 1. Evaluate "denied" conditions first
        if (!empty($permissionConditions['denied'])) {
            foreach ($permissionConditions['denied'] as $key => $deniedValues) {
                $requestValue = $requestConditions[$key] ?? null;
                $deniedValues = array_map(function ($val) {
                    if ($val === "{sub}")
                        return $this->userId ?? $this->user_id();
                    return $val;
                }, $deniedValues);

                if ($requestValue && in_array($requestValue, $deniedValues) && in_array('*', $deniedValues)) {
                    // Denied condition met, access forbidden
                    return false;
                }
            }
        }

        // 2. Evaluate "allowed" conditions if "denied" conditions are not met
        if (!empty($permissionConditions['allowed'])) {  
            foreach ($permissionConditions['allowed'] as $key => $allowedValues) {
                $requestValue = $requestConditions[$key] ?? null;
                $allowedValues = array_map(function ($val) {
                    if ($val === "{sub}")
                        return $this->userId ?? $this->user_id();
                    return $val;
                }, $allowedValues);

                if ($requestValue !== null && (in_array($requestValue, $allowedValues) || in_array('*', $allowedValues))) {
                    // Allowed condition not met
                    return true;
                }
            }
        }
        
        // All conditions are satisfied
        return false;
    }

    /**
     * Apply the permissions conditions to a model's query.
     * Dynamically modify the query builder to enforce allowed and denied conditions.
     *
     * @param Model $model
     * @param string $resource
     * @return Model
     */
    public function applyConditionsToModel(Model &$model, $resource, $columns = [])
    {
        try {
            // get token
            $token = $this->extractToken();
            $claims = $this->objectToArray($this->decodeToken($token));

            // Retrieve permissions from the decoded JWT
            $permissions = $claims['permissions'] ?? [];
            $resourcePermissions = $permissions[$resource] ?? [];

            if (count($columns) === 0) return $model;

            $hasView = false;

            foreach ($resourcePermissions as $key => $resourcePermission) {
                if (in_array('view', $resourcePermission['actions'])) {
                    $hasView = true;
                    $conditions = $resourcePermission['conditions'] ?? [];
                    // Build the query based on allowed and denied conditions
                    $allowedConditions = $conditions['allowed'] ?? [];
                    $deniedConditions = $conditions['denied'] ?? [];

                    // Apply "denied" conditions to restrict to specific records
                    foreach ($columns as $key) {
                        if (!in_array("*", $deniedConditions[$key])) {
                            $values = array_map(function ($val) {
                                if ($val === "{sub}")
                                    return $this->user_id();
                                return $val;
                            }, $deniedConditions[$key]);

                            $model->whereNotIn($key, ['', ...$values]);
                        }
                    }

                    // Apply "allowed" conditions to restrict to specific records
                    foreach ($columns as $key) {
                        if (!in_array("*", $allowedConditions[$key])) {

                            $values = array_map(function ($val) {
                                if ($val === "{sub}")
                                    return $this->user_id();
                                return $val;
                            }, $allowedConditions[$key]);

                            $model->whereIn($key, ['', ...$values]);
                        }
                    }
                }
            }

            if (!$hasView) $model->where(new RawSql('0'));

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
