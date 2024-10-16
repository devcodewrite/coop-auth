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

        $permissions = [];
        foreach ($permissionsData as $permission) {

            // Prepare the permission structure for the resource
            $permissionEntry = [
                'actions' => json_decode($permission->actions, true),
                'scopes' => json_decode($permission->scopes, true),
                'filters' => json_decode($permission->filters, true)
            ];
            if (!isset($permissions[$permission->resource_id]))
                $permissions[$permission->resource_id] = [];

            // Add the permission entry to the resource
            $permissions[$permission->resource_id][] = $permissionEntry;
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
    public function can(string $action, string $resource, array $scopes = [], array $records = []): GuardReponse
    {
        try {
            // get token
            $token = $this->extractToken();
            // get claims
            $claims = $this->objectToArray($this->decodeToken($token));

            // Retrieve permissions from the decoded JWT
            $permissions = $claims['permissions'] ?? [];

            $filteredRecords = [];

            if (!isset($permissions[$resource]))
                return new GuardReponse(false, CoopResponse::UNAUTHORIZED, null, $filteredRecords);

            // Iterate over each record to check permission
            foreach ($records as $record) {
                $record = $this->objectToArray($record);
                $hasAccess = false;

                // Loop through each permission rule for the given entity
                foreach ($permissions[$resource] as $permission) {
                    // Check if the action is allowed
                    if (in_array($action, $permission['actions']) || $permission['actions'] === '*') {
                        // Check if the record is within the allowed scope or if the scope is null (no restriction)
                        if (
                            $permission['scopes'] === null || empty(array_diff($scopes, $permission['scopes']))
                        ) {
                            // Check filters for this record
                            $filtersMatch = true;
                            $filters = $permission['filters'] ?? [];

                            foreach ($filters as $filterKey => $allowedValues) {

                                // If filter is "*", allow all values, otherwise match against the allowed values
                                if ($allowedValues !== '*' && !empty($allowedValues)) {
                                    // Check if the record's field value matches the allowed filter values
                                    if (!in_array($record[$filterKey], $allowedValues)) {
                                        $filtersMatch = false;
                                        break;
                                    }
                                }
                            }

                            // If all filters match, set hasAccess to true
                            if ($filtersMatch) {
                                $hasAccess = true;
                                break; // No need to check further permissions for this record
                            }
                        }
                    }
                }

                // If no valid permission is found for any of the records, return false
                if (!$hasAccess) {
                    return new GuardReponse(false, GuardReponse::UNAUTHORIZED);
                } else {
                    $filteredRecords[] = $record;
                }
            }
            // If all records passed the permission check, return true
            return new GuardReponse(true, GuardReponse::OK, null, $filteredRecords);
        } catch (ExpiredException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_EXPIRED);
        } catch (HTTPException $e) {
            return new GuardReponse(false, CoopResponse::TOKEN_NOT_PROVIDED);
        } catch (Exception $e) {
            return new GuardReponse(false, CoopResponse::INVALID_PERMISSION, $e->getMessage());
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
    public function canUser($userId, string $action, string $resource, array $scopes = [], array $records = []): GuardReponse
    {
        // Generate permissions
        $permissions = $this->generatePermissions($userId)['permissions'] ?? [];
        try {
            $filteredRecords = [];
            if (!isset($permissions[$resource]))
                return new GuardReponse(false, CoopResponse::UNAUTHORIZED, null, $filteredRecords);

            // Iterate over each record to check permission
            foreach ($records as $record) {
                $record = $this->objectToArray($record);
                $hasAccess = false;

                // Loop through each permission rule for the given entity
                foreach ($permissions[$resource] as $permission) {
                    // Check if the action is allowed
                    if (in_array($action, $permission['actions']) || $permission['actions'] === '*') {
                        // Check if the record is within the allowed scope or if the scope is null (no restriction)
                        if (
                            $permission['scopes'] === null || empty(array_diff($scopes, $permission['scopes']))
                        ) {
                            // Check filters for this record
                            $filtersMatch = true;
                            $filters = $permission['filters'] ?? [];

                            foreach ($filters as $filterKey => $allowedValues) {

                                // If filter is "*", allow all values, otherwise match against the allowed values
                                if ($allowedValues !== '*' && !empty($allowedValues)) {
                                    // Check if the record's field value matches the allowed filter values
                                    if (!in_array($record[$filterKey], $allowedValues)) {
                                        $filtersMatch = false;
                                        break;
                                    }
                                }
                            }

                            // If all filters match, set hasAccess to true
                            if ($filtersMatch) {
                                $hasAccess = true;
                                break; // No need to check further permissions for this record
                            }
                        }
                    }
                }

                // If no valid permission is found for any of the records, return false
                if (!$hasAccess) {
                    return new GuardReponse(false, GuardReponse::UNAUTHORIZED);
                } else {
                    $filteredRecords[] = $record;
                }
            }
            // If all records passed the permission check, return true
            return new GuardReponse(true, GuardReponse::OK, null, $filteredRecords);
        } catch (Exception $e) {
            return new GuardReponse(false, CoopResponse::INVALID_PERMISSION, $e->getMessage());
        }
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

                    $model->groupStart();
                    // Apply "denied" conditions to restrict to specific records
                    foreach ($columns as $key) {
                        if (!in_array("*", ($deniedConditions[$key] ?? []))) {
                            $values = array_map(function ($val) {
                                if ($val === "{sub}")
                                    return $this->user_id();
                                return $val;
                            }, $deniedConditions[$key] ?? []);

                            $model->whereNotIn($key, ['#', ...$values]);
                        }
                    }
                    $model->groupEnd();
                    $model->groupStart();
                    // Apply "allowed" conditions to restrict to specific records
                    foreach ($columns as $key) {
                        if (!in_array("*", ($allowedConditions[$key] ?? []))) {

                            $values = array_map(function ($val) {
                                if ($val === "{sub}")
                                    return $this->user_id();
                                return $val;
                            }, $allowedConditions[$key] ?? []);

                            $model->whereIn($key, ['#', ...$values]);
                        }
                    }
                    $model->groupEnd();
                }
            }

            if (!$hasView) $model->where(new RawSql('0'));

            return $model;
        } catch (Exception $e) {
            die($e->getMessage());
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
