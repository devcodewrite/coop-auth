<?php

namespace Codewrite\CoopAuth\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\Response;
use Config\Services;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use CodeIgniter\API\ResponseTrait;


class JwtFilter implements FilterInterface
{
    use ResponseTrait;
    /**
     * Before filter to check permissions for REST API access.
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Step 1: Extract JWT from the Authorization header
        $authHeader = $request->header('Authorization');
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

        try {
            // Decode the JWT with a secret key
            $decoded = JWT::decode($token, new Key(env('jwt.secret'), 'HS256'));
            $permissions = $decoded->permissions ?? [];

            // Step 3: Get the http request method (e.g. POST, GET)
            $method = $request->getMethod();

            // Step 5: Check permissions
            if ($this->hasPermission($request, $permissions, $method, $arguments)) {
                return; // Permission found, proceed to the controller
            }
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

        // Step 5: No matching permissions, deny access
        return $this->forbiddenResponse([
            'error_code' => 4,
            'message' => 'Insufficient permissions to access the resource.'
        ]);
    }

    /**
     * After filter (not used in this case).
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // No action needed after the controller is executed for REST API
    }

    /**
     * Extract JWT from the Authorization header.
     */
    private function extractToken($authHeader)
    {
        if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return $matches[1]; // Return the token part
        }
        return null;
    }

    /**
     * Extract the resource ID from the request URI or arguments.
     */
    private function getResourceIdFromRequest($request, $arguments = null)
    {
        // Implement logic to parse the request URI and create the resource ID
        $uriSegments = $request->getUri()->getSegments();

        $resource   = $uriSegments[0] ?? '';
        $value      = $uriSegments[1] ?? '';
        $key        = $value ? "sid" : '';
        return env("app.resourceName") . ":$resource:{" . $key . ':' . $value . "}";
    }

    /**
     * Check if a role has permission to access a resource ID.
     */
    private function hasPermission(RequestInterface $request, $permissions, $method, $arguments)
    {
        // Map HTTP Method to Action
        $httpToActionMap = [
            'GET' => 'read',
            'POST' => 'create',
            'PUT' => 'update',
            'PATCH' => 'update',
            'DELETE' => 'delete'
        ];

        $requestedAction = $httpToActionMap[$method] ?? null;

        if (!$permissions || gettype($permissions) !== 'array') return false;

        foreach ($permissions as $permission) {
            if ($this->resourceMatches($request, $permission, $requestedAction, $arguments)) {
                return true;
            }
        }
    }

    /**
     * Check if the given resource ID matches the permission pattern.
     */
    private function resourceMatches(RequestInterface $request, $permission, $requestedAction, $arguments)
    {
        if (
            !isset($permission->resource) || !isset($permission->actions)
            || gettype($permission->actions) !== 'array'
            || gettype($permission->resource) !== 'string'
        ) throw new \Exception('Invalid permission list.');

        $resourceId = $this->getResourceIdFromRequest($request, $arguments);
     
        // Example matching logic using wildcards or specific values
        return ($permission->resource === '*'
            || $permission->resource === '*:*'
            || $permission->resource === '*:*:{}'
            || $permission->resource === env("app.resourceName") . ':*'
            || $permission->resource === env("app.resourceName") . ':*:{:}'
            || $permission->resource === env("app.resourceName") . ':' .  $request->getUri()->getSegment(1)
            || $permission->resource === env("app.resourceName") . ':' .  $request->getUri()->getSegment(1).":{:}"
            || $permission->resource === $resourceId
        )
            && in_array($requestedAction, $permission->actions);
    }

    /**
     * Return a 401 Unauthorized response.
     */
    private function unauthorizedResponse($data)
    {
        return Services::response()->setJSON($data)->setStatusCode(Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Return a 403 Forbidden response.
     */
    private function forbiddenResponse($data)
    {
        return Services::response()->setJSON($data)->setStatusCode(Response::HTTP_FORBIDDEN);
    }
}
