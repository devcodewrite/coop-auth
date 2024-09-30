<?php

namespace Codewrite\CoopAuth\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\Response;
use CodeIgniter\API\ResponseTrait;


class JwtFilter implements FilterInterface
{
    use ResponseTrait;
    /**
     * Before filter to check permissions for REST API access.
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Map HTTP Method to Action
        $httpToActionMap = [
            'GET' => 'view',
            'POST' => 'create',
            'PUT' => 'update',
            'PATCH' => 'update',
            'DELETE' => 'delete'
        ];

        $requestedAction = $httpToActionMap[$request->getMethod()] ?? null;
        return auth()->can($requestedAction, $request->getUri()->getSegment(1))->responsed();
    }

    /**
     * After filter (not used in this case).
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // No action needed after the controller is executed for REST API
    }

    /**
     * Return a 401 Unauthorized response.
     */
    private function unauthorizedResponse($data)
    {
        return response()->setJSON($data)->setStatusCode(Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Return a 403 Forbidden response.
     */
    private function forbiddenResponse($data)
    {
        return response()->setJSON($data)->setStatusCode(Response::HTTP_FORBIDDEN);
    }
}
