<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\Config\Services;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Model;

class ApiResponse
{
    protected $model;
    protected $params;
    protected $tableName;
    protected $allowedColumns = [];
    protected $scopes;

    /**
     * Constructor to initialize the model and request parameters.
     *
     * @param Model $model The CodeIgniter model instance.
     * @param array $params Request parameters for columns, filters, sort, and pagination.
     * @param array $allowedColumns List of allowed columns for the response.
     */
    public function __construct(Model &$model, array $params, array $allowedColumns)
    {
        $this->model = $model;
        $this->params = $params;
        $this->allowedColumns = $allowedColumns;
        $this->tableName = $model->getTable(); // Get the associated table name
    }

    /**
     * Process the query for a collection of data and return a structured response.
     *
     * @return array Structured JSON response for a collection.
     */
    public function getCollectionResponse($check = false, array $scopes = []): ResponseInterface
    {
        $this->scopes = $scopes;

        // Parse and validate columns
        $columns = $this->validateColumns($this->params['columns'] ?? '*');
        if (isset($columns['error'])) {
            return Services::response()->setJSON($columns)
                ->setStatusCode(Response::HTTP_BAD_REQUEST); // Return error if columns are invalid
        }

        $filters   = $this->params['filters'] ?? [];
        $sort      = $this->params['sort'] ?? [];
        $page      = isset($this->params['page']) ? (int) $this->params['page'] : 1;
        $pageSize  = isset($this->params['pageSize']) ? (int) $this->params['pageSize'] : 10;

        // Apply filters
        if (!empty($filters)) {

            foreach ($filters as $column => $value) {
                if (in_array($column, $this->allowedColumns)) {
                    $this->model->where($column, $value);
                }
            }
        }

        // Apply column selection
        if ($columns !== '*') {
            $this->model->select($columns);
        }

        // Apply sorting
        if (!empty($sort)) {
            foreach ($sort as $column => $direction) {
                if (in_array($column, $this->allowedColumns)) {
                    $this->model->orderBy($column, strtoupper($direction));
                }
            }
        }

        // Get total count
        $totalItems = $this->model->countAllResults(false);

        // Apply pagination
        $offset = ($page - 1) * $pageSize;
        $results = $this->model->findAll($pageSize, $offset);

        if ($check) {
            $guard = auth()->can('view', $this->tableName, $scopes, $results);
            if ($guard->denied()) return $guard->responsed();
            $results = $guard->results();
        }

        // Calculate total pages
        $totalPages = (int) ceil($totalItems / $pageSize);

        return Services::response()->setJSON([
            'status' => true,
            'code' => 0,
            'message' => "'{$this->tableName}' retrieved successfully.",
            'data' => $results,
            'metadata' => [
                'currentPage' => $page,
                'totalPages' => $totalPages,
                'pageSize' => $pageSize,
                'totalItems' => $totalItems,
                'links' => $this->generateLinks($page, $totalPages)
            ]
        ])->setStatusCode(Response::HTTP_OK);
    }

    /**
     * Process the query for a single data item and return a structured response.
     *
     * @return array Structured JSON response for a single data item.
     */
    public function getSingleResponse($check = false, $scopes = []): ResponseInterface
    {
        $this->scopes = $scopes;

        // Parse and validate columns
        $columns = $this->validateColumns($this->params['columns'] ?? '*');
        if (isset($columns['error'])) {
            return Services::response()->setJSON($columns)
                ->setStatusCode(Response::HTTP_BAD_REQUEST); // Return error if columns are invalid
        }

        $filters = $this->params['filters'] ?? [];

        // Apply filters
        if (!empty($filters)) {
            foreach ($filters as $column => $value) {
                if (in_array($column, $this->allowedColumns)) {
                    $this->model->where($column, $value);
                }
            }
        }

        // Apply column selection
        if ($columns !== '*') {
            $this->model->select($columns);
        }

        // Retrieve the single record
        $result = $this->model->first();

        if(!$result) {
            return Services::response()->setJSON([
                'status'    => false,
                'code'      => CoopResponse::DATA_NOT_FOUND,
                'message'   => "No record found in the '{$this->tableName}' matching the criteria.",
                'data'      => null,
                'error'     => null
            ])->setStatusCode(Response::HTTP_NOT_FOUND);
        }

        if ($check) {
            $guard = auth()->can('view', $this->tableName, $scopes, [$result]);
            if ($guard->denied()) return $guard->responsed();
            $result = $guard->results();
        }

        if ($result) {
            return Services::response()->setJSON([
                'status' => true,
                'code' => 0,
                'message' => "'{$this->tableName}' retrieved successfully.",
                'data' => $result
            ])->setStatusCode(Response::HTTP_OK);
        }
    }

    /**
     * Validate the requested columns against allowed columns.
     *
     * @param string|array $requestedColumns The columns requested in the API call.
     * @return string|array Validated columns string or error response.
     */
    private function validateColumns($requestedColumns)
    {
        // If columns are set to "*", allow all columns
        if ($requestedColumns === '*') {
            return '*';
        }

        // Convert columns to an array if provided as a comma-separated string
        $columnsArray = is_string($requestedColumns) ? explode(',', $requestedColumns) : $requestedColumns;

        // Check if all requested columns are allowed
        $invalidColumns = count($this->allowedColumns) === 0 ? [] : array_diff($columnsArray, $this->allowedColumns);

        if (!empty($invalidColumns)) {
            return [
                'status' => false,
                'code' => CoopResponse::INVALID_COLUMNS,
                'message' => "The following columns are not allowed: " . implode(', ', $invalidColumns),
                'data' => null,
                'error' => [
                    'code' => 'INVALID_COLUMNS',
                    'message' => 'One or more requested columns are not permitted.',
                    'details' => $invalidColumns
                ]
            ];
        }

        // Return validated columns as a comma-separated string
        return implode(',', array_merge($this->scopes, $columnsArray));
    }

    /**
     * Generate pagination links for collection response.
     *
     * @param int $currentPage Current page number.
     * @param int $totalPages Total number of pages.
     * @return array Navigation links.
     */
    private function generateLinks(int $currentPage, int $totalPages): array
    {
        $baseUrl = current_url(); // Get the current URL

        $params = $this->params;
        $params['page'] = 1;
        $first = $baseUrl . '?' . http_build_query($params);

        $params['page'] = $currentPage > 1 ? $currentPage - 1 : null;
        $previous = $params['page'] ? $baseUrl . '?' . http_build_query($params) : null;

        $params['page'] = $currentPage < $totalPages ? $currentPage + 1 : null;
        $next = $params['page'] ? $baseUrl . '?' . http_build_query($params) : null;

        $params['page'] = $totalPages;
        $last = $baseUrl . '?' . http_build_query($params);

        return [
            'first' => $first,
            'previous' => $previous,
            'next' => $next,
            'last' => $last
        ];
    }
}
