<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;

class ErrorResponse implements ErrorResponseInterface
{
    protected $message;
    protected $code;
    protected $httpStatusMap = [
        1 => Response::HTTP_NOT_FOUND,
        2 => Response::HTTP_FORBIDDEN,
        3 => Response::HTTP_FORBIDDEN,
        4 => Response::HTTP_FORBIDDEN,
        5 => Response::HTTP_FORBIDDEN,
        6 => Response::HTTP_UNAUTHORIZED,
        7 => Response::HTTP_UNAUTHORIZED,
    ];

    protected $httpMessageMap = [
        1 => "Resource not found",
        2 => "Token not provided",
        3 => "Invalid token",
        4 => "Token expired",
        5 => "Invalid condition key",
        6 => "Authorized access",
        7 => "Invalid permission",
    ];

    public $response;

    public function __construct(bool $status, int $code, string $message = "")
    {
        $this->message  = $message;
        $this->code     = $code;
        if ($status) {
            $this->response = response()->setJSON([
                'message' => $message,
                'code' => $code,
                'status' => false
            ])->setStatusCode(
                $this->httpStatusMap[$code],
                $this->httpMessageMap[$code]
            );
        }
    }

    public function responsed(): ResponseInterface
    {
        return $this->response;
    }
}
