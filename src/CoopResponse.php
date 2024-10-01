<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;

class CoopResponse implements CoopResponseInterface
{
    protected $message;
    protected $code;
    
    protected $httpStatusMap = [
        0   => Response::HTTP_OK,
        1   => Response::HTTP_NOT_FOUND,
        2   => Response::HTTP_FORBIDDEN,
        3   => Response::HTTP_FORBIDDEN,
        4   => Response::HTTP_FORBIDDEN,
        5   => Response::HTTP_FORBIDDEN,
        6   => Response::HTTP_UNAUTHORIZED,
        7   => Response::HTTP_UNAUTHORIZED,
        8   => Response::HTTP_UNAUTHORIZED,
        9   => Response::HTTP_NOT_FOUND,
        10  => Response::HTTP_BAD_REQUEST
    ];

    public $httpMessageMap = [
        0 => "Ok",
        1 => "Resource not found",
        2 => "Token not provided",
        3 => "Invalid token",
        4 => "Token expired",
        5 => "Invalid condition key",
        6 => "Authorized access",
        7 => "Invalid permission",
        8 => "Insufficient scope",
        9 => "Data not found",
        10 => "Invalid query param columns"
    ];

    public $response;

    public function __construct(bool $status, int $code, string $message = "", array $error = null)
    {
        $this->message  = $message;
        $this->code     = $code;
        if (!$status) {
            $this->response = response()->setJSON([
                'status' => false,
                'code' => $code,
                'message' => $message === "" ? $this->httpMessageMap[$code] : $message,
                'error' => $error
            ])->setStatusCode(
                $this->httpStatusMap[$code],
                $this->httpMessageMap[$code]
            );
        }
    }

    public function responsed(string $message = null, $error = null): ResponseInterface | null
    {
        if ($message) {
            return response()->setJSON([
                'status' => false,
                'code' => $this->code,
                'message' => $message === "" ? $this->httpMessageMap[$this->code] : $message,
                'error' => $error
            ])->setStatusCode(
                $this->httpStatusMap[$this->code],
                $this->httpMessageMap[$this->code]
            );
        }

        return $this->response;
    }
}
