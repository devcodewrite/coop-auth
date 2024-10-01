<?php

namespace Codewrite\CoopAuth;

use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;

class CoopResponse implements CoopResponseInterface
{
    protected $message;
    protected $code;
    protected $status;
    protected $error;

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
        5 => "Action not allowed",
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
        $this->status   = $status;
        $this->error    = $error;
    }

    public function responsed(string $message = null, $error = null): ResponseInterface | null
    {
        return response()->setJSON([
            'status' => $this->status,
            'code' => $this->code,
            'message' => $message ? $message : $this->httpMessageMap[$this->code],
            'error' => $error ? $error : $this->error
        ])->setStatusCode(
            $this->httpStatusMap[$this->code],
            $this->httpMessageMap[$this->code]
        );
        return $this->response;
    }
}
