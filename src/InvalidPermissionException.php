<?php

namespace Codewrite\CoopAuth\Exceptions;

use Exception;

class InvalidPermissionException extends Exception
{
    /**
     * InvalidPermissionException constructor.
     * @param string $message
     * @param int $code
     * @param Exception|null $previous
     */
    public function __construct(string $message = "Invalid permission", int $code = 403, ?Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Custom string representation of the exception.
     *
     * @return string
     */
    public function __toString(): string
    {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}
