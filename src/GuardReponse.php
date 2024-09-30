<?php

namespace Codewrite\CoopAuth;

class GuardReponse extends ErrorResponse
{
    protected $status;

    public function __construct($status, $errorCode, $message = "")
    {
        parent::__construct($status, $errorCode, $message);
        $this->status = $status;
    }
    public function allowed(): bool
    {
        return $this->status;
    }

    public function denied(): bool
    {
        return !$this->status;
    }
}
