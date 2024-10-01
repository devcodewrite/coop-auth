<?php

namespace Codewrite\CoopAuth;

class GuardReponse extends CoopResponse
{
    protected $status;

    public function __construct($status, $code, $message = "")
    {
        parent::__construct($status, $code, $message);
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
