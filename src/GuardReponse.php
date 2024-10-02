<?php

namespace Codewrite\CoopAuth;

class GuardReponse extends CoopResponse
{

    public function __construct($status, $code, $message = null)
    {
        parent::__construct($status, $code, $message);
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
