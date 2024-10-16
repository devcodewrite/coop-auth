<?php

namespace Codewrite\CoopAuth;

class GuardReponse extends CoopResponse
{
    protected $results;

    public function __construct($status, $code, $message = null, array $results = null)
    {
        parent::__construct($status, $code, null, $message);
        $this->results = $results;
    }

    public function allowed(): bool
    {
        return $this->status;
    }

    public function denied(): bool
    {
        return !$this->status;
    }

    public function results(): array
    {
        return $this->results;
    }
}
