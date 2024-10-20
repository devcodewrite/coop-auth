<?php

declare(strict_types=1);

namespace Codewrite\CoopAuth;


interface CoopResponseInterface
{
    public const OK                     = 0;    // Ok
    public const NOT_FOUND              = 1;    // resource not found
    public const TOKEN_NOT_PROVIDED     = 2;    // token not provided
    public const INVALID_TOKEN          = 3;    // invalid token
    public const TOKEN_EXPIRED          = 4;    // token expired
    public const ACTION_NOT_ALLOWED     = 5;    // action not allowed
    public const UNAUTHORIZED           = 6;    // authorized access
    public const INVALID_PERMISSION     = 7;    // invalid permission 
    public const INSUFFICIENT_SCOPE     = 8;    // Insufficent scopes
    public const DATA_NOT_FOUND         = 9;    // Data not found
    public const INVALID_COLUMNS        = 10;   // Invalid query columns
    public const INVALID_CREDENTIALS    = 11;   // Invalid credentials
    public const UNVERIFIED_EMAIL       = 12;   // Email is not verified
    public const UNVERIFIED_PHONE       = 13;   // Phone is not verified
}
