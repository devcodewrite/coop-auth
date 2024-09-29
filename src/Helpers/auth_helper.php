<?php

if (! function_exists('auth')) {
    function auth()
    {
        static $instance = null;

        if ($instance === null) {
            // Instantiate the Auth class with current token or context
            $instance = new \Codewrite\CoopAuth\Auth(); // Adjust initialization as necessary
        }

        return $instance;
    }
}
