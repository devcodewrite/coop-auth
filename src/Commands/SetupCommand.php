<?php

namespace Codewrite\CoopAuth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;

class SetupCommand extends BaseCommand
{
    protected $group       = 'CoopAuth';
    protected $name        = 'coopauth:setup';
    protected $description = 'Setup the CoopAuth library by publishing configuration and other necessary files.';

    /**
     * The main function that gets executed when the command is called.
     */
    public function run(array $params)
    {
        // Ask the user if they want to publish the config file.
        CLI::write('Setting up CoopAuth library...', 'green');

        // Ask for confirmation to publish config file.
        if (CLI::prompt('Do you want to publish the configuration file?', ['y', 'n']) === 'y') {
            $this->publishConfig();
        }
     
        if (CLI::prompt('Do you want to publish the helper file?', ['y', 'n']) === 'y') {
            $this->publishHelper();
        }

        CLI::write('CoopAuth setup is complete!', 'green');
    }

    /**
     * Publishes the configuration file to the CodeIgniter project.
     */
    protected function publishConfig()
    {
        // Get the current path of the config file in the package.
        $source = __DIR__ . '/../Config/CoopAuth.php';

        // Determine the destination path in the target CodeIgniter project.
        $destination = ROOTPATH . 'app/Config/CoopAuth.php';

        // Copy the config file.
        if (! is_file($source)) {
            CLI::error('Configuration file not found.');
            return;
        }

        if (copy($source, $destination)) {
            CLI::write("Configuration file published to `app/Config/CoopAuth.php`", 'yellow');
        } else {
            CLI::error("Failed to publish configuration file.");
        }
    }

    /**
     * Publishes the configuration file to the CodeIgniter project.
     */
    protected function publishHelper()
    {
        // Get the current path of the config file in the package.
        $source = __DIR__ . '/../Helpers/auth_helper.php';

        // Determine the destination path in the target CodeIgniter project.
        $destination = ROOTPATH . 'app/Helpers/auth_helper.php';

        // Copy the config file.
        if (! is_file($source)) {
            CLI::error('Helper file not found.');
            return;
        }

        if (copy($source, $destination)) {
            CLI::write("Helper file published to `app/Helpers/auth_helper.php`", 'yellow');
        } else {
            CLI::error("Helper to publish fitler file.");
        }
    }
}
