<?php
namespace Lyubaev\HTTPHook\Console;

use Symfony\Component\Console\Application as ConsoleApplication;
use Symfony\Component\Console\Command\HelpCommand;
use Symfony\Component\Console\Command\ListCommand;
use Lyubaev\HTTPHook\Console\Command\InitCommand;


class Application extends ConsoleApplication
{
    const NAME = 'HTTPHook';
    const VERSION = '1.0.0';

    public function __construct()
    {
        parent::__construct(static::NAME, static::VERSION);
    }

    public function getDefaultCommands()
    {
        return array(
            new HelpCommand(),
            new ListCommand(),
            new InitCommand()
        );
    }
}
