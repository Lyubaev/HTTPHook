<?php
require __DIR__ . '/../vendor/autoload.php';

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'user_conf.php')) {
    $conf = include __DIR__ . DIRECTORY_SEPARATOR . 'user_conf.php';
} else {
    $conf = array(
        /**
         * User conf...
         */
    );
}

Lyubaev\HTTPHook\Application::run($conf);
