<?php
namespace Lyubaev\HTTPHook;

use Psr\Log\LogLevel;
use Monolog\Logger;
use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Processor\PsrLogMessageProcessor;
use Jeremeamia\SuperClosure\SerializableClosure;
use Lyubaev\HTTPHook\Console\Command\InitCommand;


class Application
{
    const LOG_LEVEL = LogLevel::NOTICE;
    const LOG_MAX_FILES = 0;

    const USER_LOG_LEVEL = LogLevel::DEBUG;
    const USER_LOG_MAX_FILES = 0;

    protected $log_application;
    protected $log_user;

    private $access_token;
    private $events;

    protected static $levels = array(
        LogLevel::DEBUG,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::WARNING,
        LogLevel::ERROR,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::EMERGENCY
    );

    public function __construct(array $conf = array())
    {
        $main_conf = require __DIR__ . DIRECTORY_SEPARATOR . 'Conf.php';
        $conf = array_replace_recursive($main_conf, $conf);

        $buffer_error = array();
        # Установка журнала приложения.
        if (!empty($conf['log']['application'])) {
            $level = $conf['log']['application']['level'];
            if (!in_array(strtolower($level), self::$levels, true)) {
                # Уровень журнала является недействительным.
                throw new \DomainException("Invalid log level '$level'.");
            }

            $target = $conf['log']['application']['target'];
            if (!is_string($target)) {
                # Недопустимое значение директивы "target".
                throw new \InvalidArgumentException('Invalid value directives log target.');
            }

            if (!is_numeric($conf['log']['application']['max_files'])) {
                # Количество файлов журнала может быть целым и положительным числом.
                $buffer_error[LogLevel::NOTICE] []= 'Number of log files can be whole and positive number.';
                $max_files = self::LOG_MAX_FILES;
            } else {
                $max_files = (int) $conf['log']['application']['max_files'];
            }

            if (empty($target)) {
                goto create_null_log;
            }

            $this->log_application = new Logger('app');
            if (1 === $max_files || preg_match('/^php:\/\/.+$/', $target)) {
                $this->log_application->pushHandler(
                    new StreamHandler($target, $level)
                );
            } else {
                $this->log_application->pushHandler(
                    new RotatingFileHandler($target, $max_files, $level)
                );
            }
            $this->log_application->pushProcessor(new PsrLogMessageProcessor());
        } else {
            create_null_log:
            $this->log_application = new Logger('app', array(new NullHandler()));
        }

        // Сбросим буффер в журнал.
        array_walk($buffer_error, function ($pool, $level, $logger) {
            foreach ($pool as $message) {
                $logger->log($level, $message);
            }
        }, $this->log_application);

        # Установка журнала пользователя.
        if (!empty($conf['log']['user'])) {
            if (isset($conf['log']['user']['level'])) {
                $level = $conf['log']['user']['level'];
                if (!in_array(strtolower($level), self::$levels, true)) {
                    # Уровень журнала является недействительным.
                    $this->error(LogLevel::EMERGENCY, "Invalid log level.", array('level' => $level));
                }
            } else {
                $level = self::USER_LOG_LEVEL;
            }

            $target = $conf['log']['user']['target'];
            if (empty($target)) {
                # Источник журнала не установлен.
                $this->error(LogLevel::EMERGENCY, 'Invalid value directives log target.');
            }

            if (!is_numeric($conf['log']['user']['max_files'])) {
                # Количество файлов журнала может быть целым и положительным числом.
                $this->log(LogLevel::NOTICE, 'Number of log files can be whole and positive number.', array('max_files' => $conf['log']['user']['max_files']));
                $max_files = self::USER_LOG_MAX_FILES;
            } else {
                $max_files = (int) $conf['log']['user']['max_files'];
            }

            $this->log_user = new Logger('user');
            $this->log_user->pushHandler(new RotatingFileHandler($target, $max_files, $level));
        } else {
            $this->log_user = new Logger('user', array(new NullHandler()));
        }

        # Получить токен.
        if (empty($conf['access_token'])) {
            $this->log(LogLevel::ALERT, 'The private key is not installed.');
        } elseif (!isset($conf['access_token']{InitCommand::MIN_LENGTH_ACCESS_TOKEN})) {
            $this->log(LogLevel::WARNING, 'The secret key is unreliable.');
        }

        $this->access_token = $conf['access_token'];
        $this->events = $conf['events'];

        unset($main_conf, $conf, $buffer_error);
    }

    /**
     * Статический метод выполняющий запуск приложения.
     *
     * @param array $conf массив конфигурации пользователя.
     */
    public static function run(array $conf = array())
    {
        $that = new self($conf);
        $that->start();
    }

    public function log($level, $message, array $context = array())
    {
        $this->log_application->log($level, $message, $context);
    }

    public function error($level, $message, array $context = array())
    {
        $this->log_application->log($level, $message, $context);
        exit(1);
    }

    /**
     * Метод выполняет проверку прав доступа к приложению, сравнивая
     * полученный access_token с токеном в конфиг. файле.
     *
     * Метод получает "сырые" данные от сервера, переданные методом POST.
     * Данные анализируются на предмет поступившего события. Если событие
     * зарегистрировано, его обработчик будет вызван.
     *
     * В обработчик передаются 2 параметра:
     * массив принятых декодированных данных
     * объект логгера
     */
    public function start()
    {
        # Авторизация.
        if (array_key_exists('access_token', $_GET)) {
            if (strcmp($this->access_token, $_GET['access_token'])) {
                header('HTTP/1.1 401 Unauthorized');
                # Авторизация не удалась. Недопустимый токен.
                $this->error(LogLevel::EMERGENCY, 'Authorization failed. Invalid token.');
            }
        } else {
            header('HTTP/1.1 401 Unauthorized');
            # Авторизация не удалась. Используйте токен.
            $this->error(LogLevel::EMERGENCY, 'Access denied. Requires a token.');
        }

        $input = json_decode(file_get_contents('php://input'), true);
        if (null == $input) {
            if (0 !== json_last_error()) {
                $this->log(LogLevel::WARNING, self::jsonErrorMessage());
            }
            $this->error(LogLevel::ERROR, 'Broken data from the server GitLab.');
        }

        if (!isset($input['object_kind'])) {
            # Получено неизвестное событие.
            $this->error(LogLevel::ALERT, 'Received unknown event.');
        }

        $event = $input['object_kind'];
        if (empty($this->events[$event])) {
            # Событие не отслеживается.
            $this->log(LogLevel::INFO, sprintf('The event "%s" is not monitored.', $event));
            exit(0);
        }
        if (is_string($this->events[$event]) && strpos($this->events[$event], 'SerializableClosure')) {
            $this->events[$event] = unserialize($this->events[$event])->getClosure();
        }

        if (is_callable($this->events[$event])) {
            call_user_func($this->events[$event], $input, clone($this->log_user));
            return;
        }

        # Вызвать каждый метод "actionMethod".
        $this->events[$event] = (array) $this->events[$event];
        foreach ($this->events[$event] as $class) {
            $instance = new $class;
            $ref_class = new \ReflectionClass($class);
            $ref_methods = $ref_class->getMethods(\ReflectionMethod::IS_PUBLIC);

            foreach ($ref_methods as $method) {
                if ('action' === substr($method->getName(), 0, 6)) {
                    $method->invoke($instance, $input, clone($this->log_user));
                }
            }
        }
    }

    private static function jsonErrorMessage()
    {
        if (function_exists('json_last_error_msg')) {
            return json_last_error_msg();
        }

        static $errors = array(
            JSON_ERROR_NONE           => 'No Error',
            JSON_ERROR_DEPTH          => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Underflow or the modes mismatch',
            JSON_ERROR_CTRL_CHAR      => 'Unexpected control character found',
            JSON_ERROR_SYNTAX         => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8           => 'Malformed UTF-8 characters, possibly incorrectly encoded'
        );

        $code = json_last_error();

        return isset($errors[$code]) ? $errors[$code] : "Unknown error ({$code})";
    }
}
