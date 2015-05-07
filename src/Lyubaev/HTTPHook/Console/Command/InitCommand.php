<?php
namespace Lyubaev\HTTPHook\Console\Command;

use Psr\Log\LogLevel;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Lyubaev\HTTPHook\Application;


class InitCommand extends Command
{
    const MIN_LENGTH_ACCESS_TOKEN = 8;
    const DEF_LENGTH_ACCESS_TOKEN = 64;
    const MAX_LENGTH_ACCESS_TOKEN = 128;

    private static $user_conf = 'user_conf.php';
    private static $greetings = '  Welcome to the HTTPHook config generator!  ';

    private static $gitlab_events = array(
        'push',
        'tag_push',
        'issue',
        'merge_request'
    );

    private static $log_levels = array(
        LogLevel::DEBUG,
        LogLevel::INFO,
        LogLevel::NOTICE,
        LogLevel::WARNING,
        LogLevel::ERROR,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::EMERGENCY
    );

    private $events = array();
    private $logger = array();

    public function __construct()
    {
        $this->events = array_fill_keys(self::$gitlab_events, array());

        parent::__construct('init');
    }

    protected function configure()
    {
        $this
            ->setDescription(sprintf('Creates %s file in current directory', self::$user_conf))
            ->addOption(
                'length-token',
                's',
                InputOption::VALUE_OPTIONAL,
                sprintf(
                    'The length of the private token. Range [%d, %d]',
                    self::MIN_LENGTH_ACCESS_TOKEN,
                    self::MAX_LENGTH_ACCESS_TOKEN
                ),
                self::DEF_LENGTH_ACCESS_TOKEN
            )
            ->addArgument(
                'reset',
                InputArgument::OPTIONAL,
                'Reset private token.'
            )
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $length_token = (int) $input->getParameterOption(array('--length-token', '-s'), self::DEF_LENGTH_ACCESS_TOKEN);
        if ($length_token < self::MIN_LENGTH_ACCESS_TOKEN) {
            $length_token = self::MIN_LENGTH_ACCESS_TOKEN;
        } elseif ($length_token > self::MAX_LENGTH_ACCESS_TOKEN) {
            $length_token = self::MAX_LENGTH_ACCESS_TOKEN;
        }

        if ('reset' === $input->getArgument('reset')) {
            if (file_exists(self::$user_conf)) {
                $user_conf = include self::$user_conf;
                $user_conf['access_token'] = self::generateToken($length_token);
                $output->writeln('');
                $output->writeln("<info>Your token: {$user_conf['access_token']}</info>");
                goto save_conf;
            } else {
                $output->writeln('');
                $output->writeln(sprintf('<error> File %s not found! </error>', self::$user_conf));
                return false;
            }
        }

        $output->writeln('');
        $output->writeln(sprintf('<question>%s</question>', str_repeat(' ', strlen(self::$greetings))));
        $output->writeln(sprintf('<question>%s</question>', self::$greetings));
        $output->writeln(sprintf('<question>%s</question>', str_repeat(' ', strlen(self::$greetings))));
        $output->writeln('');
        $output->writeln('This command will guide you through creating your config.');
        $output->writeln('');

        $this->selectEventType($input, $output);
        $this->selectLogger($input, $output);

        $user_conf = array_merge(
            array('events' => $this->events),
            array('log' => $this->logger),
            array('access_token' => self::generateToken($length_token))
        );

        dump($user_conf);

        $helper = $this->getHelper('question');
        $question = new ConfirmationQuestion(
            $this->highlight('Do you confirm generation?', '[Yes]')
        );
        if (!$helper->ask($input, $output, $question)) {
            $output->write('<error> Command aborted </error>');
            return ;
        }

        save_conf:
        file_put_contents(self::$user_conf, sprintf("<?php\nreturn %s;", var_export($user_conf, true)));
    }

    protected function selectEventType(InputInterface $input, OutputInterface $output)
    {
        $helper = $this->getHelper('question');
        do {
            # Выбрать тип события из списка.
            $question = new ChoiceQuestion(
                $this->highlight('Please select event type:'),
                array_merge(self::$gitlab_events, array('skip...'))
            );

            $question->setErrorMessage('Enter the correct value.');
            $event = $helper->ask($input, $output, $question);

            if (!in_array($event, self::$gitlab_events, true)) {
                break;
            }

            $question = new Question(
                $this->highlight('Please enter the name of the class completely:'),
                ''
            );
            $question->setValidator(function ($answer) {
                if (!preg_match('/^[a-zA-Z_\x7f-\xff][\\a-zA-Z0-9_\x7f-\xff]*$/', $answer)) {
                    throw new \RuntimeException('Invalid format.');
                }
                $length = strlen($answer);
                if ('\\' === $answer[$length - 1]) {
                    throw new \RuntimeException('Prefix not must end with a namespace separator.');
                }

                return $answer;
            });
            $prefix = $helper->ask($input, $output, $question);

            $this->events[$event][] = $prefix;
            $this->events[$event] = array_unique($this->events[$event]);

            $question = new ConfirmationQuestion(
                $this->highlight('Continue?', '[Yes]')
            );
            if (!$helper->ask($input, $output, $question)) {
                break;
            }

        } while (1);
    }

    protected function selectLogger(InputInterface $input, OutputInterface $output)
    {
        $helper = $this->getHelper('question');

        # Включить журнал приложения?
        $question = new ConfirmationQuestion(
            $this->highlight('Enable application log?', '[Yes]')
        );
        if ($helper->ask($input, $output, $question)) {
            # Пожалуйста введите путь к файлу журнала.
            $question = new Question($this->highlight('Please enter the path to the log file:'));
            $question->setValidator(function ($answer) {
                //TODO file://wrapper and php://output
                if (empty($answer)) {
                    throw new \RuntimeException('The path is invalid');
                }
                return $answer;
            });
            $target = $helper->ask($input, $output, $question);

            # Пожалуйста выберете уровень логирования.
            $question = new ChoiceQuestion(
                $this->highlight('Please select the level of logging:', sprintf('[%s]', Application::LOG_LEVEL)),
                self::$log_levels,
                array_search(Application::LOG_LEVEL, self::$log_levels, true)
            );
            $question->setErrorMessage('Option %s is invalid.');
            $level = $helper->ask($input, $output, $question);

            # Пожалуйста введите количество файлов журнала.
            $question = new Question(
                $this->highlight('Please enter the number of log files:', sprintf('[%d]',Application::LOG_MAX_FILES)),
                Application::LOG_MAX_FILES
            );
            $question->setValidator(function ($answer) {
                if (!is_numeric($answer)) {
                    throw new \RuntimeException(sprintf('The number "%s" is invalid, matching: /^\d+$/', $answer));
                }
                return $answer;
            });
            $max_files = $helper->ask($input, $output, $question);

            $this->logger['application'] = array(
                'level' => $level,
                'target' => $target,
                'max_files' => $max_files
            );
        }

        # Включить журнал пользователя?
        $question = new ConfirmationQuestion(
            $this->highlight('Enable user log?', '[Yes]')
        );
        if ($helper->ask($input, $output, $question)) {
            # Пожалуйста введите путь к файлу журнала.
            $question = new Question($this->highlight('Please enter the path to the log file:'));
            $question->setValidator(function ($answer) {
                if (empty($answer)) {
                    throw new \RuntimeException('The path is invalid');
                }
                return $answer;
            });
            $target = $helper->ask($input, $output, $question);

            # Пожалуйста введите количество файлов журнала.
            $question = new Question(
                $this->highlight('Please enter the number of log files:', sprintf('[%d]', Application::USER_LOG_MAX_FILES)),
                Application::USER_LOG_MAX_FILES
            );
            $question->setValidator(function ($answer) {
                if (!is_numeric($answer)) {
                    throw new \RuntimeException(sprintf('The number "%s" is invalid, matching: /^\d+$/', $answer));
                }
                return $answer;
            });
            $max_files = $helper->ask($input, $output, $question);

            $this->logger['user'] = array(
                'target' => $target,
                'max_files' => $max_files
            );
        }
    }

    public static function generateToken($length)
    {
        $ascii = array_merge(
            # digital
            range(48, 57),
            # upper case
            range(65, 90),
            # lower case
            range(97, 122),
            # -_
            array(45, 95)
        );

        $token = array();
        $length += 1;
        while (--$length) {
            $token []= chr($ascii{array_rand($ascii)});
        }

        return implode($token);
    }

    private function highlight($question, $default = '[]')
    {
        return "<info>$question</info> <comment>$default</comment> ";
    }
}
