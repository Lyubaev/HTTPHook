# HTTPHook
HTTPHook - веб-приложение для обработки прослушиваемых событий вашего приложения.

###### Поддерживает:
- Авторизацию по токену
- Несколько обработчиков одного события
- Журнал приложения и журнал пользователя
- Генератор конфигурационного файла

###### Обрабатываемые события
- push
- tag_push
- issue
- merge_request

###### Авторизация по токену
Для доступа к приложению используется секретный ключ, передаваемый в GET строке с параметром *access_token*.
```
http://example.org?access_token=your_secret_key
```

###### Обработчики событий:
Для обработки события используется функция, принимающая два параметра.
Первый параметр - *массив*, содержащий данные о произошедшем событии.
Второй параметр - *объект логгера*.
```php
<?php
# Отрывок конфигурационного файла.
return [
  ...
  'push' => function (array $input, Psr\Log\LoggerInterface $log) {
    // Некоторые действия...
  },
  'tag_push' => ...
  ...
];
```

Для использования нескольких обработчиков, можно использовать открытые методы класса, которые начинаются словом *action*. **Порядок выполнения методов может быть произвольным!**

```php
<?php
namespace Acme;

class My_Handlers
{
  public function actionFoo(array $input, Psr\Log\LoggerInterface $log)
  {
    // Некоторые действия...
  }

  public function actionBar(array $input, Psr\Log\LoggerInterface $log)
  {
    // Некоторые действия...
  }
}
```

Зарегистрируйте класс:
```php
<?php
# Отрывок конфигурационного файла.
return [
  ...
  'push' => 'Acme\My_Handlers',
  'tag_push' => ...
  ...
];
```

Вы должны будете включить файл содержащий класс до вызова метода выполнения приложения. Другой вариант, воспользоваться автозагрузчиком Composer.
```json
"autoload": {
  "psr-4": {
    "Acme\\": "public/Acme"
  }
}
```

###### Журналы
Журнал содержит сообщения событий, которые могут произойти в процессе работы приложения. Поддерживаются события 8 уровней: *debug*, *info*, *notice*, *warning*, *error*, *critical*, *alert*, *emergency*.

```php
<?php
# Отрывок конфигурационного файла.
return [
  ...
  'log' => [
    'application' => [
        'level' => 'warning',
        'target' => '/var/log/app.log',
        'max_files' => 1
    ],
    ...
  ],
  ...
];
```
В примере выше приложение будет отслеживать события выше уровня notice и записывать сообщения в файл */var/log/app.log*. Директива `max_files` будет отслеживать максимальное количество журналов. Если установлено в 1, всегда будет только один файл журнала. Значение 0 - каждый день будет создаваться новый журнал, при этом старые не удаляются.

Журнал пользователя настраивается по аналогии с журналом приложения, за исключением того, что ему не доступна директива `level`. По умолчанию она установлена в *debug*.
```php
<?php
# Отрывок конфигурационного файла.
return [
  ...
  'log' => [
    'application' => [
        'level' => 'warning',
        'target' => '/var/log/app.log',
        'max_files' => 1
    ],
    'user' => [
      'target' => '/var/log/user.log'
    ]
  ],
  ...
];
```

###### Генератор конфигурационного файла
Процесс создания конфигурационного файла может быть утомительным. Воспользуйтесь генератором конфигурационного файла, запустив консольную утилиту `src/bin/http_hook` с командой `init`. По окончанию работы она создаст новый файл *user_conf.php* в текущий директории и автоматически сгенерирует секретный ключ. Используйте его для доступа к приложению.

##### Зависимости:
- "php": ">=5.3.0",
- "monolog/monolog": "~1.13",
- "symfony/console": "^2.6.6",
- "symfony/var-dumper": "^2.6.6"
