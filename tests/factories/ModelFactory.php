<?php

use Alfheim\SessionTokenGuard\Tests\User;
use Alfheim\SessionTokenGuard\SessionToken;

$factory->define(User::class, function ($faker) {
    static $password;

    return [
        'name' => $faker->name,
        'email' => $faker->unique()->safeEmail,
        'password' => $password ?: $password = bcrypt('secret'),
    ];
});

$factory->define(SessionToken::class, function ($faker) {
    return [
        'secret' => str_random(60),
        'authenticatable_id' => function () {
            return factory(User::class)->create()->id;
        },
        'ip_address' => $faker->{mt_rand(0, 1) === 1 ? 'ipv6' : 'ipv4'},
        'user_agent' => $faker->userAgent,
    ];
});
