<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Carbon\Carbon;
use PHPUnit\Framework\Assert as PHPUnit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\TestResponse;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use Alfheim\SessionTokenGuard\SessionTokenGuardServiceProvider;

abstract class TestCase extends TestbenchTestCase
{
    protected function setUp()
    {
        parent::setUp();

        app('hash')->setRounds(4);

        $this->setUpDatabase();

        $this->setUpRoutes();

        $this->withFactories(__DIR__.'/factories');

        Carbon::setTestNow(null);

        TestResponse::macro('assertCookieIsNotQueued', function ($cookieName) {
            PHPUnit::assertNull(
                $this->getCookie($cookieName),
                "Cookie [{$cookieName}] is unexpectedly present on response."
            );
        });

        TestResponse::macro('assertCookieIsCleared', function ($cookieName) {
            PHPUnit::assertTrue(
                $this->getCookie($cookieName)->isCleared(),
                "Cookie [{$cookieName}] is expected to be cleared."
            );
        });
    }

    protected function getPackageProviders($app)
    {
        return [SessionTokenGuardServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('app.debug', true);

        $app['config']->set('app.key', 'base64:O+nkeNb+91gU/5q8aQwrduDOithO8kHPABJU1A+MjVE=');

        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('database.default', 'test');

        $app['config']->set('database.connections.test', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
        ]);
    }

    protected function setUpDatabase()
    {
        $this->app['db']->connection()->getSchemaBuilder()->create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });

        $this->artisan('migrate', ['--database' => 'test']);
    }

    protected function setUpRoutes()
    {
        $this->app['router']->middleware([
            'web',
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        ])->group(__DIR__.'/Fixtures/routes.php');
    }
}
