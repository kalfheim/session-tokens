<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Illuminate\Database\Schema\Blueprint;
use Alfheim\SessionGuard\SessionGuardServiceProvider;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use Alfheim\SessionGuard\Middleware\AuthenticateSession;

abstract class TestCase extends TestbenchTestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->setUpDatabase();

        $this->withFactories(__DIR__.'/factories');
    }

    protected function getPackageProviders($app)
    {
        return [SessionGuardServiceProvider::class];
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
            AuthenticateSession::class,
        ])->group(__DIR__.'/Fixtures/routes.php');
    }
}
