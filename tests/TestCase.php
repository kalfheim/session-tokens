<?php

namespace Alfheim\SessionTokens\Tests;

use RuntimeException;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Assert as PHPUnit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\TestResponse;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use Alfheim\SessionTokens\SessionTokensServiceProvider;

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

        TestResponse::macro('retrieveCookie', function ($cookieName) {
            $cookie = $this->getCookie($cookieName);

            if (! $cookie) {
                throw new RuntimeException('Could not retrieve cookie ['.$cookieName.']');
            }

            return $cookie;
        });
    }

    protected function getPackageProviders($app)
    {
        return [SessionTokensServiceProvider::class];
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
        // @todo: switch to the "web" middleware group when the commit to include
        // AddQueuedCookiesToResponse in orchestra testbench is tagged
        $this->app['router']->middleware([
            \Illuminate\Cookie\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\Middleware\StartSession::class,
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,
            \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class,
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ])->group(__DIR__.'/Fixtures/routes.php');
    }
}
