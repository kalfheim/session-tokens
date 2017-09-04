<?php

namespace Alfheim\SessionTokens;

use Illuminate\Support\ServiceProvider;
use Illuminate\Auth\CreatesUserProviders;
use Alfheim\SessionTokens\Console\MakeSessionTokensCommand;
use Alfheim\SessionTokens\Console\SessionTokensFlushCommand;

class SessionTokensServiceProvider extends ServiceProvider
{
    use CreatesUserProviders;

    public function boot()
    {
        $this->registerGuard();

        $this->loadMigrationsFrom(dirname(__DIR__).'/migrations');

        $this->registerCommands();
    }

    /**
     * Register the session token guard with the auth manager.
     *
     * @return void
     */
    protected function registerGuard()
    {
        $driver = $this->getDriverName();

        $this->app['auth']->extend($driver, function ($app, $name, $config) {
            return $this->createSessionTokenGuard($name, $config);
        });
    }

    /**
     * Register console commands.
     *
     * @return void
     */
    protected function registerCommands()
    {
        $this->commands([
            MakeSessionTokensCommand::class,
            SessionTokensFlushCommand::class,
        ]);
    }

    /**
     * Create an instance of the session token guard.
     *
     * @param  string $name
     * @param  array  $config
     * @return void
     */
    protected function createSessionTokenGuard($name, $config)
    {
        $provider = $this->createUserProvider($config['provider']);

        return tap(new SessionTokenGuard($name, $provider, $this->app['session.store']), function ($guard) {
            $guard->setCookieJar($this->app['cookie']);

            $guard->setDispatcher($this->app['events']);

            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        });
    }

    /**
     * Get the name to be used for the guard driver.
     *
     * @return string
     */
    protected function getDriverName()
    {
        return $this->app['config']->get('auth.session_tokens.driver_name', 'session');
    }
}
