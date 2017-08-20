<?php

namespace Alfheim\SessionTokenGuard;

use Illuminate\Support\ServiceProvider;
use Illuminate\Auth\CreatesUserProviders;

class SessionTokenGuardServiceProvider extends ServiceProvider
{
    use CreatesUserProviders;

    public function boot()
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/migrations');

        // $this->commands(Commands\SessionTokensFlushCommand::class);

        $this->registerSessionTokenGuard();
    }

    /**
     * Register the session token guard with the auth manager.
     *
     * @return void
     */
    protected function registerSessionTokenGuard()
    {
        // @todo: maybe use a different name?

        $this->app['auth']->extend('session', function ($app, $name, $config) {
            return $this->createSessionTokenGuard($name, $config);
        });
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
            $guard->setCookie($this->app['cookie']);

            $guard->setDispatcher($this->app['events']);

            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        });
    }
}
