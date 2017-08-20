<?php

namespace Alfheim\SessionGuard;

use Illuminate\Support\ServiceProvider;
use Illuminate\Auth\CreatesUserProviders;

class SessionTokenGuardServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->loadMigrationsFrom(dirname(__DIR__).'/migrations');

        // $this->commands(Commands\SessionTokensFlushCommand::class);

        $this->registerSessionGuard();
    }

    /**
     * Register the session token guard with the auth manager.
     *
     * @return void
     */
    protected function registerSessionGuard()
    {
        // @todo: maybe use a different name?

        $this->app['auth']->extend('session', function ($app, $name, $config) {
            return $this->createSessionGuard($name, $config);
        });
    }

    /**
     * Create an instance of the session token guard.
     *
     * @param  string $name
     * @param  array  $config
     * @return void
     */
    protected function createSessionGuard($name, $config)
    {
        $provider = new SessionTokenAwareUserProvider(
            $this->createUserProvider($config['provider'])
        );

        return tap(new SessionGuard($name, $provider, $this->app['session.store']), function ($guard) {
            $guard->setCookieJar($this->app['cookie']);

            $guard->setDispatcher($this->app['events']);

            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        });
    }
}
