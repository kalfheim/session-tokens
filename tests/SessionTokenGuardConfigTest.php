<?php

namespace Alfheim\SessionTokens\Tests;

use Illuminate\Auth\SessionGuard;
use Illuminate\Support\Facades\Auth;
use Alfheim\SessionTokens\SessionTokenGuard;

class SessionTokenGuardConfigTest extends TestCase
{
    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('auth.session_token_guard_driver', 'sessionTokenDriver');

        $app['config']->set('auth.guards.sessionToken', [
            'driver'   => 'sessionTokenDriver',
            'provider' => 'users',
        ]);
    }

    /** @test */
    public function it_should_use_the_laravel_session_guard_by_default()
    {
        $this->assertSame(get_class(Auth::guard()), SessionGuard::class);
    }

    /** @test */
    public function it_should_work_as_a_custom_guard()
    {
        factory(User::class)->create(['email' => 'foo@example.com']);
        factory(User::class)->create();

        $guard = Auth::guard('sessionToken');

        $this->assertSame(get_class($guard), SessionTokenGuard::class);

        $this->assertTrue($guard->attempt([
            'email'    => 'foo@example.com',
            'password' => 'secret',
        ]));
    }
}
