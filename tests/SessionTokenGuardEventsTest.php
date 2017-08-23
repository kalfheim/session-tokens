<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Auth\Events\Attempting;
use Alfheim\SessionTokenGuard\Tests\User;
use Illuminate\Auth\Events\Authenticated;

class SessionTokenGuardEventsTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();

        Event::fake();
    }

    /** @test */
    public function it_should_fire_events_when_attempt_is_successful()
    {
        $user = factory(User::class)->create(['email' => 'foo@example.com']);
        factory(User::class)->create();

        $credentials = ['email' => 'foo@example.com', 'password' => 'secret'];

        Auth::guard()->attempt($credentials, true);

        Event::assertDispatched(Attempting::class, function ($e) use ($credentials) {
            return $e->credentials === $credentials &&
                $e->remember === true;
        });

        Event::assertDispatched(Login::class, function ($e) use ($user) {
            return $e->user->id === $user->id && $e->remember === true;
        });
    }

    /** @test */
    public function it_should_fire_events_when_attempt_is_unsuccessful()
    {
        factory(User::class)->create(['email' => 'foo@example.com']);

        $credentials = ['email' => 'foo@example.com', 'password' => 'wrong'];

        Auth::guard()->attempt($credentials, false);

        Event::assertDispatched(Attempting::class, function ($e) use ($credentials) {
            return $e->credentials === $credentials &&
                $e->remember === false;
        });

        Event::assertDispatched(Failed::class, function ($e) use ($credentials) {
            return $e->credentials === $credentials;
        });
    }

    /** @test */
    public function it_should_fire_authenticated_when_user_is_set()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        Auth::guard()->setUser($user);

        Event::assertDispatched(Authenticated::class, function ($e) use ($user) {
            return $e->user->id === $user->id;
        });
    }

    /** @test */
    public function it_should_fire_logout_event_when_logging_out()
    {
        $this->be($user = factory(User::class)->create());
        factory(User::class)->create();

        Auth::guard()->logout();

        Event::assertDispatched(Logout::class, function ($e) use ($user) {
            return $e->user->id === $user->id;
        });
    }
}
