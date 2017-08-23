<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Events\Attempting;
use Alfheim\SessionTokenGuard\SessionToken;
use Alfheim\SessionTokenGuard\SessionTokenGuard;

class SessionTokenGuardTest extends TestCase
{
    /** @test */
    public function it_should_use_the_correct_guard()
    {
        $this->get('guard')->assertSee('Alfheim\SessionTokenGuard\SessionTokenGuard');
    }

    /** @test */
    public function it_should_deny_when_credentials_are_incorrect()
    {
        factory(User::class)->create(['email' => 'foo@example.com']);

        $this->post('login', ['email' => 'foo@example.com', 'password' => 'wrong'])
             ->assertSee('Bad credentials');

        $this->assertGuest();
    }

    /** @test */
    public function it_should_authenticate_when_credentials_match()
    {
        factory(User::class)->create(['email' => 'foo@example.com']);

        $this->post('login', ['email' => 'foo@example.com', 'password' => 'secret'])
             ->assertSee('Great success');

        $this->assertAuthenticated();
    }

    /** @test */
    public function it_should_store_recaller_in_session_when_remember_is_not_checked()
    {
        $user = factory(User::class)->create();

        $this->post('login', ['email' => $user->email, 'password' => 'secret'])
             ->assertSee('Great success')
             ->assertSessionHas(Auth::guard()->getRecallerName());
             // @todo
             // ->assertCookieMissing(Auth::guard()->getRecallerName());
    }

    /** @test */
    public function it_should_store_recaller_in_cookie_when_remember_is_checked()
    {
        $user = factory(User::class)->create();

        $this->post('login', ['email' => $user->email, 'password' => 'secret', 'remember' => 'yes'])
             ->assertSee('Great success')
             ->assertCookie(Auth::guard()->getRecallerName())
             ->assertSessionMissing(Auth::guard()->getRecallerName());
    }

    /** @test */
    public function it_should_authenticate_from_recaller_session()
    {
        $sessionToken = factory(SessionToken::class)->create();
        $user = $sessionToken->getAuthenticatable(User::class);

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);

        $this->get('me')->assertJson($user->toArray());
    }

    /** @test */
    public function it_should_authenticate_from_recaller_cookie()
    {
        $sessionToken = factory(SessionToken::class)->create();
        $user = $sessionToken->getAuthenticatable(User::class);

        $this->call('GET', 'me', [], [
            Auth::guard()->getRecallerName() => encrypt($sessionToken->recaller),
        ])->assertJson($user->toArray());
    }

    /** @test */
    public function it_works_with_the_be_method()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->be($user);

        $this->get('me')->assertJson($user->toArray());
    }

    /** @test */
    public function it_works_with_the_acting_as_method()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->actingAs($user)->get('me')->assertJson($user->toArray());
    }

    /** @test */
    public function it_clears_session_recaller_when_logging_out()
    {
        $sessionToken = factory(SessionToken::class)->create();

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);

        $this->get('logout')
             ->assertSuccessful()
             ->assertSessionMissing(Auth::guard()->getRecallerName());
    }

    /** @test */
    public function it_clears_cookie_recaller_when_logging_out()
    {
        $sessionToken = factory(SessionToken::class)->create();
        $user = $sessionToken->getAuthenticatable(User::class);

        $this->call('GET', 'me', [], [
            Auth::guard()->getRecallerName() => encrypt($sessionToken->recaller),
        ])->assertJson($user->toArray());

        $this->assertAuthenticatedAs($user);

        $this->call('GET', 'logout', [], [
            Auth::guard()->getRecallerName() => encrypt($sessionToken->recaller),
        ])->assertSuccessful()
          ->assertCookieIsCleared(Auth::guard()->getRecallerName());

        $this->assertGuest();
    }

    /** @test */
    public function it_should_delete_the_session_token_when_logging_out()
    {
        $sessionToken = factory(SessionToken::class)->create();

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);

        $this->get('logout')->assertSuccessful();

        $this->assertSoftDeleted($sessionToken->getTable(), ['id' => $sessionToken->id]);
    }

    /** @test */
    public function it_should_log_in_once_without_state_using_credentials()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->assertFalse(
            Auth::guard()->once(['email' => $user->email, 'password' => 'wrong'])
        );

        $this->assertGuest();

        $this->assertTrue(
            Auth::guard()->once(['email' => $user->email, 'password' => 'secret'])
        );

        $this->assertAuthenticatedAs($user);
    }

    /** @test */
    public function it_should_log_in_once_without_state_using_id()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->assertFalse(Auth::guard()->onceUsingId(9001));
        $this->assertGuest();

        $this->assertSame($user->id, Auth::guard()->onceUsingId($user->id)->id);
        $this->assertAuthenticatedAs($user);
    }

    /** @test */
    public function it_should_log_in_using_id()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->assertFalse(Auth::guard()->loginUsingId(9001));

        $this->assertSame($user->id, Auth::guard()->loginUsingId($user->id)->id);

        $this->assertSame(
            $user->sessionTokens()->first()->recaller,
            app('session.store')->get(Auth::guard()->getRecallerName())
        );
    }

    /** @test */
    public function it_should_log_in_using_id_and_remember()
    {
        $user = factory(User::class)->create();
        factory(User::class)->create();

        $this->assertFalse(Auth::guard()->loginUsingId(9001));

        $this->assertSame(
            $user->id,
            Auth::guard()->loginUsingId($user->id, true)->id
        );

        $this->assertTrue(
            $this->app['cookie']->hasQueued(Auth::guard()->getRecallerName())
        );
    }
}
