<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;
use Alfheim\SessionTokenGuard\SessionToken;
use Symfony\Component\HttpFoundation\Request;

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
             ->assertSessionHas(Auth::guard()->getRecallerName())
             ->assertCookieIsNotQueued(Auth::guard()->getRecallerName());
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
    public function it_should_validate_a_users_credentials()
    {
        factory(User::class)->create(['email' => 'foo@example.com']);
        factory(User::class)->create();

        $guard = Auth::guard();

        $this->assertFalse($guard->validate(['email' => 'foo@example.com', 'password' => 'wrong']));
        $this->assertFalse($guard->validate(['email' => 'bar@example.com', 'password' => 'secret']));
        $this->assertTrue($guard->validate(['email' => 'foo@example.com', 'password' => 'secret']));
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

    /** @test */
    public function it_should_refresh_the_session_token_data_at_a_given_rate()
    {
        $this->assertUpdatedAtGetsUpdated(60);
    }

    /** @test */
    public function it_should_refresh_the_session_token_data_at_a_given_rate_which_is_configurable()
    {
        app('config')->set('auth.session_tokens.refresh_rate', 10);

        $this->assertUpdatedAtGetsUpdated(10);
    }

    /** @test */
    public function it_should_update_user_agent_and_ip_if_they_change()
    {
        $sessionToken = factory(SessionToken::class)->create([
            'ip_address' => '69.69.69.69',
            'user_agent' => 'An Actual Space Ship',
        ]);

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);
        Auth::guard()->user();

        $sessionToken = $sessionToken->fresh();

        $this->assertSame($this->getTestIp(), $sessionToken->ip_address);
        $this->assertSame($this->getTestUserAgent(), $sessionToken->user_agent);
    }

    /** @test */
    public function via_remember_should_return_false()
    {
        $this->assertFalse(Auth::guard()->viaRemember());
    }

    protected function assertUpdatedAtGetsUpdated($seconds)
    {
        $now = Carbon::now();

        // Rewind the time...
        Carbon::setTestNow((clone $now)->subSeconds($seconds));

        $sessionToken = factory(SessionToken::class)->create([
            'ip_address' => $this->getTestIp(),
            'user_agent' => $this->getTestUserAgent(),
        ]);

        // Reset the time...
        Carbon::setTestNow(clone $now);

        $this->assertSame($seconds, $sessionToken->updated_at->diffInSeconds($now));

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);
        Auth::guard()->user();

        $this->assertSame(
            $now->timestamp,
            $sessionToken->fresh()->updated_at->timestamp
        );
    }

    protected function getTestIp()
    {
        return Request::create('')->getClientIp();
    }

    protected function getTestUserAgent()
    {
        return Request::create('')->headers->get('User-Agent', null);
    }
}
