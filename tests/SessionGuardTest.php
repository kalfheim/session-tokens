<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Mockery as m;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Attempting;
use Alfheim\SessionTokenGuard\SessionTokenGuard;

class SessionGuardTest extends TestCase
{
    public function testAttemptCallsRetrieveByCredentials()
    {
        $guard = $this->getGuard();
        $guard->getDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $guard->getDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Failed::class));
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->with(['foo']);
        $guard->attempt(['foo']);
    }

    public function testAttemptReturnsUserInterface()
    {
        extract($this->getMocks());
        $guard = $this->getMockBuilder(SessionTokenGuard::class)->setMethods(['login'])->setConstructorArgs(['web', $provider, $session])->getMock();
        $guard->setDispatcher($events);
        $events->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $user = $this->createMock('Illuminate\Contracts\Auth\Authenticatable');
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->andReturn($user);
        $guard->getProvider()->shouldReceive('validateCredentials')->with($user, ['foo'])->andReturn(true);
        $guard->expects($this->once())->method('login')->with($this->equalTo($user));
        $this->assertTrue($guard->attempt(['foo']));
    }

    public function testAttemptReturnsFalseIfUserNotGiven()
    {
        $guard = $this->getGuard();
        $guard->getDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Attempting::class));
        $guard->getDispatcher()->shouldReceive('dispatch')->once()->with(m::type(Failed::class));
        $guard->getProvider()->shouldReceive('retrieveByCredentials')->once()->andReturn(null);
        $this->assertFalse($guard->attempt(['foo']));
    }

    protected function getGuard()
    {
        extract($this->getMocks());

        $guard = new SessionTokenGuard('web', $provider, $session);
        $guard->setRequest($request);
        $guard->setCookie($cookie);
        $guard->setDispatcher($events);

        return $guard;
    }

    protected function getMocks()
    {
        return [
            'session'  => m::mock('Illuminate\Contracts\Session\Session'),
            'provider' => m::mock('Illuminate\Contracts\Auth\UserProvider'),
            'request'  => \Symfony\Component\HttpFoundation\Request::create('/', 'GET'),
            'cookie'   => m::mock('Illuminate\Cookie\CookieJar'),
            'events'   => m::mock('Illuminate\Contracts\Events\Dispatcher'),
        ];
    }
}
