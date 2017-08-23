<?php

namespace Alfheim\SessionTokenGuard;

use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Session\Session;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Auth\Events\Login as LoginEvent;
use Illuminate\Auth\Events\Failed as FailedEvent;
use Illuminate\Auth\Events\Logout as LogoutEvent;
use Illuminate\Auth\Events\Attempting as AttemptingEvent;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Illuminate\Auth\Events\Authenticated as AuthenticatedEvent;

class SessionTokenGuard implements StatefulGuard
{
    use GuardHelpers;

    /**
     * @var string
     */
    protected $name;

    /**
     * The session instance.
     *
     * @var \Illuminate\Contracts\Session\Session
     */
    protected $session;

    /**
     * The incoming HTTP request instance.
     *
     * @var \Symfony\Component\HttpFoundation\Request|null
     */
    protected $request;

    /**
     * @var \Illuminate\Contracts\Cookie\QueueingFactory
     */
    protected $cookie;

    /**
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * Create a new session token guard.
     *
     * @param string  $name
     * @param \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct($name, UserProvider $provider, Session $session)
    {
        $this->name = $name;
        $this->provider = $provider;
        $this->session = $session;
    }

    /**
     * @param  \Symfony\Component\HttpFoundation\Request $request
     * @return void
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;
    }

    /**
     * @return \Symfony\Component\HttpFoundation\Request
     * @throws \RuntimeException
     */
    public function getRequest()
    {
        if (is_null($this->request)) {
            throw new RuntimeException('An HTTP request has not been set.');
        }

        return $this->request;
    }

    /**
     * @param  \Illuminate\Contracts\Cookie\QueueingFactory $cookieJar
     * @return void
     */
    public function setCookieJar(CookieJar $cookieJar)
    {
        $this->cookieJar = $cookieJar;
    }

    /**
     * @return \Illuminate\Contracts\Cookie\QueueingFactory
     * @throws \RuntimeException
     */
    public function getCookieJar()
    {
        if (is_null($this->cookieJar)) {
            throw new RuntimeException('A cookie jar has not been set.');
        }

        return $this->cookieJar;
    }

    /**
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }

    /**
     * @return \Illuminate\Contracts\Events\Dispatcher
     * @throws \RuntimeException
     */
    public function getDispatcher()
    {
        if (is_null($this->events)) {
            throw new RuntimeException('An event dispatcher has not been set.');
        }

        return $this->events;
    }

    /**
     * @return \Illuminate\Contracts\Auth\UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // If the user has already been fetched, just re-use it.
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $sessionToken = $this->sessionToken()) {
            return;
        }

        $this->user = $sessionToken->getAuthenticatable(
            $this->getUserModelClass()
        );

        if (! is_null($this->user)) {
            $this->fireAuthenticatedEvent($this->user);
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return $this
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        $this->fireAuthenticatedEvent($user);

        return $this;
    }

    /**
     * @return string
     */
    protected function getUserModelClass()
    {
        $provider = config("auth.guards.{$this->name}.provider");

        return config("auth.providers.{$provider}.model");
    }

    /**
     * @return \Alfheim\SessionTokenGuard\SessionToken|null
     */
    public function sessionToken()
    {
        if (property_exists($this, 'sessionToken')) {
            return $this->sessionToken;
        }

        $recallerName = $this->getRecallerName();

        $recallerValue = $this->request->cookies->get($recallerName) ?:
                         $this->session->get($recallerName);

        if (! $recallerValue) {
            return $this->sessionToken = null;
        }

        return $this->sessionToken = SessionToken::findByRecaller($recallerValue);
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->hasValidCredentials(
            $this->provider->retrieveByCredentials($credentials),
            $credentials
        );
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);

        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, array $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        $this->fireAttemptEvent($credentials);

        $user = $this->provider->retrieveByCredentials($credentials);

        if (! $this->hasValidCredentials($user, $credentials)) {
            return false;
        }

        $this->setUser($user);

        return true;
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    public function login(Authenticatable $user, $remember = false)
    {
        $sessionToken = $this->createSessionToken($user);

        if ($remember) {
            $this->storeRecallerInCookieJar($sessionToken);
        } else {
            $this->storeRecallerInSession($sessionToken);
        }

        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);
    }

    protected function storeRecallerInCookieJar(SessionToken $sessionToken)
    {
        $cookie = $this->getCookieJar()->forever(
            $this->getRecallerName(), $sessionToken->recaller
        );

        $this->getCookieJar()->queue($cookie);
    }

    protected function storeRecallerInSession(SessionToken $sessionToken)
    {
        $this->session->put($this->getRecallerName(), $sessionToken->recaller);
    }

    /**
     * @return string
     */
    public function getRecallerName()
    {
        return $this->name.'_'.md5(static::class);
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \Alfheim\SessionTokenGuard\SessionToken
     */
    protected function createSessionToken($user)
    {
        $request = $this->getRequest();

        return tap((new SessionToken)->forceFill([
            'secret'             => Str::random(60),
            'authenticatable_id' => $user->getAuthIdentifier(),
            'ip_address'         => $request->getClientIp(),
            'user_agent'         => $request->headers->get('User-Agent', null),
        ]))->save();
    }

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed  $id
     * @param  bool   $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function loginUsingId($id, $remember = false)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param  mixed  $id
     * @return \Illuminate\Contracts\Auth\Authenticatable|false
     */
    public function onceUsingId($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember()
    {
        // @todo: figure out if it really matters what this returns
        return false;
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $sessionToken = $this->sessionToken();
        $user = $this->user();

        $this->clearUserDataFromStorage();

        if (! is_null($sessionToken)) {
            $sessionToken->delete();
        }

        if (isset($this->events)) {
            $this->events->dispatch(new LogoutEvent($user));
        }

        unset($this->sessionToken);
        $this->user = null;
    }

    /**
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        $recallerName = $this->getRecallerName();

        if ($this->session->has($recallerName)) {
            $this->session->remove($recallerName);
        }

        if ($this->request->cookies->has($recallerName)) {
            $this->getCookieJar()->queue(
                $this->getCookieJar()->forget($this->getRecallerName())
            );
        }
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @param  bool  $remember
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new AttemptingEvent(
                $credentials, $remember
            ));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new LoginEvent($user, $remember));
        }
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireAuthenticatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new AuthenticatedEvent($user));
        }
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array  $credentials
     * @return void
     */
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new FailedEvent($user, $credentials));
        }
    }
}
