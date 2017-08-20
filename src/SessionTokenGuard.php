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
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;

class SessionTokenGuard implements StatefulGuard
{
    use GuardHelpers;

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
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Illuminate\Contracts\Session\Session   $session
     */
    public function __construct(UserProvider $provider, Session $session)
    {
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
     * @param  \Illuminate\Contracts\Cookie\QueueingFactory $cookie
     * @return void
     */
    public function setCookie(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }

    /**
     * @return \Illuminate\Contracts\Cookie\QueueingFactory
     * @throws \RuntimeException
     */
    public function getCookieJar()
    {
        if (is_null($this->cookie)) {
            throw new RuntimeException('A cookie jar has not been set.');
        }

        return $this->cookie;
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
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // @todo: fire events

        // If the user has already been fetched, just re-use it.
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (! $sessionToken = $this->loadSessionToken()) {
            return;
        }

        return $this->user = $sessionToken->authenticatable;
    }

    /**
     * @return \Alfheim\SessionTokenGuard\SessionToken|null
     */
    protected function loadSessionToken()
    {
        $recallerName = $this->getRecallerName();

        $recallerValue = $this->request->cookies->get($recallerName) ?:
                         $this->session->get($recallerName);

        if (! $recallerValue) {
            return;
        }

        return SessionToken::findByRecaller($recallerValue);
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
        // @todo: fire events

        $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

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
        // @todo: fire events

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
        // @todo: fire events

        $sessionToken = $this->createSessionToken($user);

        if ($remember) {
            $this->storeRecallerInCookieJar($sessionToken);
        } else {
            $this->storeRecallerInSession($sessionToken);
        }

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
    protected function getRecallerName()
    {
        return 'session_'.md5(static::class);
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
            'ip_address'         => $request->ip(),
            'user_agent'         => $request->header('User-Agent', null),
        ]))->save();
    }

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed  $id
     * @param  bool   $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable
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
     * @return bool
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
        throw new \Exception('Method not implemented');
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        throw new \Exception('Method not implemented');
    }
}
