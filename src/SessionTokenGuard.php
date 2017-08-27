<?php

namespace Alfheim\SessionTokenGuard;

use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Support\Carbon;
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
     * The "name" of this guard instance (from the application configuration.).
     *
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
     * The cookie jar instance.
     *
     * @var \Illuminate\Contracts\Cookie\QueueingFactory
     */
    protected $cookie;

    /**
     * The event dispatcher.
     *
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
     * Set the incoming HTTP request instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request $request
     * @return void
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Set the cookie jar instance.
     *
     * @param  \Illuminate\Contracts\Cookie\QueueingFactory $cookieJar
     * @return void
     */
    public function setCookieJar(CookieJar $cookieJar)
    {
        $this->cookieJar = $cookieJar;
    }

    /**
     * Set the event dispatcher instance.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
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

        $this->touchSessionToken();

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
     * Get the session token related to the incoming HTTP request.
     *
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

    /**
     * Get the name of the recaller for use in cookie and session.
     *
     * @return string
     */
    public function getRecallerName()
    {
        return $this->name.'_'.md5(static::class);
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
     * Create a fresh session token for new logins.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \Alfheim\SessionTokenGuard\SessionToken
     */
    protected function createSessionToken($user)
    {
        return tap((new SessionToken)->forceFill([
            'secret'             => Str::random(60),
            'authenticatable_id' => $user->getAuthIdentifier(),
            'ip_address'         => $this->request->getClientIp(),
            'user_agent'         => $this->request->headers->get('User-Agent', null),
        ]))->save();
    }

    /**
     * Store the session token's recaller string in a cookie and queue it. This
     * is only done when the "remember me" option is used.
     *
     * @param \Alfheim\SessionTokenGuard\SessionToken  $sessionToken
     * @return void
     */
    protected function storeRecallerInCookieJar(SessionToken $sessionToken)
    {
        $cookie = $this->cookieJar->forever(
            $this->getRecallerName(), $sessionToken->recaller
        );

        $this->cookieJar->queue($cookie);
    }

    /**
     * Store the session token's recaller string in the local session. This is
     * the method used when the "remember me" option is *not* used.
     *
     * @param \Alfheim\SessionTokenGuard\SessionToken  $sessionToken
     * @return void
     */
    protected function storeRecallerInSession(SessionToken $sessionToken)
    {
        $this->session->put($this->getRecallerName(), $sessionToken->recaller);
    }

    /**
     * Clear some data after logging out.
     *
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        $recallerName = $this->getRecallerName();

        if ($this->session->has($recallerName)) {
            $this->session->remove($recallerName);
        }

        if ($this->request->cookies->has($recallerName)) {
            $this->cookieJar->queue(
                $this->cookieJar->forget($this->getRecallerName())
            );
        }
    }

    /**
     * "Touch" the session token in order to update the updated_at timestamp,
     * IP address etc.
     *
     * @return void
     */
    protected function touchSessionToken()
    {
        $sessionToken = $this->sessionToken();

        if ($sessionToken->updated_at->diffInSeconds() >= $this->getSessionTokenRefreshRate()) {
            $sessionToken->updated_at = Carbon::now();
        }

        if ($sessionToken->ip_address !== $this->request->getClientIp()) {
            $sessionToken->ip_address = $this->request->getClientIp();
        }

        if ($sessionToken->user_agent !== $this->request->headers->get('User-Agent', null)) {
            $sessionToken->user_agent = $this->request->headers->get('User-Agent', null);
        }

        if ($sessionToken->isDirty()) {
            $sessionToken->save();
        }
    }

    /**
     * Get the number of seconds for which the session token `updated_at` value
     * should be refreshed.
     *
     * @return int
     */
    protected function getSessionTokenRefreshRate()
    {
        return config('auth.session_tokens.refresh_rate', 60);
    }

    /**
     * Get the class name of the Eloquent model which is configured with the
     * user provider.
     *
     * @return string
     */
    protected function getUserModelClass()
    {
        $provider = config("auth.guards.{$this->name}.provider");

        return config("auth.providers.{$provider}.model");
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
