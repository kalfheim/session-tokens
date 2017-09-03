<?php

namespace Alfheim\SessionTokens\Recallers;

use Alfheim\SessionTokens\SessionToken;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;

class CookieRecaller implements RecallerInterface
{
    /**
     * @var string
     */
    protected $recallerName;

    /**
     * @var \Illuminate\Contracts\Cookie\QueueingFactory
     */
    protected $cookieJar;

    /**
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * Create a cookie recaller instance.
     *
     * @param  string  $recallerName
     * @param  \Illuminate\Contracts\Cookie\QueueingFactory  $cookieJar
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     */
    public function __construct($recallerName, CookieJar $cookieJar, Request $request)
    {
        $this->recallerName = $recallerName;
        $this->cookieJar = $cookieJar;
        $this->request = $request;
    }

    /**
     * {@inheritdoc}
     */
    public function storeData($recallerString)
    {
        $config = config('session');

        $cookie = $this->cookieJar->forever(
            $this->recallerName, $recallerString, $config['path'],
            $config['domain'], $config['secure'] ?? false,
            $config['http_only'] ?? true, false, $config['same_site'] ?? null
        );

        $this->cookieJar->queue($cookie);
    }

    /**
     * {@inheritdoc}
     */
    public function hasData()
    {
        return $this->request->cookies->has($this->recallerName);
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveSessionToken()
    {
        return SessionToken::findByRecaller(
            $this->request->cookies->get($this->recallerName)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function clearData()
    {
        $this->cookieJar->queue(
            $this->cookieJar->forget($this->recallerName)
        );
    }
}
