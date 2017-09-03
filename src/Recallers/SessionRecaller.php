<?php

namespace Alfheim\SessionTokens\Recallers;

use Alfheim\SessionTokens\SessionToken;
use Illuminate\Contracts\Session\Session;

class SessionRecaller implements RecallerInterface
{
    /**
     * @var string
     */
    protected $recallerName;

    /**
     * @var \Illuminate\Contracts\Session\Session
     */
    protected $session;

    /**
     * Create a session recaller instance.
     *
     * @param  string  $recallerName
     * @param  \Illuminate\Contracts\Session\Session  $session
     */
    public function __construct($recallerName, Session $session)
    {
        $this->recallerName = $recallerName;
        $this->session = $session;
    }

    /**
     * {@inheritdoc}
     */
    public function storeData($recallerString)
    {
        $this->session->put($this->recallerName, $recallerString);
    }

    /**
     * {@inheritdoc}
     */
    public function hasData()
    {
        return $this->session->has($this->recallerName);
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveSessionToken()
    {
        return SessionToken::findByRecaller(
            $this->session->get($this->recallerName)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function clearData()
    {
        $this->session->remove($this->recallerName);
    }
}
