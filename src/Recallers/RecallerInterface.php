<?php

namespace Alfheim\SessionTokens\Recallers;

interface RecallerInterface
{
    /**
     * Store the given recaller string.
     *
     * @param  string  $recallerString
     * @return void
     */
    public function storeData($recallerString);

    /**
     * Determine if this recaller type has stored data than can be used to
     * attempt to retrieve a session token.
     *
     * @return bool
     */
    public function hasData();

    /**
     * Attempt to retrieve a session token from the recaller data.
     *
     * @return \Alfheim\SessionTokens\SessionToken|null
     */
    public function retrieveSessionToken();

    /**
     * Clear the data this recaller type uses.
     *
     * @return void
     */
    public function clearData();
}
