<?php

namespace Alfheim\SessionTokens;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @property int  $id
 * @property string  $secret
 * @property int  $authenticatable_id
 * @property string  $ip_address
 * @property string  $user_agent
 * @property \Carbon\Carbon  $created_at
 * @property \Carbon\Carbon  $updated_at
 * @property \Carbon\Carbon  $deleted_at
 * @property-read string  $recaller
 */
class SessionToken extends Model
{
    use SoftDeletes;

    /**
     * {@inheritdoc}
     */
    protected $dates = [
        'deleted_at',
    ];

    /**
     * {@inheritdoc}
     */
    protected $hidden = [
        'secret',
    ];

    /**
     * Find a session token by a recaller string.
     *
     * @param  string  $recaller
     * @return \Alfheim\SessionTokens\SessionToken|null
     */
    public static function findByRecaller($recaller)
    {
        if (substr_count($recaller, '|') !== 1) {
            return;
        }

        list($id, $secret) = explode('|', $recaller, 2);

        if (! $sessionToken = static::find($id)) {
            return;
        }

        if (hash_equals($sessionToken->secret, $secret)) {
            return $sessionToken;
        }
    }

    /**
     * Get the related authenticatable (user) model.
     *
     * @param  string  $related  The class name of the user model.
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getAuthenticatable($related)
    {
        return $this->belongsTo($related, 'authenticatable_id')->getResults();
    }

    /**
     * Attribute: Get the recaller string which will be stored in session & cookie.
     *
     * @return string
     */
    protected function getRecallerAttribute()
    {
        return "{$this->id}|{$this->secret}";
    }
}
