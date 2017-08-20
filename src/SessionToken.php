<?php

namespace Alfheim\SessionTokenGuard;

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
 * @property \Illuminate\Contracts\Auth\Authenticatable  $authenticatable
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
     * @return string
     */
    public function getRecallerAttribute()
    {
        return "{$this->id}|{$this->secret}";
    }

    /**
     * Find a session token by a recaller string.
     *
     * @param  string  $recaller
     * @return \Alfheim\SessionTokenGuard\SessionToken|null
     */
    public static function findByRecaller($recaller)
    {
        if (substr_count($recaller, '|') !== 1) {
            return;
        }

        list($id, $secret) = explode('|', $recaller, 2);

        if (! $sessionToken = static::with('authenticatable')->find($id)) {
            return;
        }

        if (hash_equals($sessionToken->secret, $secret)) {
            return $sessionToken;
        }
    }

    /**
     * The Authenticatable relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasOne
     */
    public function authenticatable()
    {
        // @todo: make the model configurable
        return $this->hasOne('App\User', 'authenticatable_id');
    }
}
