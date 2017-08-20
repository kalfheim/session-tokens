<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Alfheim\SessionTokenGuard\SessionToken;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $guarded = [];

    public function sessionTokens()
    {
        return $this->hasMany(SessionToken::class, 'authenticatable_id');
    }
}
