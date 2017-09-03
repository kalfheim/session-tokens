<?php

namespace Alfheim\SessionTokens\Tests;

use Alfheim\SessionTokens\SessionToken;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $guarded = [];

    public function sessionTokens()
    {
        return $this->hasMany(SessionToken::class, 'authenticatable_id');
    }
}
