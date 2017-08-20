<?php

namespace Alfheim\SessionTokenGuard\Tests;

use Alfheim\SessionTokenGuard\SessionToken;

class SessionTokenTest extends TestCase
{
    /** @test */
    public function it_should_build_a_formatted_recaller_string()
    {
        $sessionToken = factory(SessionToken::class)->make([
            'id' => '1',
            'secret' => 'not_so_secret',
        ]);

        $this->assertSame('1|not_so_secret', $sessionToken->recaller);
    }

    /** @test */
    public function it_should_find_the_session_token_by_recaller_string()
    {
        $sessionToken = factory(SessionToken::class)->create([
            'secret' => $secret = str_random(60),
        ]);

        $this->assertSame(
            $sessionToken->id,
            SessionToken::findByRecaller('1|'.$secret)->id
        );
    }

    /** @test */
    public function it_should_return_null_when_the_recaller_does_not_match_any_session_tokens()
    {
        factory(SessionToken::class)->create();

        $this->assertNull(SessionToken::findByRecaller('1|'.str_repeat('x', 60)));
    }

    /** @test */
    public function it_should_return_null_when_the_recaller_format_is_invalid()
    {
        factory(SessionToken::class)->create();

        $this->assertNull(SessionToken::findByRecaller('so_invalid'));
        $this->assertNull(SessionToken::findByRecaller('1|also|invalid'));
    }

    /** @test */
    public function it_should_be_soft_deleted()
    {
        $sessionToken = factory(SessionToken::class)->create([
            'secret' => $secret = str_random(60),
        ]);

        $sessionToken->delete();

        factory(SessionToken::class)->create();

        $this->assertSoftDeleted((new SessionToken)->getTable(), ['id' => 1]);

        $this->assertNull(SessionToken::findByRecaller('1|'.$secret));
    }

    /** @test */
    public function it_should_return_the_related_user_model()
    {
        $user = factory(User::class)->create();

        $sessionToken = factory(SessionToken::class)->create([
            'authenticatable_id' => $user->id,
        ]);

        factory(User::class)->create();

        $this->assertSame(
            $user->id,
            $sessionToken->getAuthenticatable(User::class)->id
        );
    }
}
