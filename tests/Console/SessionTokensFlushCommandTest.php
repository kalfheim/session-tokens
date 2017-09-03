<?php

namespace Alfheim\SessionTokens\Tests\Console;

use Illuminate\Support\Carbon;
use Alfheim\SessionTokens\Tests\User;
use Alfheim\SessionTokens\SessionToken;
use Alfheim\SessionTokens\Tests\TestCase;

class SessionTokensFlushCommandTest extends TestCase
{
    /** @test */
    public function it_should_soft_delete_old_session_tokens()
    {
        $old = factory(SessionToken::class)->times(2)->create([
            'updated_at' => Carbon::now()->subDays(30),
        ]);

        $new = factory(SessionToken::class)->create();

        $this->assertSame(0, $this->artisan('session-tokens:flush', ['--days' => 30]));

        foreach ($old as $sessionToken) {
            $this->assertSoftDeleted((new SessionToken)->getTable(), [
                'id' => $sessionToken->id,
            ]);
        }

        $this->assertDatabaseHas((new SessionToken)->getTable(), [
            'id' => $new->id, 'deleted_at' => null,
        ]);
    }

    /** @test */
    public function it_should_hard_delete_session_tokens_when_specified()
    {
        $old = factory(SessionToken::class)->times(2)->create([
            'updated_at' => Carbon::now()->subDays(30),
        ]);

        $new = factory(SessionToken::class)->create();

        $this->assertSame(1, $this->artisan('session-tokens:flush', [
            '--days' => 30,
            '--hard' => true,
        ]));

        // --force must be specified for hard deletes
        $this->assertSame(0, $this->artisan('session-tokens:flush', [
            '--days' => 30,
            '--hard' => true,
            '--force' => true,
        ]));

        foreach ($old as $sessionToken) {
            $this->assertDatabaseMissing((new SessionToken)->getTable(), [
                'id' => $sessionToken->id,
            ]);
        }

        $this->assertDatabaseHas((new SessionToken)->getTable(), [
            'id' => $new->id, 'deleted_at' => null,
        ]);
    }

    /** @test */
    public function it_should_only_allow_more_than_5_days_unless_forced()
    {
        $this->assertSame(1, $this->artisan('session-tokens:flush', ['--days' => 4]));
        $this->assertSame(0, $this->artisan('session-tokens:flush', ['--days' => 4, '--force' => true]));
    }

    /** @test */
    public function it_should_allow_specifying_a_user_id()
    {
        $user = factory(User::class)->create();

        $old = factory(SessionToken::class)->times(2)->create([
            'authenticatable_id' => $user->id,
            'updated_at' => Carbon::now()->subDays(30),
        ]);

        $new = factory(SessionToken::class)->create([
            'authenticatable_id' => $user->id,
        ]);

        $otherUser = factory(SessionToken::class)->create([
            'updated_at' => Carbon::now()->subDays(30),
        ]);

        $this->assertSame(0, $this->artisan('session-tokens:flush', [
            '--user' => [$user->id],
        ]));

        foreach ($old as $sessionToken) {
            $this->assertSoftDeleted((new SessionToken)->getTable(), [
                'id' => $sessionToken->id,
            ]);
        }

        $this->assertDatabaseHas((new SessionToken)->getTable(), [
            'id' => $new->id, 'deleted_at' => null,
        ]);

        $this->assertDatabaseHas((new SessionToken)->getTable(), [
            'id' => $otherUser->id, 'deleted_at' => null,
        ]);
    }
}
