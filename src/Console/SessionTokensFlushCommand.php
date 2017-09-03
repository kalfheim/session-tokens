<?php

namespace Alfheim\SessionTokens\Console;

use Illuminate\Support\Carbon;
use Illuminate\Console\Command;
use Alfheim\SessionTokens\SessionToken;

class SessionTokensFlushCommand extends Command
{
    /**
     * {@inheritdoc}
     */
    protected $signature = 'session-tokens:flush
        {--days=30 : Number of days a token must have been untouched for it to be flushed}
        {--user=* : (Optional) Only select the given user ID}
        {--hard : Perform hard deletion instead of soft deletion}
        {--force}
    ';

    /**
     * {@inheritdoc}
     */
    protected $description = 'Flush session tokens';

    /**
     * {@inheritdoc}
     */
    public function handle()
    {
        $errors = [];

        if (($hard = $this->option('hard')) && ! $this->option('force')) {
            $errors[] = '--hard will permanently delete records. Use --force to confirm.';
        }

        $since = Carbon::now()->subDays($this->option('days'));

        if ($since->diffInDays() < 5 && ! $this->option('force')) {
            $errors[] = '--days cannot be less than 5. (force using --force)';
        }

        if ($errors) {
            return (int) array_walk($errors, [$this, 'error']);
        }

        $count = $this->flushSessionTokens(
            $hard, $since, $this->option('user')
        );

        if ($count === 0) {
            $this->comment('No session tokens to flush.');

            return 0;
        }

        $this->info(
            ($hard ? 'Hard deleted' : 'Flushed').
            " {$count} session ".str_plural('token', $count).
            " that have not been touched since {$since->diffForHumans()}"
        );

        return 0;
    }

    /**
     * Perform the deletion and return the number of affected rows.
     *
     * @param  bool  $hard
     * @param  \Illuminate\Support\Carbon  $since
     * @param  array  $users
     * @return int
     */
    protected function flushSessionTokens($hard, $since, array $users)
    {
        $query = (new SessionToken)->newQuery();

        if ($hard) {
            $query->withTrashed();
        }

        $query->where('updated_at', '<=', $since);

        if ($users) {
            $query->whereIn('authenticatable_id', $users);
        }

        return $query->{$hard ? 'forceDelete' : 'delete'}();
    }
}
