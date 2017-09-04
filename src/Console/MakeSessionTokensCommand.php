<?php

namespace Alfheim\SessionTokens\Console;

use Illuminate\Console\Command;
use Illuminate\Console\DetectsApplicationNamespace;

class MakeSessionTokensCommand extends Command
{
    use DetectsApplicationNamespace;

    /**
     * {@inheritdoc}
     */
    protected $signature = 'make:session-tokens
        {--force : Overwrite existing views by default}
    ';

    /**
     * {@inheritdoc}
     */
    protected $description = 'Scaffold a basic user interface for session tokens';

    /**
     * The views that need to be exported.
     *
     * @var array
     */
    protected $views = [
        'session-tokens/index.stub' => 'session-tokens/index.blade.php',
    ];

    /**
     * {@inheritdoc}
     */
    public function handle()
    {
        $this->createDirectories();

        $this->exportViews();

        file_put_contents(
            $path = app_path('Http/Controllers/UserSessionTokensController.php'),
            $this->compileControllerStub()
        );

        $this->comment('Created controller ['.$path.']');

        file_put_contents(
            $path = base_path('routes/web.php'),
            file_get_contents(__DIR__.'/stubs/make/routes.stub'),
            FILE_APPEND
        );

        $this->comment('Added routes to ['.$path.']');

        $this->info('Session tokens UI scaffolding generated successfully.');

        return 0;
    }

    /**
     * Create the directories for the files.
     *
     * @return void
     */
    protected function createDirectories()
    {
        if (! is_dir($directory = resource_path('views/session-tokens'))) {
            mkdir($directory, 0755, true);

            $this->comment('Created directory ['.$directory.']');
        }
    }

    /**
     * Export the views.
     *
     * @return void
     */
    protected function exportViews()
    {
        foreach ($this->views as $key => $value) {
            if (file_exists($view = resource_path('views/'.$value)) && ! $this->option('force')) {
                if (! $this->confirm("The [{$value}] view already exists. Do you want to replace it?")) {
                    continue;
                }
            }

            copy(
                __DIR__.'/stubs/make/views/'.$key,
                $view
            );

            $this->comment('Exported view to ['.$view.']');
        }
    }

    /**
     * Compiles the UserSessionTokensController stub.
     *
     * @return string
     */
    protected function compileControllerStub()
    {
        return str_replace(
            '{{namespace}}',
            $this->getAppNamespace(),
            file_get_contents(__DIR__.'/stubs/make/UserSessionTokensController.stub')
        );
    }
}
