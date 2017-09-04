<?php

namespace Alfheim\SessionTokens\Tests\Console;

use Illuminate\Support\Facades\Auth;
use Alfheim\SessionTokens\Tests\User;
use Alfheim\SessionTokens\SessionToken;
use Alfheim\SessionTokens\Tests\TestCase;

class MakeSessionTokensCommandTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();

        $this->setUpFakeApplication();
    }

    /** @test */
    public function it_should_scaffold_and_then_list_all_sessions()
    {
        $this->assertSame(0, $this->artisan('make:session-tokens'));
        $this->setUpAfterScaffold();

        $user = factory(User::class)->create();
        $sessionToken = factory(SessionToken::class)->create(['authenticatable_id' => $user->id]);
        factory(SessionToken::class)->create(['authenticatable_id' => $user->id]);

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);

        $this->actingAs($user)
            ->get('session-tokens')
            ->assertSuccessful()
            ->assertSee($sessionToken->user_agent)
            ->assertSee('it\'s you!')
            ->assertSee('Revoke');
    }

    /** @test */
    public function it_should_scaffold_and_then_revoke_a_session()
    {
        $this->assertSame(0, $this->artisan('make:session-tokens'));
        $this->setUpAfterScaffold();

        $user = factory(User::class)->create();
        $sessionToken = factory(SessionToken::class)->create(['authenticatable_id' => $user->id]);
        $otherSessionToken = factory(SessionToken::class)->create(['authenticatable_id' => $user->id]);

        app('session.store')->put(Auth::guard()->getRecallerName(), $sessionToken->recaller);

        $this->actingAs($user)
            ->delete('session-tokens/'.$otherSessionToken->id)
            ->assertRedirect()
            ->assertSessionHas('status', 'The session has been revoked.');
    }

    /** @test */
    public function it_should_overwrite_views_when_force_is_used()
    {
        $path = resource_path('views/session-tokens/index.blade.php');
        $files = resolve('files');

        $this->assertSame(0, $this->artisan('make:session-tokens'));

        $files->put($path, 'foobar');
        $this->assertSame('foobar', $files->get($path));

        $this->assertSame(
            0,
            $this->artisan('make:session-tokens', ['--force' => true])
        );

        $this->assertNotSame('foobar', $files->get($path));
    }

    protected function setUpAfterScaffold()
    {
        // @todo: switch to the "web" middleware group when the commit to include
        // AddQueuedCookiesToResponse in orchestra testbench is tagged
        $this->app['router']->middleware([
            \Illuminate\Cookie\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\Middleware\StartSession::class,
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,
            \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class,
            \Illuminate\Routing\Middleware\SubstituteBindings::class,
        ])->namespace('App\Http\Controllers')->group(base_path('routes/web.php'));

        // What is this autoloading you speak of?
        require_once app_path('Http/Controllers/Controller.php');
        require_once app_path('Http/Controllers/UserSessionTokensController.php');
    }

    protected function setUpFakeApplication()
    {
        $files = resolve('files');

        $this->cleanUpFiles();

        $files->makeDirectory(app_path('Http/Controllers'), 0755, true, true);
        $files->put(app_path('Http/Controllers/Controller.php'), $this->getBaseController());
        $files->makeDirectory(base_path('routes'), 0755, true, true);
        $files->put(base_path('routes/web.php'), "<?php\n");

        $files->makeDirectory(resource_path('views/layouts'), 0755, true, true);
        $files->put(resource_path('views/layouts/app.blade.php'), "@yield('content')");

        $this->beforeApplicationDestroyed([$this, 'cleanUpFiles']);
    }

    protected function cleanUpFiles()
    {
        $files = resolve('files');

        // Clean up stubs that may have been created during test
        $files->deleteDirectory(app_path('Http/Controllers'));
        $files->deleteDirectory(resource_path('views/session-tokens'));
        $files->deleteDirectory(resource_path('views/layouts'));
        $files->delete(app_path('Http/Controllers/UserSessionTokensController.php'));
    }

    protected function getBaseController()
    {
        return '<?php

namespace App\\Http\\Controllers;

use Illuminate\\Foundation\\Bus\\DispatchesJobs;
use Illuminate\\Routing\\Controller as BaseController;
use Illuminate\\Foundation\\Validation\\ValidatesRequests;
use Illuminate\\Foundation\\Auth\\Access\\AuthorizesRequests;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
}
';
    }
}
