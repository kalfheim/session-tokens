<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateSessionTokensTable extends Migration
{
    public function up()
    {
        Schema::create('session_tokens', function (Blueprint $table) {
            $table->increments('id');
            $table->string('secret', 60);
            $table->integer('authenticatable_id')->unsigned();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->unique(['secret', 'authenticatable_id']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('session_tokens');
    }
}
