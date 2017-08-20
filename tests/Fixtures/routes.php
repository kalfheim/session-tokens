<?php

$router->middleware('auth')->group(function ($router) {
    $router->get('me', function () {
        return Auth::guard()->user();
    });

    $router->get('logout', function () {
        return Auth::guard()->logout() ? 'Logged out' : 'Something went wrong';
    });
});

$router->middleware('guest')->group(function ($router) {
    $router->post('login', function (Illuminate\Http\Request $request) {
        return Auth::guard()->attempt([
            'email'    => $request->email,
            'password' => $request->password,
        ], $request->has('remember')) ? 'Successful attempt' : 'Wrong e-mail or password';
    });
});
