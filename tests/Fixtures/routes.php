<?php

$router->middleware('auth')->group(function ($router) {
    $router->get('me', function () {
        return Auth::guard()->user();
    });

    $router->get('logout', function () {
        return Auth::guard()->logout();
    });
});

$router->middleware('guest')->group(function ($router) {
    $router->post('login', function (Illuminate\Http\Request $request) {
        return Auth::guard()->attempt([
            'email'    => $request->email,
            'password' => $request->password,
        ], $request->has('remember')) ? 'Great success' : 'Bad credentials';
    });
});

$router->get('guard', function () {
    return get_class(Auth::guard());
});
