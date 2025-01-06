<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request){

        $validator=Validator::make(
            $request->all(),
            [
                'name'=>'required',
                'email'=>'required|email|unique:App\Models\User,email',
                'password'=>'required',
                'role'=>'required|integer'
            ]
        );
        if ($validator->fails()) {
            return response()->json($validator->errors(),400);
        }
        $input=$request->all();
        $input['password']=bcrypt($input['password']);
        $user=User::create($input);
        return response()->json($input,201);
    }
}
