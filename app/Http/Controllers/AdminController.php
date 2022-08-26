<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\Admin;
use Validator;
use OpenApi\Annotations as OA;

/**
 *
 * @OA\Info(
 *      version="v1",
 *      title="Admin API",
 *      description="",
 *      @OA\Contact(
 *          email="***@***.com"
 *      )
 * )
 * @OA\Server(
 *      url= L5_SWAGGER_CONST_HOST,
 *      description="*** API Admin Serve"
 * )
 *
 */

class AuthController extends Controller
{
  
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['loginAdmin','editProfile']]);
    }

    
    

    public function loginAdmin(Request $request) {
        $credentials = $request->only('email', 'password');
        try {
            if (!$token = auth()->guard('admin')->attempt($credentials)) {
                return response()->json(['success' => false, 'error' => 'Some Error Message'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['success' => false, 'error' => 'Failed to login, please try again.'], 500);
        }
        return $this->respondWithToken($token);
      }

    public function logout() {
        auth()->logout();
        return response()->json(['message' => 'User successfully signed out']);
    }
    
    public function userProfile(Request $request) {
        return response()->json(auth()->user());
    }
    
    public function editProfile(Request $request)
    {
       /** @var \App\Models\User $user */
        if (!$user = Auth::user()) {
            return response()->json('User profile not found', 401);
        }

        if (!empty($request->name)) {
            $user->name = $request->name;
        }
        if (!empty($request->email)) {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:100|unique:users',
            ]);
            if ($validator->fails()) {
                return response()->json($validator->errors()->toJson(), 400);
            }
            $user->email = $request->email;
        }
        if (!empty($request->password)) {
            $user->password = bcrypt($request->password);
        }
        if (!empty($request->telegram)) {
            $user->telegram = $request->telegram;
        }
        $user->save();
        $response = [
            'message' => 'User profile update successfully',
            'user' => $user
        ];
        return response()->json($response, 200);
    }

    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}