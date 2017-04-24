<?php

namespace App\Http\Controllers\Auth;

use DB;
use Mail;
use App\User;
use Validator;
use Illuminate\Http\Request;
use App\Mail\EmailVerification;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Support\Facades\Session;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;

    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';
    
    /**
     * Custom validation status
     * 
     * @var boolean
     */
    protected $valStatus = true;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    
    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'lastname' => $data['lastname'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
            'email_token' => str_random(10),
        ]);
    }
    
    /**
     * make string cutom validation
     * 
     * @param string fields
     */
    protected function customValidations($validationString, $pattern) {
        preg_match($pattern, $validationString, $matches);
        
        if (empty($matches)){  
            return false;
        } else {
            return true;
        }
    }
    

    /**
     *  Over-ridden the register method from the "RegistersUsers" trait
     *  Remember to take care while upgrading laravel
     */
    public function register(Request $request) {
         
        // Laravel validation
        $validator =  Validator::make($request->all(), [
            'name' => 'required',
            'lastname' => 'required',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:2|confirmed',
        ]);
        
       
        $this->valStatus = $this->customValidations($request->input('name'), '/^[a-zA-Z0-9 ]*$/');
  
        $validator->after(function($validator) {
            if (!$this->valStatus) {
                $validator->errors()->add('name', 'Name must consist of only letters and spaces!');
                
            }
        });

        $this->valStatus = $this->customValidations($request->input('lastname'), '/^[a-zA-Z0-9 ]*$/');

        $validator->after(function($validator) {
            if (!$this->valStatus) {
                $validator->errors()->add('lastname', 'Last name must consist of only letters and spaces!');
            }
        });
        
        $this->valStatus = $this->customValidations($request->input('password'), '/(?=.*?[0-9])(?=.*?[#?!@$%^&*-])/');
        
        $validator->after(function($validator) {
            if (!$this->valStatus) {
                $validator->errors()->add('password', 'Password must contain at least 1 number and special symbol');
            }
        });

        if ($validator->fails()) {
            $this->throwValidationException($request, $validator);
        }
        // Using database transactions is useful here because stuff happening is actually a transaction
        // I don't know what I said in the last line! Weird!
        DB::beginTransaction();

        try {
            $user = $this->create($request->all());
            // After creating the user send an email with the random token generated in the create method above
            $email = new EmailVerification(new User(['email_token' => $user->email_token]));
            Mail::to($user->email)->send($email);
            DB::commit();
            Session::flash('message','We have sent you a verification email!');
            return back();
        } catch(Exception $e) {
            DB::rollback(); 
            return back();
        }
    }

    // Get the user who has the same token and change his/her status to verified i.e. 0 -> 1
    public function verify($token) {
        // The verified method has been added to the user model and chained here for better readability
        User::where('email_token',$token)->firstOrFail()->verified();
        Session::flash('message','Your account is now active, Please login!');
        return redirect('login');
    }
    
   
}