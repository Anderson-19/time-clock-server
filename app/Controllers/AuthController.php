<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\UserModel;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class AuthController extends BaseController
{

    use ResponseTrait;

    public function register()
    {
        $rules = [
            "name" => "required|trim|min_length[3]|max_length[30]",
            "lastname" => "required|trim|min_length[2]|max_length[30]",
            "username" => "required|trim|min_length[2]|max_length[30]|is_unique[users.username]",
            "email" => "required|is_unique[users.email]",
            "password" => "required|min_length[8]|max_length[30]"
        ];

        if (!$this->validate(($rules))) {
            return $this->respond($this->genericResponse(
                ResponseInterface::HTTP_INTERNAL_SERVER_ERROR,
                $this->validator->getErrors(),
                true,
                []
            ), ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
        }

        $data = [
            'name' => $this->request->getVar("name"),
            'lastname' => $this->request->getVar("lastname"),
            'username' => $this->request->getVar("username"),
            'email' => $this->request->getVar("email"),
            'password' => password_hash($this->request->getVar("password"), PASSWORD_DEFAULT),
            'role' => 'user',
            'created_at' => date("Y-m-d h:i:sa")
        ];

        $userModel = new UserModel();
        $registered = $userModel->save($data);

        if (!$registered) {
            return $this->respond($this->genericResponse(
                ResponseInterface::HTTP_FORBIDDEN,
                'Problems to User Register',
                true,
                []
            ), ResponseInterface::HTTP_FORBIDDEN);
        }

        return $this->respond($this->genericResponse(
            ResponseInterface::HTTP_OK,
            'User Register In successfully',
            false,
            []
        ), ResponseInterface::HTTP_OK);
    }

    public function login()
    {
        $rules = [
            "email" => "required",
            "password" => "required|min_length[8]|max_length[30]"
        ];

        if (!$this->validate(($rules))) {
            return $this->respond($this->genericResponse(
                ResponseInterface::HTTP_INTERNAL_SERVER_ERROR,
                $this->validator->getErrors(),
                true,
                []
            ), ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
        }

        $userModel = new UserModel();

        $user = $userModel->where("email", $this->request->getVar('email'))->first();
        if (is_null($user)) {
            return $this->respond($this->genericResponse(
                ResponseInterface::HTTP_UNAUTHORIZED,
                ["email" => "Invalid email"],
                true,
                []
            ), ResponseInterface::HTTP_UNAUTHORIZED);
        }

        $pwd_verify = password_verify($this->request->getVar('password'), $user['password']);
        if (!$pwd_verify) {
            return $this->respond($this->genericResponse(
                ResponseInterface::HTTP_UNAUTHORIZED,
                ["password" => "Invalid password"],
                true,
                []
            ), ResponseInterface::HTTP_UNAUTHORIZED);
        }

        helper('generate-jwt_helper');
        $token = generateJWT($user);

        return $this->respond($this->genericResponse(
            ResponseInterface::HTTP_OK,
            'Login Succesful',
            false,
            [
                'user' => $user,
                'token' => $token
            ]
        ), ResponseInterface::HTTP_OK);
    }

    public function checkToken(){

        $token = $this->request->getHeaderLine("Authorization");

        if(empty($token)) return $this->respond(['token', 'user'], Response::HTTP_FORBIDDEN);

        try {
            $key = getenv('JWT_SECRET');
            $verifyToken = JWT::decode($token, new Key($key, 'HS256'));

            if(empty($verifyToken)) return $this->respond(['token', 'user'], Response::HTTP_FORBIDDEN);

            $db = db_connect();
            $user = $db->query("SELECT * FROM users WHERE id=".$verifyToken->id."")->getResult('array'); 
    
            return $this->respond([
                'token' => $token,
                'user' => $user[0]
            ], Response::HTTP_OK);
            
        } catch (\Throwable $th) {
            return $this->respond(['token','user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

    }

    private function genericResponse(int $status, string | array $message, bool $error, array $data)
    {
        return [
            "status" => $status,
            "message" => $message,
            "error" => $error,
            "data" => $data
        ];
    }
}
