<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\API\ResponseTrait;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\HTTP\Response;
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class ValidateJWTFilter implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param RequestInterface $request
     * @param array|null       $arguments
     *
     * @return RequestInterface|ResponseInterface|string|void
     */

    use ResponseTrait;

    public function before(RequestInterface $request, $arguments = null)
    {

        $token = $request->getHeaderLine("Authorization");

        if (empty($token)) return $this->respond(['token', 'user'], Response::HTTP_FORBIDDEN);

        try {
            $key = getenv('JWT_SECRET');
            $verifyToken = JWT::decode($token, new Key($key, 'HS256'));

            if (empty($verifyToken)) return $this->respond(['token', 'user'], Response::HTTP_FORBIDDEN);

            $db = db_connect();
            $user = $db->query("SELECT * FROM users WHERE id=" . $verifyToken->id . "")->getResult('array');

            return $this->respond([
                'token' => $token,
                'user' => $user[0]
            ], Response::HTTP_OK);
            
        } catch (\Throwable $th) {
            return $this->respond(['token', 'user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        } //
    }

    /**
     * Allows After filters to inspect and modify the response
     * object as needed. This method does not allow any way
     * to stop execution of other after filters, short of
     * throwing an Exception or Error.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @param array|null        $arguments
     *
     * @return ResponseInterface|void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        //
    }
}
