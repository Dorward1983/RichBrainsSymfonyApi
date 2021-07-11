<?php

namespace App\Controller\Api;

use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Validator\Constraints;
use Symfony\Component\Validator\Constraints\Email;
use App\Entity\User;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;


class ApiController extends AbstractController
{
    /**
     * @Route("/api", name="api")
     */
    public function  index()
    {
        return $this->response('HI');
    }

    /**
     * @Route("/api/user/create", name="api_user_create")
     * @param Request $request
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @return JsonResponse
     */
    public function createAction(Request $request, UserPasswordEncoderInterface $passwordEncoder, ValidatorInterface $validator)
    {

        $request = $this->transformJsonBody($request);
        $response = [];

        if($request) {
            $user = new User();
            $em = $this->getDoctrine()->getManager();

            $password = $request['password'] ?? '';
            $user->setPassword($password);
            $user->setRoles(['ROLE_USER']);
            $user->setEmail($request['email'] ?? '');
            $user->setPhone($request['phone'] ?? '');
            $user->setFirstName($request['firstName'] ?? '');
            $user->setLastName($request['lastName'] ?? '');

            $violations = $validator->validate($user);
            $messages = [];

            if(count($violations)) {
                foreach ($violations as $constraint) {
                    $prop = $constraint->getPropertyPath();
                    $messages[$prop][] = $constraint->getMessage();
                }

                $response = [
                    'status' => 'validation error',
                    'message' => $messages
                ];

            } else {

                $password = $passwordEncoder->encodePassword($user, $password);
                $user->setPassword($password);

                $em->persist($user);
                $em->flush();

                if($id = $user->getId()) {
                    $response = [
                        'status' => 'ok',
                        'user_id' => $id
                    ];
                }

            }
        } else {
            $response = [
                'status' => 'error',
                'message' => 'Не переданы данные'
            ];
        }

        return $this->response($response);
    }

    /**
     * @Route("/api/user/update/{userId}", name="api_user_update")
     * @param Request $request
     * @param int $userId
     * @return JsonResponse
     */
    public function updateAction(
        Request $request,
        int $userId,
        UserPasswordEncoderInterface $passwordEncoder,
        ValidatorInterface $validator,
        TokenStorageInterface $tokenStorage
    )
    {
        // Getting auth user info
        $authUser = $tokenStorage->getToken()->getUser();
        $authUserId = $authUser->getId();
        $authUserRoles = $authUser->getRoles();

        $response = [];

        if(($authUserId == $userId) || in_array('ROLE_ADMIN', $authUserRoles)) {
            $user = $this->getDoctrine()->getRepository(User::class)->find($userId);

            $request = $this->transformJsonBody($request);

            if(!empty($user) && !empty($request)) {
                $em = $this->getDoctrine()->getManager();

                $password = $request['password'] ?? '';
                $user->setPassword($password);
                $user->setEmail($request['email'] ?? '');
                $user->setPhone($request['phone'] ?? '');
                $user->setFirstName($request['firstName'] ?? '');
                $user->setLastName($request['lastName'] ?? '');

                $violations = $validator->validate($user);
                $messages = [];

                if(count($violations)) {
                    foreach ($violations as $constraint) {
                        $prop = $constraint->getPropertyPath();
                        $messages[$prop][] = $constraint->getMessage();
                    }

                    $response = [
                        'status' => 'validation error',
                        'message' => $messages
                    ];

                } else {

                    $password = $passwordEncoder->encodePassword($user, $password);
                    $user->setPassword($password);

                    $em->flush();

                    $response = [
                        'status' => 'ok',
                        'message' => "Данные по пользователю {$user->getId()} обновлены"
                    ];
                    
                }
            } else {
                $response = [
                    'status' => 'error',
                    'message' => 'Пользователь не найден'
                ];
            }
        } else {
            $response = [
                'status' => 'error',
                'message' => 'Нет доступа'
            ];
        }



        return $this->response($response);

    }

    /**
     * @Route("/api/user/delete/{userId}", name="api_user_delete")
     * @param int $userId
     * @return JsonResponse
     */
    public function deleteAction(int $userId)
    {

        $user = $this->getDoctrine()->getRepository(User::class)->find($userId);
        $response = [];

        if(!empty($user)) {
            $roles = $user->getRoles();
            if(!in_array('ROLE_ADMIN', $roles)) {
                // if user isn't admin

                $em = $this->getDoctrine()->getManager();
                $em->remove($user);
                $em->flush();

                $response = [
                    'status' => "ok",
                    'message' => "Пользователь $userId успешно удален"
                ];
            } else {
                $response = [
                    'status' => 'error',
                    'message' => 'Попытка удалить администратора'
                ];
            }
        } else {
            $response = [
                'status' => 'error',
                'message' => 'Пользователь не найден'
            ];
        }

        return $this->response($response);
    }

    /**
     * Returns a JSON response
     *
     * @param array $data
     * @param $status
     * @param array $headers
     * @return JsonResponse
     */
    public function response($data, $status = 200, $headers = [])
    {
        return new JsonResponse($data, $status, $headers);
    }

    protected function transformJsonBody(\Symfony\Component\HttpFoundation\Request $request)
    {
        $data = json_decode($request->getContent(), true);
        return $data;
    }

}