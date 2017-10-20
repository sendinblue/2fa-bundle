<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Authenticator;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token\SecondFactorToken;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

interface AuthenticatorInterface
{
    /**
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request);

    /**
     * @param Request $request
     *
     * @return mixed
     */
    public function getCredentials(Request $request);

    /**
     * @param $credentials
     * @param TwoFactorAuthenticatedUserInterface $user
     *
     * @throws AuthenticationException
     */
    public function checkCredentials($credentials, TwoFactorAuthenticatedUserInterface $user);

    /**
     * @param Request           $request
     * @param SecondFactorToken $token
     *
     * @return Response
     */
    public function onAuthenticationSuccess(Request $request, SecondFactorToken $token);

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception);
}
