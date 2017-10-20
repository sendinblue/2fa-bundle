<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Authenticator;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token\SecondFactorToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface SuccessHandlerInterface
{
    /**
     * @param Request           $request
     * @param SecondFactorToken $token
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, SecondFactorToken $token);
}
