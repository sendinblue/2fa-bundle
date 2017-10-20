<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Provider;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token\SecondFactorToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class SecondFactorProvider implements AuthenticationProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof SecondFactorToken;
    }
}
