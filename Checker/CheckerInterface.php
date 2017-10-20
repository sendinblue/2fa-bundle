<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\BadFactorException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\FactorExpiredException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;

interface CheckerInterface
{
    /**
     * @param mixed                               $credentials
     * @param TwoFactorAuthenticatedUserInterface $user
     *
     * @throws BadFactorException
     * @throws FactorExpiredException
     */
    public function check($credentials, TwoFactorAuthenticatedUserInterface $user);
}
