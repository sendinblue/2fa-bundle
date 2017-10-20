<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\BadFactorException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\OtpUserInterface;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;
use SendinBlue\Otp\Exception\InvalidCodeException;

class OtpChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function check($credentials, TwoFactorAuthenticatedUserInterface $user)
    {
        if (!$user instanceof OtpUserInterface) {
            throw new \InvalidArgumentException();
        }

        try {
            $user->getOtp()->check($credentials);
        } catch (InvalidCodeException $e) {
            throw new BadFactorException('', 0, $e);
        }
    }
}
