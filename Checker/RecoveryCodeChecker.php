<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\BadFactorException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\RecoveryCodeUserInterface;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;

class RecoveryCodeChecker implements CheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function check($credentials, TwoFactorAuthenticatedUserInterface $user)
    {
        if (!$user instanceof RecoveryCodeUserInterface) {
            throw new \InvalidArgumentException();
        }

        foreach ($user->getAvailableRecoveryCodes() as $recoveryCode) {
            if (hash_equals($recoveryCode, $credentials)) {
                return;
            }
        }

        throw new BadFactorException();
    }
}
