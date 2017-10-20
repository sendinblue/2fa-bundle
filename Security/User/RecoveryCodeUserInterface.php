<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User;

interface RecoveryCodeUserInterface extends TwoFactorAuthenticatedUserInterface
{
    /**
     * @return string[]
     */
    public function getAvailableRecoveryCodes();
}
