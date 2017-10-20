<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User;

interface TwoFactorAuthenticatedUserInterface
{
    /**
     * @return bool
     */
    public function hasEnabled2FA();
}
