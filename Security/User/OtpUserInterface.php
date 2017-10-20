<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User;

use SendinBlue\Otp\Otp;

interface OtpUserInterface extends TwoFactorAuthenticatedUserInterface
{
    /**
     * @return Otp
     */
    public function getOtp();
}
