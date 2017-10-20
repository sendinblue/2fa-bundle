<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\DependencyInjection\Security\Factory\TwoFactorAuthenticationFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SendinBlueTwoFactorAuthenticationBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new TwoFactorAuthenticationFactory());
    }
}
