<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class TwoFactorAuthenticationFactory implements SecurityFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $definitionClassName = $this->getDefinitionClassname();

        $providerId = "security.authentication.provider.2fa.{$id}";
        $container->setDefinition($providerId, new $definitionClassName('security.authentication.provider.2fa'));

        $listenerId = "security.authentication.listener.2fa.{$id}";
        $listenerDefinition = $container
            ->setDefinition($listenerId, new $definitionClassName('security.authentication.listener.2fa'))
            ->replaceArgument(2, new Reference($userProvider))
            ->replaceArgument(7, $config)
            ->addTag('kernel.event_subscriber')
        ;

        if ($config['remember_me']) {
            $listenerDefinition->addTag('security.remember_me_aware', ['id' => $id, 'provider' => $userProvider]);
        }

        $authenticators = [];

        if ($config['otp']['enabled']) {
            $otpAuthenticatorId = "sendinblue_2fa.otp_authenticator.{$id}";
            $otpAuthenticatorDefinition = $container
                ->setDefinition($otpAuthenticatorId, new $definitionClassName('sendinblue_2fa.code_authenticator'))
                ->replaceArgument(1, new Reference($config['otp']['checker']))
                ->replaceArgument(2, $config['otp'])
            ;
            if ($config['otp']['failure_handler']) {
                $otpAuthenticatorDefinition->replaceArgument(3, new Reference($config['otp']['failure_handler']));
            }
            if ($config['otp']['success_handler']) {
                $otpAuthenticatorDefinition->replaceArgument(4, new Reference($config['otp']['success_handler']));
            }

            $authenticators[] = new Reference($otpAuthenticatorId);
        }

        if ($config['recovery_code']['enabled']) {
            $recoveryCodeAuthenticatorId = "sendinblue_2fa.recovery_code_authenticator.{$id}";
            $recoveryCodeAuthenticatorDefinition = $container
                ->setDefinition($recoveryCodeAuthenticatorId, new $definitionClassName('sendinblue_2fa.code_authenticator'))
                ->replaceArgument(1, new Reference($config['recovery_code']['checker']))
                ->replaceArgument(2, $config['recovery_code'])
            ;
            if ($config['recovery_code']['failure_handler']) {
                $recoveryCodeAuthenticatorDefinition->replaceArgument(3, new Reference($config['recovery_code']['failure_handler']));
            }
            if ($config['recovery_code']['success_handler']) {
                $recoveryCodeAuthenticatorDefinition->replaceArgument(4, new Reference($config['recovery_code']['success_handler']));
            }

            $authenticators[] = new Reference($recoveryCodeAuthenticatorId);
        }

        $listenerDefinition->replaceArgument(6, $authenticators);

        return [$providerId, $listenerId, $defaultEntryPoint];
    }

    /**
     * {@inheritdoc}
     */
    public function getPosition()
    {
        return 'form';
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return '2fa';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $builder)
    {
        $builder = $builder->children();

        $builder
            ->scalarNode('default_authenticator')
                ->validate()
                ->ifNotInArray(['otp', 'recovery_code'])
                    ->thenInvalid('Invalid authenticator %s.')
                ->end()
            ->end()
            ->scalarNode('default_target_path')->defaultValue('/')->end()
            ->scalarNode('target_path_parameter')->defaultValue('_target_path')->end()
            ->booleanNode('remember_me')->defaultTrue()->end()
            ->arrayNode('otp')
                ->canBeEnabled()
                ->children()
                    ->scalarNode('default_target_path')->defaultNull()->end()
                    ->scalarNode('target_path_parameter')->defaultNull()->end()
                    ->scalarNode('login_path')->defaultValue('/2fa/otp')->end()
                    ->scalarNode('check_path')->defaultValue('/2fa/otp')->end()
                    ->scalarNode('code_parameter')->defaultValue('_code')->end()
                    ->booleanNode('post_only')->defaultTrue()->end()
                    ->scalarNode('checker')->defaultValue('sendinblue_2fa.otp_checker')->end()
                    ->scalarNode('failure_handler')->defaultNull()->end()
                    ->scalarNode('success_handler')->defaultNull()->end()
                ->end()
            ->end()
            ->arrayNode('recovery_code')
                ->canBeEnabled()
                ->children()
                    ->scalarNode('default_target_path')->defaultNull()->end()
                    ->scalarNode('target_path_parameter')->defaultNull()->end()
                    ->scalarNode('login_path')->defaultValue('/2fa/recovery')->end()
                    ->scalarNode('check_path')->defaultValue('/2fa/recovery')->end()
                    ->scalarNode('code_parameter')->defaultValue('_recovery_code')->end()
                    ->booleanNode('post_only')->defaultTrue()->end()
                    ->scalarNode('checker')->defaultValue('sendinblue_2fa.recovery_code_checker')->end()
                    ->scalarNode('failure_handler')->defaultNull()->end()
                    ->scalarNode('success_handler')->defaultNull()->end()
                ->end()
            ->end()
        ;
    }

    /**
     * @return string
     */
    private function getDefinitionClassname()
    {
        return class_exists(ChildDefinition::class) ? ChildDefinition::class : DefinitionDecorator::class;
    }
}
