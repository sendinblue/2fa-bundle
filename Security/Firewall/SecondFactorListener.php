<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Firewall;

use Psr\Log\LoggerInterface;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Authenticator\AuthenticatorInterface;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token\SecondFactorToken;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\RememberMeToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\FirewallMapInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class SecondFactorListener implements ListenerInterface, EventSubscriberInterface
{
    const KEY = '_first_token';

    /** @var FirewallMapInterface */
    private $firewallMap;

    /** @var TokenStorageInterface */
    private $tokenStorage;

    /** @var UserProviderInterface */
    private $userProvider;

    /** @var SessionAuthenticationStrategyInterface */
    private $sessionAuthenticationStrategy;

    /** @var HttpUtils */
    private $httpUtils;

    /** @var EventDispatcherInterface */
    private $dispatcher;

    /** @var AuthenticatorInterface[] */
    private $authenticators;

    /** @var array */
    private $options;

    /** @var LoggerInterface */
    private $logger;

    /** @var RememberMeServicesInterface */
    private $rememberMeServices;

    /**
     * @param FirewallMapInterface                   $firewallMap
     * @param TokenStorageInterface                  $tokenStorage
     * @param UserProviderInterface                  $userProvider
     * @param SessionAuthenticationStrategyInterface $sessionAuthenticationStrategy
     * @param HttpUtils                              $httpUtils
     * @param EventDispatcherInterface               $dispatcher
     * @param AuthenticatorInterface[]               $authenticators
     * @param array                                  $options
     * @param LoggerInterface|null                   $logger
     */
    public function __construct(
        FirewallMapInterface $firewallMap,
        TokenStorageInterface $tokenStorage,
        UserProviderInterface $userProvider,
        SessionAuthenticationStrategyInterface $sessionAuthenticationStrategy,
        HttpUtils $httpUtils,
        EventDispatcherInterface $dispatcher,
        array $authenticators,
        array $options,
        LoggerInterface $logger = null
    ) {
        $this->firewallMap = $firewallMap;
        $this->tokenStorage = $tokenStorage;
        $this->userProvider = $userProvider;
        $this->sessionAuthenticationStrategy = $sessionAuthenticationStrategy;
        $this->httpUtils = $httpUtils;
        $this->dispatcher = $dispatcher;
        $this->authenticators = $authenticators;
        $this->options = $options;
        $this->logger = $logger;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $session = $request->getSession();
        if (null === $session) {
            return;
        }

        if (!$session->has(self::KEY)) {
            return;
        }

        /** @var TokenInterface $firstFactorToken */
        $firstFactorToken = unserialize($session->get(self::KEY));

        try {
            foreach ($this->authenticators as $authenticator) {
                if (!$authenticator->supports($request)) {
                    continue;
                }

                $user = $this->userProvider->loadUserByUsername($firstFactorToken->getUsername());
                if (!$user instanceof TwoFactorAuthenticatedUserInterface) {
                    throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
                }

                $authenticator->checkCredentials($authenticator->getCredentials($request), $user);

                $event->setResponse($this->onSuccess($request, new SecondFactorToken($firstFactorToken), $authenticator));

                break;
            }
        } catch (AuthenticationException $e) {
            $event->setResponse($this->onFailure($request, $e, $authenticator));
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::RESPONSE => 'onResponse',
            SecurityEvents::INTERACTIVE_LOGIN => ['onInteractiveLogin', 2048],
        ];
    }

    /**
     * @param InteractiveLoginEvent $e
     */
    public function onInteractiveLogin(InteractiveLoginEvent $e)
    {
        $token = $e->getAuthenticationToken();
        if ($token instanceof SecondFactorToken || $token instanceof RememberMeToken) {
            return;
        }

        $user = $token->getUser();
        if (!$user instanceof TwoFactorAuthenticatedUserInterface || !$user->hasEnabled2FA()) {
            return;
        }

        $request = $e->getRequest();
        $listen2FA = false;

        foreach ($this->firewallMap->getListeners($request)[0] as $listener) {
            if ($listener instanceof self) {
                $listen2FA = true;

                break;
            }
        }

        if (!$listen2FA) {
            return;
        }

        $e->stopPropagation();
        $request->attributes->set(self::KEY, $token);
        $this->tokenStorage->setToken(null);
    }

    /**
     * @param FilterResponseEvent $e
     */
    public function onResponse(FilterResponseEvent $e)
    {
        $request = $e->getRequest();

        if (!$request->attributes->has(self::KEY)) {
            return;
        }

        $request->getSession()->set(self::KEY, serialize($request->attributes->get(self::KEY)));

        $e->setResponse($this->httpUtils->createRedirectResponse(
            $request,
            $this->options[$this->options['default_authenticator']]['login_path']
        ));
    }

    /**
     * @param RememberMeServicesInterface $rememberMeServices
     */
    public function setRememberMeServices(RememberMeServicesInterface $rememberMeServices)
    {
        $this->rememberMeServices = $rememberMeServices;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $failed
     * @param AuthenticatorInterface  $authenticator
     *
     * @return Response
     */
    private function onFailure(Request $request, AuthenticationException $failed, AuthenticatorInterface $authenticator)
    {
        if (null !== $this->logger) {
            $this->logger->info('Authentication request failed.', ['exception' => $failed]);
        }

        $session = $request->getSession();
        $session->set(Security::AUTHENTICATION_ERROR, $failed);

        if (!$failed instanceof BadCredentialsException) {
            $session->remove(self::KEY);
        }

        return $authenticator->onAuthenticationFailure($request, $failed);
    }

    /**
     * @param Request                $request
     * @param SecondFactorToken      $token
     * @param AuthenticatorInterface $authenticator
     *
     * @return Response
     */
    private function onSuccess(Request $request, SecondFactorToken $token, AuthenticatorInterface $authenticator)
    {
        if (null !== $this->logger) {
            $this->logger->info('User has been authenticated successfully.', ['username' => $token->getUsername()]);
        }

        $this->tokenStorage->setToken($token);

        $session = $request->getSession();
        $session->remove(Security::AUTHENTICATION_ERROR);
        $session->remove(self::KEY);
        $this->sessionAuthenticationStrategy->onAuthentication($request, $token);

        $loginEvent = new InteractiveLoginEvent($request, $token);
        $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);

        $response = $authenticator->onAuthenticationSuccess($request, $token);

        if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }

        return $response;
    }
}
