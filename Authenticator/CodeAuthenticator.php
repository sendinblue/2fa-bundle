<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Authenticator;

use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\CheckerInterface;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\BadFactorException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Checker\Exception\FactorExpiredException;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token\SecondFactorToken;
use SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\User\TwoFactorAuthenticatedUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Http\HttpUtils;

class CodeAuthenticator implements AuthenticatorInterface
{
    /** @var HttpUtils */
    private $httpUtils;

    /** @var CheckerInterface */
    private $credentialsChecker;

    /** @var array */
    private $options;

    /** @var FailureHandlerInterface|null */
    private $failureHandler;

    /** @var SuccessHandlerInterface|null */
    private $successHandler;

    /**
     * @param HttpUtils                    $httpUtils
     * @param CheckerInterface             $credentialsChecker
     * @param array                        $options
     * @param FailureHandlerInterface|null $failureHandler
     * @param SuccessHandlerInterface|null $successHandler
     */
    public function __construct(
        HttpUtils $httpUtils,
        CheckerInterface $credentialsChecker,
        array $options,
        FailureHandlerInterface $failureHandler = null,
        SuccessHandlerInterface $successHandler = null
    ) {
        $this->httpUtils = $httpUtils;
        $this->credentialsChecker = $credentialsChecker;
        $this->options = $options;
        $this->failureHandler = $failureHandler;
        $this->successHandler = $successHandler;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request)
    {
        return $this->httpUtils->checkRequestPath($request, $this->options['check_path']) && null !== $this->getCode($request);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        return $this->getCode($request);
    }

    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, TwoFactorAuthenticatedUserInterface $user)
    {
        try {
            $this->credentialsChecker->check($credentials, $user);
        } catch (BadFactorException $e) {
            throw new BadCredentialsException('', 0, $e);
        } catch (FactorExpiredException $e) {
            throw new CredentialsExpiredException('', 0, $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, SecondFactorToken $token)
    {
        if ($this->successHandler && ($response = $this->successHandler->onAuthenticationSuccess($request, $token))) {
            return $response;
        }

        return $this->httpUtils->createRedirectResponse(
            $request,
            $request->get($this->options['target_path_parameter'], $this->options['default_target_path'])
        );
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($this->failureHandler && ($response = $this->failureHandler->onAuthenticationFailure($request, $exception))) {
            return $response;
        }

        return $this->httpUtils->createRedirectResponse($request, $this->options['login_path']);
    }

    /**
     * @param Request $request
     *
     * @return string
     */
    private function getCode(Request $request)
    {
        return $this->options['post_only']
            ? $request->request->get($this->options['code_parameter'])
            : $request->get($this->options['code_parameter'])
        ;
    }
}
