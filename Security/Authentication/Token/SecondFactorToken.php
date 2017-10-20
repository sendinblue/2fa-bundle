<?php

namespace SendinBlue\Bundle\TwoFactorAuthenticationBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class SecondFactorToken implements TokenInterface
{
    /** @var TokenInterface */
    private $firstToken;

    /**
     * @param TokenInterface $firstToken
     */
    public function __construct(TokenInterface $firstToken)
    {
        $this->firstToken = $firstToken;
    }

    /**
     * @return TokenInterface
     */
    public function getFirstToken()
    {
        return $this->firstToken;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString()
    {
        return "2FA ({$this->firstToken})";
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->firstToken->getRoles();
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getUser()
    {
        return $this->firstToken->getUser();
    }

    /**
     * {@inheritdoc}
     */
    public function setUser($user)
    {
        throw new \LogicException('Cannot set this token user.');
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return $this->firstToken->getUsername();
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated()
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated($isAuthenticated)
    {
        throw new \LogicException('This token always is authenticated by default.');
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
        $this->firstToken->eraseCredentials();
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributes()
    {
        return $this->firstToken->getAttributes();
    }

    /**
     * {@inheritdoc}
     */
    public function setAttributes(array $attributes)
    {
        $this->firstToken->setAttributes($attributes);
    }

    /**
     * {@inheritdoc}
     */
    public function hasAttribute($name)
    {
        return $this->firstToken->hasAttribute($name);
    }

    /**
     * {@inheritdoc}
     */
    public function getAttribute($name)
    {
        return $this->firstToken->getAttribute($name);
    }

    /**
     * {@inheritdoc}
     */
    public function setAttribute($name, $value)
    {
        $this->firstToken->setAttribute($name, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize($this->firstToken);
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        $this->firstToken = unserialize($serialized);
    }
}
