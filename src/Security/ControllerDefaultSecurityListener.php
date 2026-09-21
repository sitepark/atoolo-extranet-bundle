<?php

declare(strict_types=1);

namespace Atoolo\Extranet\Security;

use Overblog\GraphQLBundle\Controller\GraphController;
use ReflectionClass;
use ReflectionException;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ControllerDefaultSecurityListener implements EventSubscriberInterface
{
    public function __construct(private readonly ?Security $security) {}

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => 'onController',
        ];
    }

    /**
     * @throws ReflectionException
     */
    public function onController(ControllerEvent $event): void
    {

        $siteMode = $_SERVER['SITE_MODE'] ?? '';

        if ($siteMode !== 'extranet') {
            return;
        }

        if ($this->security === null) {
            throw new AccessDeniedException('security is not configured');
        }

        if ($this->security->isGranted('ROLE_WEB_ACCOUNT')) {
            return;
        }

        if ($this->hasSecurityAttribute($event->getController())) {
            return;
        }

        throw new AccessDeniedException('web-account authentication required');
    }

    /**
     * @throws ReflectionException
     */
    private function hasSecurityAttribute(callable $controller): bool
    {
        if (!is_array($controller)) {
            return false;
        }

        [$object, $method] = $controller;

        // Access control is handled via GraphQLDefaultAccessConfigProcessor
        if ($object instanceof GraphController) {
            return true;
        }

        $reflectionClass = new ReflectionClass($object);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $methodAttrs = $reflectionMethod->getAttributes(IsGranted::class);
        if (!empty($methodAttrs)) {
            return true;
        }

        $classAttrs = $reflectionClass->getAttributes(IsGranted::class);
        if (!empty($classAttrs)) {
            return true;
        }

        return false;
    }
}
