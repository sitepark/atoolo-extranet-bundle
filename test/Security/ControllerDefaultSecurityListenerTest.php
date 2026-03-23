<?php

declare(strict_types=1);

namespace Atoolo\Extranet\Test\Security;

use Atoolo\Extranet\Security\ControllerDefaultSecurityListener;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ControllerDefaultSecurityListenerTest extends TestCase
{
    private Security $security;
    private ControllerDefaultSecurityListener $listener;

    protected function setUp(): void
    {
        $this->security = $this->createMock(Security::class);
        $this->listener = new ControllerDefaultSecurityListener($this->security);
    }

    protected function tearDown(): void
    {
        unset($_SERVER['SITE_MODE']);
    }

    private function createEvent(callable $controller): ControllerEvent
    {
        $kernel = $this->createMock(HttpKernelInterface::class);
        $request = Request::create('/');
        return new ControllerEvent($kernel, $controller, $request, HttpKernelInterface::MAIN_REQUEST);
    }

    public function testGetSubscribedEventsReturnsControllerEvent(): void
    {
        $events = ControllerDefaultSecurityListener::getSubscribedEvents();

        $this->assertSame(
            [KernelEvents::CONTROLLER => 'onController'],
            $events,
            'Expected CONTROLLER event mapped to onController',
        );
    }

    public function testOnControllerDoesNothingWhenSiteModeIsNotExtranet(): void
    {
        unset($_SERVER['SITE_MODE']);
        $event = $this->createEvent(static function (): void {});

        $this->listener->onController($event);

        $this->expectNotToPerformAssertions();
    }

    public function testOnControllerThrowsWhenSecurityIsNull(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $listener = new ControllerDefaultSecurityListener(null);
        $event = $this->createEvent(static function (): void {});

        $this->expectException(AccessDeniedException::class);

        $listener->onController($event);
    }

    public function testOnControllerThrowsWithCorrectMessageWhenSecurityIsNull(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $listener = new ControllerDefaultSecurityListener(null);
        $event = $this->createEvent(static function (): void {});

        $this->expectExceptionMessage('security is not configured');

        $listener->onController($event);
    }

    public function testOnControllerDoesNothingWhenUserHasRoleWebAccount(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security
            ->method('isGranted')
            ->with('ROLE_WEB_ACCOUNT')
            ->willReturn(true);
        $event = $this->createEvent(static function (): void {});

        $this->listener->onController($event);

        $this->expectNotToPerformAssertions();
    }

    public function testOnControllerThrowsWhenControllerIsNotAnArray(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $event = $this->createEvent(static function (): void {});

        $this->expectException(AccessDeniedException::class);

        $this->listener->onController($event);
    }

    public function testOnControllerDoesNothingWhenMethodHasIsGrantedAttribute(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $controller = new ExtranetControllerWithIsGrantedOnMethod();
        $event = $this->createEvent([$controller, 'action']);

        $this->listener->onController($event);

        $this->expectNotToPerformAssertions();
    }

    public function testOnControllerDoesNothingWhenClassHasIsGrantedAttribute(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $controller = new ExtranetControllerWithIsGrantedOnClass();
        $event = $this->createEvent([$controller, 'action']);

        $this->listener->onController($event);

        $this->expectNotToPerformAssertions();
    }

    public function testOnControllerThrowsWhenNoSecurityAttributes(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $controller = new ExtranetPlainController();
        $event = $this->createEvent([$controller, 'action']);

        $this->expectException(AccessDeniedException::class);

        $this->listener->onController($event);
    }

    public function testOnControllerThrowsWithCorrectMessageWhenNoSecurityAttributes(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $controller = new ExtranetPlainController();
        $event = $this->createEvent([$controller, 'action']);

        $this->expectExceptionMessage('web-account authentication required');

        $this->listener->onController($event);
    }

}

// ---------------------------------------------------------------------------
// Controller fixtures
// ---------------------------------------------------------------------------

class ExtranetPlainController
{
    public function action(): void {}
}

class ExtranetControllerWithIsGrantedOnMethod
{
    #[IsGranted('ROLE_USER')]
    public function action(): void {}
}

#[IsGranted('ROLE_USER')]
class ExtranetControllerWithIsGrantedOnClass
{
    public function action(): void {}
}
