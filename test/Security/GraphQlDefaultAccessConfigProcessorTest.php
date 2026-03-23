<?php

declare(strict_types=1);

namespace Atoolo\Extranet\Test\Security;

use Atoolo\Extranet\Security\GraphQlDefaultAccessConfigProcessor;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class GraphQlDefaultAccessConfigProcessorTest extends TestCase
{
    private Security $security;
    private GraphQlDefaultAccessConfigProcessor $processor;

    protected function setUp(): void
    {
        $this->security = $this->createMock(Security::class);
        $this->processor = new GraphQlDefaultAccessConfigProcessor($this->security);
    }

    protected function tearDown(): void
    {
        unset($_SERVER['SITE_MODE']);
    }

    public function testProcessReturnsConfigUnchangedForNonRootType(): void
    {
        $config = ['name' => 'SomeOtherType', 'fields' => []];

        $result = $this->processor->process($config);

        $this->assertSame($config, $result, 'Non-root types must be returned unchanged');
    }

    public function testProcessReturnsConfigUnchangedWhenNotInExtranetMode(): void
    {
        unset($_SERVER['SITE_MODE']);
        $config = ['name' => 'RootQuery', 'fields' => []];

        $result = $this->processor->process($config);

        $this->assertSame($config, $result, 'Config must not be modified outside extranet mode');
    }

    public function testProcessReturnsConfigUnchangedWhenUserIsGranted(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security
            ->method('isGranted')
            ->with('ROLE_WEB_ACCOUNT')
            ->willReturn(true);
        $config = ['name' => 'RootQuery', 'fields' => []];

        $result = $this->processor->process($config);

        $this->assertSame($config, $result, 'Config must not be modified when user has ROLE_WEB_ACCOUNT');
    }

    public function testProcessHandlesRootMutationInExtranetMode(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = ['name' => 'RootMutation'];

        $result = $this->processor->process($config);

        $this->assertSame('RootMutation', $result['name'], 'RootMutation name must be preserved');
    }

    public function testProcessDoesNotWrapNonCallableFields(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $originalFields = ['field1' => ['type' => 'String']];
        $config = ['name' => 'RootQuery', 'fields' => $originalFields];

        $result = $this->processor->process($config);

        $this->assertSame(
            $originalFields,
            $result['fields'],
            'Non-callable fields array must not be wrapped',
        );
    }

    public function testProcessWrapsCallableFieldsWithClosure(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => ['type' => 'String']],
        ];

        $result = $this->processor->process($config);

        $this->assertIsCallable($result['fields'], 'Fields must be wrapped in a callable');
    }

    public function testProcessAddsAccessClosureToFieldWithoutAccess(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => ['type' => 'String']],
        ];

        $result = $this->processor->process($config);
        $fields = ($result['fields'])();

        $this->assertIsCallable(
            $fields['field1']['access'],
            'Access closure must be injected for fields without existing access',
        );
    }

    public function testProcessDoesNotOverrideExistingAccessOnField(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $existingAccess = static fn() => true;
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => ['type' => 'String', 'access' => $existingAccess]],
        ];

        $result = $this->processor->process($config);
        $fields = ($result['fields'])();

        $this->assertSame(
            $existingAccess,
            $fields['field1']['access'],
            'Existing access closure must not be overridden',
        );
    }

    public function testProcessDoesNotModifyNonArrayField(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => 'scalar_value'],
        ];

        $result = $this->processor->process($config);
        $fields = ($result['fields'])();

        $this->assertSame(
            'scalar_value',
            $fields['field1'],
            'Non-array field values must not be modified',
        );
    }

    public function testInjectedAccessClosureThrowsAccessDeniedException(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => ['type' => 'String']],
        ];

        $result = $this->processor->process($config);
        $fields = ($result['fields'])();

        $this->expectException(AccessDeniedException::class);

        ($fields['field1']['access'])();
    }

    public function testInjectedAccessClosureThrowsWithCorrectMessage(): void
    {
        $_SERVER['SITE_MODE'] = 'extranet';
        $this->security->method('isGranted')->willReturn(false);
        $config = [
            'name' => 'RootQuery',
            'fields' => static fn() => ['field1' => ['type' => 'String']],
        ];

        $result = $this->processor->process($config);
        $fields = ($result['fields'])();

        $this->expectExceptionMessage('web-account authentication required');

        ($fields['field1']['access'])();
    }
}
