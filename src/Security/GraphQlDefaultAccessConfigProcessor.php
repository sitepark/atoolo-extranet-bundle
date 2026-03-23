<?php

declare(strict_types=1);

namespace Atoolo\Extranet\Security;

use Overblog\GraphQLBundle\Definition\ConfigProcessor\ConfigProcessorInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class GraphQlDefaultAccessConfigProcessor implements ConfigProcessorInterface
{
    public function __construct(private readonly Security $security) {}

    /**
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    public function process(array $config): array
    {
        if ($config['name'] !== 'RootQuery' && $config['name'] !== 'RootMutation') {
            return $config;
        }

        if (!$this->isGlobalAccessDenied()) {
            return $config;
        }

        $deniedAccess = static function (): void {
            throw new AccessDeniedException('web-account authentication required');
        };

        if (isset($config['fields']) && is_callable($config['fields'])) {
            $config['fields'] = static function () use ($deniedAccess, $config) {
                $fields = $config['fields']();

                foreach ($fields as &$field) {
                    if (is_array($field) && !isset($field['access'])) {
                        $field['access'] = $deniedAccess;
                    }
                }
                return $fields;
            };
        }

        return $config;
    }

    private function isGlobalAccessDenied(): bool
    {
        $siteMode = $_SERVER['SITE_MODE'] ?? '';
        return ($siteMode === 'extranet' && !$this->security->isGranted('ROLE_WEB_ACCOUNT'));
    }
}
