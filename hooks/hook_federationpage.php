<?php

declare(strict_types=1);

use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

/**
 * Hook to add the metadata to JSON converter to the admin federation page.
 *
 * @param \SimpleSAML\XHTML\Template &$template The template that we should alter in this hook.
 */
function notakey_hook_federationpage(Template &$template): void
{
    $template->data['links'][] = [
        'href' => Module::getModuleURL('notakey/metacvrt.php'),
        'text' => 'XML metadata to JSON converter',
    ];
}
