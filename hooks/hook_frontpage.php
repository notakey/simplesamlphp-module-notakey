<?php

/**
 * Hook to add link to the frontpage.
 *
 * @param array &$links  The links on the frontpage, split into sections.
 */
function notakey_hook_frontpage(&$links)
{
    assert('is_array($links)');
    assert('array_key_exists("links", $links)');

    $links['federation']['notakeymetacvrt'] = [
        'href' => \SimpleSAML\Module::getModuleURL('notakey/metacvrt.php'),
        'text' => [
            'en' => 'XML metadata to JSON converter'
        ],
        'shorttext' => [
            'en' => 'Metadata converter',
        ],
    ];
}
