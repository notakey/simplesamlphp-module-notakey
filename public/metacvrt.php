<?php

declare(strict_types=1);

use SimpleSAML\Configuration;
use SimpleSAML\Metadata\SAMLParser;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

$config = Configuration::getInstance();

(new Utils\Auth())->requireAdmin();

$xmldata = '';
if (!empty($_FILES['xmlfile']['tmp_name']) && is_uploaded_file($_FILES['xmlfile']['tmp_name'])) {
    $xmldata = trim((string) file_get_contents($_FILES['xmlfile']['tmp_name']));
} elseif (array_key_exists('xmldata', $_POST)) {
    $xmldata = trim((string) $_POST['xmldata']);
}

$output = [];

if (!empty($xmldata)) {
    $xmlUtils = new Utils\XML();
    $xmlUtils->checkSAMLMessage($xmldata, 'saml-meta');
    $entities = SAMLParser::parseDescriptorsString($xmldata);

    // get all metadata for the entities
    foreach ($entities as &$entity) {
        $entity = [
            'saml20-sp-remote'  => $entity->getMetadata20SP(),
            'saml20-idp-remote' => $entity->getMetadata20IdP(),
        ];
    }
    unset($entity);

    // transpose from $entities[entityid][type] to $output[type][entityid]
    $transposed = (new Utils\Arrays())->transpose($entities);

    // merge all metadata of each type to a single string which should be added to the corresponding file
    foreach ($transposed as $type => $typeEntities) {
        $text = '';
        foreach ($typeEntities as $entityMetadata) {
            if ($entityMetadata === null) {
                continue;
            }

            // remove the entityDescriptor element because it is unused, and only makes the output harder to read
            unset($entityMetadata['entityDescriptor']);

            $text .= json_encode($entityMetadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        if ($text !== '') {
            $output[$type] = $text;
        }
    }
}

$template = new Template($config, 'notakey:metacvrt.twig');
$template->data['xmldata'] = $xmldata;
$template->data['output'] = $output;
$template->send();
