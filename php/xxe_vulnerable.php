<?php
// XXE Vulnerable Test Cases

// Matches: php-xxe-simplexml
function vulnerable_simplexml($xmlInput) {
    return simplexml_load_string($xmlInput);
}

// Matches: php-xxe-domdocument
function vulnerable_domdocument($xmlInput) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlInput);
    return $dom;
}

// Matches: php-xxe-libxml-disable-false
function vulnerable_libxml() {
    libxml_disable_entity_loader(false);
}

// Safe: disable entity loading
function safe_xml_parse($xmlInput) {
    libxml_disable_entity_loader(true);
    return simplexml_load_string($xmlInput, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_NONET);
}
