<?php

/**
 * Handler for response for SP Request Initiation Protocol
 */

if (!array_key_exists('PATH_INFO', $_SERVER)) {
	throw new SimpleSAML_Error_BadRequest('Missing authentication source ID in Request Initiator url');
}

$sourceId = substr($_SERVER['PATH_INFO'], 1);
// Ensure the source is an SP
$source = SimpleSAML_Auth_Source::getById($sourceId, 'sspmod_saml_Auth_Source_SP');
if ($source === NULL) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}

//TODO: should we require the authsource to 'enable' this functionality?

//FIXME: validate target url is valid for this SP. e.g. no open redirects
$target = $_REQUEST['target'];
//FIXME: allow configuring default target in authsources.
// Default target is the test auth page.
$target = SimpleSAML\Utils\HTTP::getBaseURL() . 'module.php/core/authenticate.php?as=' . $sourceId;

$authParams = array(
    'ReturnTo' => $target,
);

$entityID = $_REQUEST['entityID'];
if (isset($entityID)) {
    $authParams['saml:idp'] = $entityID;
}

//TODO: handle isPassive and forceAuthn params and special rules

$auth = new SimpleSAML_Auth_Simple($sourceId);
$auth->login($authParams);
