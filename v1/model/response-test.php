<?php

require_once ('Response.php');

// rest teh api response functionality

$response = new Response();

// set properties with dummy test date:
$response->setSuccess(true);
$response->setHttpStatusCode(200);
$response->addMessage('This is a test message #1');
$response->addMessage('this is the test message #2');
$response->toCache(true);

// obtain content of element:
// echo $response->getProperty('_success');

// call the Send method to process the data:
$response->send();
