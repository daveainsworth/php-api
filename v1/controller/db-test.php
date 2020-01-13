<?php
require_once ('db.php');
require_once ('../model/Response.php');

    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();

try {

    $writeDB = DB::connectWriteDB();

} catch (PDOException $ex) {

    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage("Database connection error");
    $response->send();
    exit;
}