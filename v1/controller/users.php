<?php

require_once ('db.php');
require_once ('../model/Response.php');

// connect to the database, will always be write DB
try {

    $writeDB = DB::connectWriteDB();

} catch (PDOException $ex) {
    // write error to PHP error log
    error_log("connection error : " . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);  // Server Errror
    $response->setSuccess(false);
    $response->addMessage("Database connection error.");
    $response->send();
    exit;
}

// check the http request method, only POST accepted.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = new Response();
    $response->setHttpStatusCode(405);  // Request method not allowed
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed.");
    $response->send();
    exit;
}

// ensure content type is set to JSON
if ($_SERVER['CONTENT_TYPE'] !== 'application/json'){
    $response = new Response();
    $response->setHttpStatusCode(400);  // Client data error
    $response->setSuccess(false);
    $response->addMessage("Content Type header not set to JSON.");
    $response->send();
    exit;
}

// Get posted data and validate it is JSON data
$rawPostData = file_get_contents('php://input');
if(!$jsonData = json_decode($rawPostData)){
    $response = new Response();
    $response->setHttpStatusCode(400);  // Client data error
    $response->setSuccess(false);
    $response->addMessage("Request body is not valid JSON data.");
    $response->send();
    exit;
}

// check data, e.g. check mandatory fields are provided
if(!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)){
    $response = new Response();
    $response->setHttpStatusCode(400);  // Client data error
    $response->setSuccess(false);

    // make message back to client specific to the error:
    (!isset($jsonData->fullname) ? $response->addMessage("Full name not supplied.") : false);
    (!isset($jsonData->username) ? $response->addMessage("Username not supplied.")  : false);
    (!isset($jsonData->password) ? $response->addMessage("Password not supplied.")  : false);
    
    $response->send();
    exit;
}

// checkf or empty data or data fields too large for database tables.
if(strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255 ||
   strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 ||
   strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255  ) {
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client data error
        $response->setSuccess(false);

        // make message back to client specific to the error:
        (strlen($jsonData->fullname) < 1 ? $response->addMessage("Full name cannot be blank.") : false);
        (strlen($jsonData->fullname) > 255 ? $response->addMessage("Full name cannot be greater than 255 characters.") : false);
        (strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank.") : false);
        (strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be greater than 255 characters.") : false);
        (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank.") : false);
        (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be greater than 255 characters.") : false);
        
        $response->send();
        exit;
}

// tidy the data, trim etc
$fullname = trim($jsonData->fullname);
$username = trim($jsonData->username);
$password = $jsonData->password;

// query the database to ensure username is not already in use:
try {

    $query = $writeDB->prepare('SELECT id FROM tblusers WHERE username = :username');
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->execute();

    $rowCount = $query->rowCount();

    if ($rowCount !== 0 ){
        $response = new Response();
        $response->setHttpStatusCode(409);  // Data Conflict Error Msg
        $response->setSuccess(false);
        $response->addMessage("The username alrady exists.");
        $response->send();
        exit;
    }

// hash the password field.
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// insert this user into the database table
$query = $writeDB->prepare('INSERT INTO tblusers (fullname, username, password) 
                            VALUES(:fullname, :username, :password)');
$query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
$query->bindParam(':username' , $username, PDO::PARAM_STR);
$query->bindParam(':password', $hashed_password, PDO::PARAM_STR);
$query->execute();

$rowCount = $query->rowCount();

if($rowCount === 0){
    $response = new Response();
    $response->setHttpStatusCode(500);  // server Error Msg
    $response->setSuccess(false);
    $response->addMessage("The user was not created.");
    $response->send();
    exit;
}

// return the user details as a confirmation it was created successfully

$lastUserID = $writeDB->lastInsertId();

$returnData = array();
$returnData['user_id'] = $lastUserID;
$returnData['fullname'] = $fullname;
$returnData['username'] = $username;

$response = new Response();
$response->setHttpStatusCode(201);
$response->setSuccess(true);
$response->addMessage("The user account was created");
$response->setData($returnData);
$response->send();
exit;


} 
catch (PDOException $ex) {
    // write error to PHP error log
    error_log("connection error : " . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);  // Server Errror
    $response->setSuccess(false);
    $response->addMessage("There was an issue creating a user account.");
    $response->send();
    exit;
}