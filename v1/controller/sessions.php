<?php

require_once('db.php');
require_once('../model/Response.php');

// create a connection to the database:
try {

    $writeDB = DB::connectWriteDB();

}
catch (PDOException $ex) {
    // write error to PHP error log
    error_log("connection error : " . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);  // Server Errror
    $response->setSuccess(false);
    $response->addMessage("Database Connection Error.");
    $response->send();
    exit;
}

if(array_key_exists("sessionid", $_GET)) {

// Capture session information and access token
$sessionid = $_GET['sessionid'];

// ensure a session id is passed in and valid
if($sessionid === '' || !is_numeric($sessionid)){
    $response = new Response();
    $response->setHttpStatusCode(400);  // Client error
    $response->setSuccess(false);
    ($sessionid === '' ? $response->addMessage("Session ID cannot be blank.") : false );
    (!is_numeric($sessionid) ? $response->addMessage("Session ID has to be a number.") : false );
    $response->send();
    exit;
}

// obatin access token from header
if(!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1){
    $response = new Response();
    $response->setHttpStatusCode(401);  // un authorised error
    $response->setSuccess(false);
    (!isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage("Access is missing from header.") : false );
    (strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage("Access token is too short.") : false );
    $response->send();
    exit;
}

// store acces token into a variable:
$accesstoken = $_SERVER['HTTP_AUTHORIZATION'];

// *** session deletion (log out)
if($_SERVER['REQUEST_METHOD'] === 'DELETE'){

try {

    $query = $writeDB->prepare('DELETE FROM tblsessions WHERE id = :sessionid and accesstoken = :accesstoken ');
    $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);
    $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);

    $query->execute();

    $rowCount = $query->rowCount();

    

    if($rowCount === 0) {
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client Data Error
        $response->setSuccess(false);
        $response->addMessage("Failed out to log out this session using access token provided.");
        $response->send();
        exit;
    }

    // send a response to confirm log out
    $returnData = array();
    $returnData['session_id'] = intval($sessionid);

    $response = new Response();
    $response->setHttpStatusCode(200);  // Server Error
    $response->setSuccess(true);
    $response->addMessage("Successfully logged out the session.");
    $response->setData($returnData);
    $response->send();
    exit;

}
catch (PDOException $ex) {
    $response = new Response();
    $response->setHttpStatusCode(500);  // Server Error
    $response->setSuccess(false);
    $response->addMessage("There was an issue logging out, please retry.");
    $response->send();
    exit;
}


}

// *** refresh Access token with refresh token
elseif($_SERVER['REQUEST_METHOD'] === 'PATCH'){

    // check that content type is JSON
    if(!$_SERVER['CONTENT_TYPE'] === 'application/json'){
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client data Error
        $response->setSuccess(false);
        $response->addMessage("Content Type header not set to JSON.");
        $response->send();
        exit;
    }

    // obtain data and validate it is JSON format
    $rawPatchData = file_get_contents('php://input');

    if(!$jsonData = json_decode($rawPatchData)) {
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client data Error
        $response->setSuccess(false);
        $response->addMessage("Request body is not valid JSON.");
        $response->send();
        exit;
    }

    //ensure refresh token exists and obtain it
    if(!isset($jsonData->refresh_token) || strlen($jsonData->refresh_token) < 1){
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client data Error
        $response->setSuccess(false);
        (!isset($jsonData->refresh_token) ? $response->addMessage("Refresh Token is missing.") : false);
        (strlen($jsonData->refresh_token) ? $response->addMessage("Refresh Token cannot be blank.") : false);
        $response->send();
        exit;
    }

  
    try {
        
    // save passed in token into a variable:
    $refreshtoken = $jsonData->refresh_token;
        
    $query = $writeDB->prepare('SELECT tblsessions.id as sessionid, tblsessions.userid as userid, accesstoken, refreshtoken, useractive, loginattempts, accesstokenexpiry, refreshtokenexpiry 
                                    FROM tblsessions, tblusers 
                                    WHERE tblusers.id = tblsessions.userid
                                        AND tblsessions.id = :sessionid
                                        AND tblsessions.accesstoken = :accesstoken
                                        and tblsessions.refreshtoken = :refreshtoken');

    $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);                                        
    $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);                                        
    $query->bindParam(':refreshtoken', $refreshtoken, PDO::PARAM_STR);
   

    $query->execute();

   
    $rowCount = $query->rowCount();

    


    if($rowCount === 0 ){
        $response = new Response();
        $response->setHttpStatusCode(401);  // Authentication data Error
        $response->setSuccess(false);
        $response->addMessage("Access or Refresh token is incorrect for session id.");
        $response->send();
        exit;
    }

    $row = $query->fetch(PDO::FETCH_ASSOC);

    // save all columns returned from query into variables:
    $returned_sessionid             = $row['sessionid'];
    $returned_userid                = $row['userid'];
    $returned_accesstoken           = $row['accesstoken'];
    $returned_refreshtoken          = $row['refreshtoken'];
    $returned_useractive            = $row['useractive'];
    $returned_loginattempts         = $row['loginattempts'];
    $returned_accesstokenexpiry     = $row['accesstokenexpiry'];
    $returned_refreshtokenexpiry    = $row['refreshtokenexpiry'];

    if($returned_useractive  !== 'Y'){
        $response = new Response();
        $response->setHttpStatusCode(401);  // Unathorised error
        $response->setSuccess(false);
        $response->addMessage("User account is not active.");
        $response->send();
        exit;
    }
    if($returned_loginattempts >= 3 ){
        $response = new Response();
        $response->setHttpStatusCode(401);  // Unathorised error
        $response->setSuccess(false);
        $response->addMessage("User account is locked out.");
        $response->send();
        exit;
    }
    if(strtotime($returned_refreshtokenexpiry) < time()){
        $response = new Response();
        $response->setHttpStatusCode(401);  // Unathorised error
        $response->setSuccess(false);
        $response->addMessage("Refresh token has expired - please log in again.");
        $response->send();
        exit;
    }

    
      // generate access token
      // use 24 random bytes to generate a token then encode this as base64
      // suffix with unix time stamp to guarantee uniqueness (stale tokens)
      $accesstoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());

      // generate refresh token
      // use 24 random bytes to generate a refresh token then encode this as base64
      // suffix with unix time stamp to guarantee uniqueness (stale tokens)
      $refreshtoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());

      // set access token and refresh token expiry in seconds (access token 20 minute lifetime and refresh token 14 days lifetime)
      // send seconds rather than date/time as this is not affected by timezones
      $access_token_expiry_seconds = 1200;
      $refresh_token_expiry_seconds = 1209600;
      
      // create the query string to update the current session row in the sessions table and set the token and refresh token as well as their expiry dates and times
      $query = $writeDB->prepare('update tblsessions set accesstoken = :accesstoken, accesstokenexpiry = date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), refreshtoken = :refreshtoken, refreshtokenexpiry = date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND) where id = :sessionid and userid = :userid and accesstoken = :returnedaccesstoken and refreshtoken = :returnedrefreshtoken');
      // bind the user id
      $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
      // bind the session id
      $query->bindParam(':sessionid', $returned_sessionid, PDO::PARAM_INT);
      // bind the access token
      $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
      // bind the access token expiry date
      $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
      // bind the refresh token
      $query->bindParam(':refreshtoken', $refreshtoken, PDO::PARAM_STR);
      // bind the refresh token expiry date
      $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
      // bind the old access token for where clause as user could have multiple sessions
      $query->bindParam(':returnedaccesstoken', $returned_accesstoken, PDO::PARAM_STR);
      // bind the old refresh token for where clause as user could have multiple sessions
      $query->bindParam(':returnedrefreshtoken', $returned_refreshtoken, PDO::PARAM_STR);
      // run the query
      $query->execute();

      // get count of rows updated - should be 1
      $rowCount = $query->rowCount();

    if($rowCount === 0 ){
        $response = new Response();
        $response->setHttpStatusCode(401);  // client data Error
        $response->setSuccess(false);
        $response->addMessage("Access token could not be refreshed - please log in again.");
        $response->send();
        exit;
    }

    // returne data back to client confirming token refresh
    $returnData = array();
    $returnData['session_id']= $returned_sessionid;
    $returnData['access_token']= $accesstoken;
    $returnData['access_token_expiry']= $access_token_expiry_seconds;
    $returnData['refresh_token']= $refreshtoken;
    $returnData['refresh_token_expiry']= $refresh_token_expiry_seconds;

    $response = new Response();
        $response->setHttpStatusCode(200);  // Server data Error
        $response->setSuccess(true);
        $response->addMessage("There token was refreshed.");
        $response->setData($returnData);
        $response->send();
        exit;


    }
    catch (PDOException $ex) {
        $response = new Response();
        $response->setHttpStatusCode(500);  // Server data Error
        $response->setSuccess(false);
        $response->addMessage("There was an issue refreshing access token, please log in again.");
        $response->send();
        exit;
    }
    
}

// response back for other unsupported methods
else {
    $response = new Response();
    $response->setHttpStatusCode(405);  // Method not allowed
    $response->setSuccess(false);
    $response->addMessage("Request method not allowed.");
    $response->send();
    exit;
}

}
// *** Session Creation (log in)
elseif(empty($_GET)) {

    // ensure only post requests
    if($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = new Response();
        $response->setHttpStatusCode(405);  // Not found error
        $response->setSuccess(false);
        $response->addMessage("Request method not allowed.");
        $response->send();
        exit;
    }

    // inject a 1 second delay as a security measure
    sleep(1);

    // validate the content type is JSON
    if($_SERVER['CONTENT_TYPE'] !== 'application/json'){
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client error
        $response->setSuccess(false);
        $response->addMessage("Content type header not set to JSON.");
        $response->send();
        exit;
    }

    // obtain the content being supplied
    $rawPostData = file_get_contents('php://input');

    // validate the content is JSON format
    if(!$jsonData = json_decode($rawPostData)){
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client error
        $response->setSuccess(false);
        $response->addMessage("Request body is not valid JSON.");
        $response->send();
        exit;
    }

    // validate data for mandatory fields:
    if(!isset($jsonData->username) || !isset($jsonData->password)){
        $response = new Response();
        $response->setHttpStatusCode(400);  // Client error
        $response->setSuccess(false);
        (!isset($jsonData->username) ? $response->addMessage("Username not supplied.") : false);
        (!isset($jsonData->password) ? $response->addMessage("Password not supplied.") : false);
        $response->send();
        exit;
    }

    if(strlen($jsonData->username) < 1 || strlen($jsonData->username > 255) || 
       strlen($jsonData->password) < 1 || strlen($jsonData->password > 255)){
            $response = new Response();
            $response->setHttpStatusCode(400);  // Client error
            $response->setSuccess(false);
            (strlen($jsonData->username) < 1 || strlen($jsonData->username > 255)  ? $response->addMessage("Username to be between 1 and 255 characters.") : false);
            (strlen($jsonData->password) < 1 || strlen($jsonData->password > 255)  ? $response->addMessage("Password to be between 1 and 255 characters.") : false);
            $response->send();
            exit;
    }

    try {

        // setup variables with  username / password
        $username = $jsonData->username;
        $password = $jsonData->password;

        // query database passing in bind parameter for username
        $query = $writeDB->prepare('SELECT id, fullname, username, password, useractive, loginattempts from tblusers where username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();

        // count the number of rows being returned:
        $rowCount = $query->rowCount();

        // no user found from checking databse
        if($rowCount === 0){
            $response = new Response();
            $response->setHttpStatusCode(401);  // unauthorised error
            $response->setSuccess(false);
            $response->addMessage("Username or Password is incorrect.");
            $response->send();
            exit;
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);

        $returned_id                = $row['id'];
        $returned_fullname          = $row['fullname'];
        $returned_username          = $row['username'];
        $returned_password          = $row['password'];
        $returned_useractive        = $row['useractive'];
        $returned_loginattempts     = $row['loginattempts'];

        // check that the user is active
        if($returned_useractive !== 'Y') {
            $response = new Response();
            $response->setHttpStatusCode(401);  // unauthorised error
            $response->setSuccess(false);
            $response->addMessage("User account not active.");
            $response->send();
            exit;
        }

        // count numbr of login attempts and if more than 3 exit with message
        if ($returned_loginattempts >= 3){
            $response = new Response();
            $response->setHttpStatusCode(401);  // unauthorised error
            $response->setSuccess(false);
            $response->addMessage("User account is currently locked out.");
            $response->send();
            exit;
        }

        // check the hashed password:
        if(!password_verify($password, $returned_password)) {
            
            // update the login attempts, incrementing the number:
            $query = $writeDB->prepare('UPDATE tblusers SET loginattempts = loginattempts+1 WHERE id = :id');
            $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
            $query->execute();

            $response = new Response();
            $response->setHttpStatusCode(401);  // unauthorised error
            $response->setSuccess(false);
            $response->addMessage("Username or Password incorrect.");
            $response->send();
            exit;
        }

        // create the access token.
        $access_token = openssl_random_pseudo_bytes(24);

        // convert to hexidecimal
        $access_token = bin2hex($access_token);

        // encode as base 64
        $access_token = base64_encode($access_token);

        // time suffix to make sure it is really unique:
        $access_token = $access_token . time();

        // create the refresh token
        $refresh_token = openssl_random_pseudo_bytes(24);

        // convert to hexidecimal
        $refresh_token = bin2hex($refresh_token);

        // encode as base 64
        $refresh_token = base64_encode($refresh_token);

        // time suffix to make sure it is really unique:
        $refresh_token = $refresh_token . time();

        $access_token_expiry_seconds = 1200;

        $refresh_token_expiry_seconds = 1209600;  // 14 days
        
    }
    catch(PDOException $ex){
        $response = new Response();
        $response->setHttpStatusCode(500);  // Server error
        $response->setSuccess(false);
        $response->addMessage("There was an issue logging in.");
        $response->send();
        exit;
    }

    try {

// Successful Login, reset Login attempt to 0
        // create a database transaction, which can be rolled back if an issue occurs.
        $writeDB->beginTransaction();
        $query = $writeDB->prepare('UPDATE tblusers SET loginattempts = 0 where id = :id');
        $query->bindParam(':id' , $returned_id, PDO::PARAM_INT);
        $query->execute();

        

        // insert a new session into the database table
        $query = $writeDB->prepare('INSERT INTO tblsessions (userid, accesstoken, accesstokenexpiry, refreshtoken, refreshtokenexpiry)
                                                      VALUES (:userid, :accesstoken, date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), :refreshtoken, date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND) )');
        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->bindParam(':accesstoken', $access_token, PDO::PARAM_STR);
        $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
        $query->bindParam(':refreshtoken', $refresh_token, PDO::PARAM_STR);
        $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
        $query->execute();

        // obtain the last inserted id
        $lastSessionID = $writeDB->lastInsertId();

        // commit the transactions
        $writeDB->commit();

        // send the access and refresh token info back to the user:
        $returnData = array();
        $returnData['session_id'] = intval($lastSessionID);
        $returnData['access_token'] = $access_token;
        $returnData['access_token_expiries_in'] = $access_token_expiry_seconds;
        $returnData['refresh_token'] = $refresh_token;
        $returnData['refresh_token_expiries_in'] = $refresh_token_expiry_seconds;

        $response = new Response();
        $response->setHttpStatusCode(201);  // Created a session
        $response->setSuccess(true);
        $response->setData($returnData);
        $response->send();

    } catch (PDOException $ex) {
        $writeDB->rollBack();
        $response = new Response();
        $response->setHttpStatusCode(500);  // Not found error
        $response->setSuccess(false);
        $response->addMessage("There was an issue logging in, please try again.");
        $response->send();
        exit;
    }

}
else {
    // final position, if the type of request is not supported:
    $response = new Response();
    $response->setHttpStatusCode(404);  // Not found error
    $response->setSuccess(false);
    $response->addMessage("Endpoint not found.");
    $response->send();
    exit;
}
