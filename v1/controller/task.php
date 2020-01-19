<?php

require_once("db.php");
require_once("../model/Response.php");
require_once("../model/Task.php");

// attempt to connect to database, using both read and write connections.
try {

    $writeDB = DB::connectWriteDB();
    $readDB = DB::connectReadDB();

}
catch (PDOException $ex) {

    // write error out to server logs into the PHP error logs
    error_log("connection error - " . $ex, 0);

    // create message reporting error to user
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Database connection error');
    $response->send();
    exit();
}

// check to see if the taskid is within url:
if (array_key_exists("taskid",$_GET)) {

    $taskid = $_GET['taskid'];

    //validate information captured:
        if($taskid == '' || !is_numeric($taskid)) {
            $response = new Response();
            $response->setHttpStatusCode(400); // client error
            $response->setSuccess(false);
            $response->addMessage('Task ID cannot be blank or must be numeric');
            $response->send();
            exit();
        }

if($_SERVER['REQUEST_METHOD'] === 'GET') {

    // query the database for the passed in ID, using prepared statement:

    try {

        $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as "deadline", completed FROM tbltasks WHERE id = :taskid');
        $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
        $query->execute();

        // validate that the id returned a row of data
        $rowCount = $query->rowCount();

        if($rowCount === 0) {
            $response = new Response();
            $response->setHttpStatusCode(404); // Not Found
            $response->setSuccess(false);
            $response->addMessage('Task ID cannot found');
            $response->send();
            exit();
        }

        // if the task does exist fetch the rows:
            while($row = $query->fetch(PDO::FETCH_ASSOC)){

                // create a task from the data returned from the database
                $task = new Task($row['id'], $row['title'],$row['description'], $row['deadline'], $row['completed']);
                $taskArray[] = $task->returnTaskAsArray();
            }
        $returnData = array();
        $returnData['rows_returned'] = $rowCount;
        $returnData['tasks'] = $taskArray;
        
        $response = new Response();
        $response->setHttpStatusCode(200); // Not Found
        $response->setSuccess(true);
        $response->toCache(true);
        $response->setData($returnData);
        $response->send();
        exit;

    } catch (PDOException $ex) {
        // write error out to server logs into the PHP error logs
    error_log("Database Query error - " . $ex, 0);

    // create message reporting error to user
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Failed to get task');
    $response->send();
    exit();
    }

    catch (TaskException $ex) {
        $response = new Response();
        $response->setHttpStatusCode(500); // Not Found
        $response->setSuccess(false);
        $response->addMessage($ex->getMessage());
        $response->send();
        exit();
    }
}

elseif($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    
    try {

        // QUery to attempt to delete the specific Row based upon the id for the task
        $query = $writeDB->prepare('DELETE FROM tbltasks WHERE id = :taskid');
        $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
        $query->execute();

        // Set variable for number of rows affected by query
        $rowCount = $query->rowCount();

        // validate that something was deleted from the database
        if($rowCount === 0) {
            $response = new Response();
            $response->setHttpStatusCode(404); // client data error
            $response->setSuccess(false);
            $response->addMessage('Task ID cannot be found to be removed');
            $response->send();
            exit();
        }
        $response = new Response();
        $response->setHttpStatusCode(200); // success
        $response->setSuccess(true);
        $response->addMessage('Task ID has been removed');
        $response->send();
        exit();


    } catch (PDOException $ex) {
        $response = new Response();
        $response->setHttpStatusCode(500); // server error
        $response->setSuccess(false);
        $response->addMessage('Delete query in database failed');
        $response->send();
        exit();
    }

}

    elseif($_SERVER['REQUEST_METHOD'] === 'PATCH') {
        
    }

    else {
        // create message reporting error to user
    $response = new Response();
    $response->setHttpStatusCode(405);  // request method not allowed.
    $response->setSuccess(false);
    $response->addMessage('Request method not allowed, try GET/DELETE/PATCH.');
    $response->send();
    exit();
    }
}

// method to obtain all tasks based upon completed status y or n
elseif (array_key_exists("completed", $_GET)){


    $completed = $_GET['completed'];

    if($completed !== 'Y' && $completed !== 'N'){
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Completed filter must be Y or N');
        $response->send();
        exit();
    }

    if($_SERVER['REQUEST_METHOD'] === 'GET') {

        // retreive all tasks that either complete = y or n
        try {
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks WHERE completed = :completed');
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->execute();

            $rowCount = $query->rowCount();

            $taskArray = array();

            while ($row = $query->fetch(PDO::FETCH_ASSOC)){

                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);

                $taskArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_resturned'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit;

        } catch(PDOException $ex) {
            error_log("Database Query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to get task from database');
            $response->send();
            exit();

        } catch(TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }
        
    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Can only accept GET requests.');
        $response->send();
        exit();
    }
}

// setup functionality to send 20 per page
elseif (array_key_exists("page", $_GET)) {

    if($_SERVER['REQUEST_METHOD'] === 'GET'){

        // obtain the page number from what is passed in
        $page = $_GET['page'];

        // ensure page value is acceptable
        if($page == '' || !is_numeric($page)){
            // report back connection not allowed
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage('Page number needs to be numeric');
            $response->send();
            exit();
        }

        $limitPerPage = 20;

        try {

            // obtain number of tasks from database query
            $query = $readDB->prepare('Select count(id) as totalNoOfTasks from tbltasks');
            $query->execute();

            $row = $query->fetch(PDO::FETCH_ASSOC);

            // ensure int being returend and assign to variable
            $taskCount = intval($row['totalNoOfTasks']);

            // calculate number of pages required, rounding results up:
            $numOfPages = ceil($taskCount / $limitPerPage);

            // deal with no results being returned
            if($numOfPages == 0) {
                $numOfPages = 1;
            }

            // provide error response if page requested which does not exist
            if($page > $numOfPages || $page == 0) {
                $response = new Response();
                $response->setHttpStatusCode(404);
                $response->setSuccess(false);
                $response->addMessage('That page does not exist');
                $response->send();
                exit();
            }

            // calculate which page and products to show
            $offset = ($page == 1 ? 0 : ($limitPerPage * ($page - 1)));

            // query to obtain tasks using the offest to limit / control the rows being returned:
            $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks limit :pglimit offset :offset');
            $query->bindParam(':pglimit', $limitPerPage, PDO::PARAM_INT);
            $query->bindParam(':offset', $offset, PDO::PARAM_INT);
            $query->execute();

            // count the number of rows
            $rowCount = $query->rowCount();

            $taskArray = array();

            while($row = $query->fetch(PDO::FETCH_ASSOC)) {

                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed'], );

                $taskArray[] = $task->returnTaskAsArray();
            }

            $returnData = array();
            $returnData['rows_returned'] = $rowCount;
            $returnData['total_rows'] = $taskCount;
            $returnData['total_pages'] = $numOfPages;
            ($page < $numOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false);
            ($page > 1 ? $returnData['has_prev_page'] = true : $returnData['has_prev_page'] = false);
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->toCache(true);
            $response->setData($returnData);
            $response->send();
            exit();

        } catch (PDOException $ex) {
            error_log("Database Query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to get tasks per page from database');
            $response->send();
            exit();

        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }

    } else {
        // report back connection not allowed
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Endpoint connection type not supported.');
        $response->send();
        exit();
    }
}

// method to obtain all tasks.
elseif(empty($_GET)) {

    // the endpoing for the api will be /tasks
    // first check endpoing is get or post
    if($_SERVER['REQUEST_METHOD'] === 'GET'){

        try {
                $query = $readDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks');
                $query->execute();
                
                // obtian a count of rows returned by Query.
                $rowCount = $query->rowCount();

                // create empty array, which will hold the returned tasks.
                $taskArray = array();

                // loop through the results
                while($row = $query->fetch(PDO::FETCH_ASSOC)){

                    // create new task object based upon row of returned results.
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed'], );

                    // feed in row results into the new created Array.
                    $taskArray[] = $task->returnTaskAsArray();

                }  // end of while loop

                // create a response and send task array data
                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;

                $response = new Response();
                $response->setHttpStatusCode(200);
                $response->setSuccess(true);
                $response->toCache(true);
                $response->setData($returnData);
                $response->send();
                exit();

        } catch (PDOException $ex) {
            error_log("Database Query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to get tasks from database');
            $response->send();
            exit();

        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }

    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST'){

        // function for the creation of a new task:
        try {

            // check that content type request header is JSON
            if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("content type header is not set to JSON.");
                $response->send();
                exit();
            }

            $rawPOSTData = file_get_contents('php://input');

            // *** ensure data is JSON type
            if(!$jsonData = json_decode($rawPOSTData)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage("content type is not JSON.");
                $response->send();
                exit();
            }

            if(!isset($jsonData->title) || !isset($jsonData->completed)) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                (!isset($jsonData->title) ? $response->addMessage("Title field is missing from JSON data.") : false);
                (!isset($jsonData->completed) ? $response->addMessage("Completed field is missing from JSON data.") : false);
                $response->send();
                exit();
            }

            // *** attempt to create a  new task based upon JSON data provided:
            $newTask = new Task(null, $jsonData->title, 
                                      (isset($jsonData->description) ? $jsonData->description : null),
                                      (isset($jsonData->deadline) ? $jsonData->deadline : null),
                                      $jsonData->completed 
                );

            // *** define variables based upon the created Task:
            $title          = $newTask->getTitle();
            $description    = $newTask->getDescription();
            $deadline       = $newTask->getDeadline();
            $completed      = $newTask->getCompleted();

            

            // *** Insert new task into database based upon variables:
            $query = $writeDB->prepare('INSERT INTO tbltasks (title, description, deadline, completed) VALUES (:title, :description, STR_TO_DATE(:deadline, \'%d/%m/%Y %H:%i\'), :completed)');
            
            $query->bindParam(':title', $title, PDO::PARAM_STR);
            $query->bindParam(':description', $description, PDO::PARAM_STR);
            $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
            $query->bindParam(':completed', $completed, PDO::PARAM_STR);
            $query->execute();

            

            // ** obtain a count of rows affected by query
            $rowCount = $query->rowCount();
            
            // *** Create error response if 0 records inserted:
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage('Failed to create task');
                $response->send();
                exit();
            }

            // ** as the task has inserted the record, we now respond the created record back.

            // ** obtain last iserted id from PDO
            $lastTaskID = $writeDB->lastInsertId();

            // *** query to select task from the last id variable
            $query = $writeDB->prepare('SELECT id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed FROM tbltasks where id = :taskID');
            $query->bindParam(':taskID' , $lastTaskID, PDO::PARAM_INT);
            $query->execute();

            $rowCount = $query->rowCount();

            // *** Create error response if 0 records returned:
            if($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(500);
                $response->setSuccess(false);
                $response->addMessage('Failed to obtain task record from database.');
                $response->send();
                exit();
            }

            // Create emty task array:
            $taskArray = array();
            
            while($row = $query->fetch(PDO::FETCH_ASSOC)) {

                $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed'],);

                $taskArray[] = $task->returnTaskAsArray();

            }

            $returnData = array();
            $returnData['row_count'] = $rowCount;
            $returnData['tasks'] = $taskArray;

            $response = new Response();
            $response->setHttpStatusCode(201);
            $response->setSuccess(true);
            $response->setData($returnData);
            $response->send();
            exit;

            
       } catch (PDOException $ex) {
            error_log("Database Query error - " . $ex, 0);
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('Failed to insert task into database, validate your supplied data');
            $response->send();
            exit();

        } catch (TaskException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage($ex->getMessage());
            $response->send();
            exit();
        }   


    } else {
        // report back connection not allowed
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Endpoint connection type not supported.');
        $response->send();
        exit();
    }

// standard response to feedback endpoint not found.
} else {

    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage('Endpoint not found.');
    $response->send();
    exit();

}


