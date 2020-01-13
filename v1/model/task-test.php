<?php

require_once("task.php");

try {

    $task = new Task(1, "title here", "description here", "01/01/2020 12:00", "Y") ;

    // attempt to convert the response to JSON
    header('Content-type: application/json;chrset=UTF-8');

    echo json_encode($task->returnTaskAsArray());

} catch (TaskException $ex) {

    echo "Error : " . $ex->getMessage();
}