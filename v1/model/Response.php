<?php

class Response
{
    //create required properties for this API Response class.
    private $_success;
    private $_httpStatusCode;
    private $_messages = array();
    private $_data;
    private $_toCache = false; //this will be used to control if we cache a response.
    private $_responseData = array();

    // Getter Method:
    public function getProperty($name)
    {
        return $this->$name;
    }
    // Setter Methods:
    public function setSuccess($success)
    {
        $this->_success = $success;
    }
    public function setHttpStatusCode($httpStatusCode)
    {
        $this->_httpStatusCode = $httpStatusCode;
    }
    public function addMessage($message)
    {
        $this->_messages[] = $message;
    }
    public function setData($data)
    {
        $this->_data = $data;
    }
    public function toCache($toCache)
    {
        $this->_toCache = $toCache;
    }

    public function send(){

        // set the return data type to be JSON.
        header('Content-type: application/json;charset=utf-8');

        // set client to cache response for 60 seconds.
        if($this->_toCache) {
            header('Cache-control: max-age=60');
        } else {
        // explicitly set client to not cache response data
            header('Cache-control: no-cache, no-store');
        }
        
        // use php function to send the 500 response upon an error based upon properties values
        if(($this->_success !== false && $this->_success !== true) || !is_numeric($this->_httpStatusCode)) {
            http_response_code(500);
            $this->_responseData['statusCode']  = 500;
            $this->_responseData['success']     = false;
            $this->addMessage("Response Creation Error");
            $this->_responseData['messages'] = $this->_messages;
        } else {
            // this is the successful response:
            http_response_code($this->_httpStatusCode);
            $this->_responseData['statusCode']  = $this->_httpStatusCode;
            $this->_responseData['success']     = $this->_success;
            $this->_responseData['messages']    = $this->_messages;
            $this->_responseData['data']        = $this->_data;
        }

        echo json_encode($this->_responseData);

    }
}
