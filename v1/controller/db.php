<?php

class DB {

    private static $writeDBConnection;
    private static $writeHost       = 'localhost';
    private static $writeUsername   = 'root';
    private static $writePassword   = '';
    private static $readDBConnection;

    public static function connectWriteDB() {
        // test to see if a connection has already been created, if not create one.
        if(self::$writeDBConnection === null){

            self::$writeDBConnection = new PDO('mysql:host=localhost;dbname=tasksdb;charset=utf8','root','');
            self::$writeDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$writeDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
          //  echo "Write database connection successful <br>";
        }

        return self::$writeDBConnection;
    }

    public static function connectReadDB() {
        // test to see if a connection has already been created, if not create one.
        if(self::$readDBConnection === null){

            self::$readDBConnection = new PDO('mysql:host=localhost;dbname=tasksdb;charset=utf8','root','');
            self::$readDBConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$readDBConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
          //  echo "Read database connection successful <br>";
        }

        return self::$readDBConnection;
    }




}


?>