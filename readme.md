// *** PHP API Training Course *** //

Training course for the creation and data connectivity to an API Service using PHP code:

Requirements:

XAMPP
Code editor - Visual Code
Postman - API integration tool.

URL:
https://www.udemy.com/course/create-a-rest-api-using-basic-php-with-token-authentication/

Within .htaccess php error display is switched on, this is to be turned off on production environments.

Json encode documentation page:
https://www.php.net/manual/en/function.json-encode.php.


htaccess structure:

RewriteEngine on
// dont rewrite if it is a folder:
RewriteCond %{REQUEST_FILENAME} !-d
//dont rewrite if it is a file:
RewriteCond %{REQUEST-FILENAME} !-f

// the url to start with tasks tehn have a numeric number, the L confirms this is the last rule.
RewriteRule ^tasks/([0-9]+)$ controller/task.php?taskid=$1 [L]

Structure for postman:
-- get a specific task
localhost/php-api/v1/tasks/3

-- get all completed tasks:
localhost/php-api/v1/tasks/complete

-- get all tasks:
localhost/php-api/v1/tasks

-- POST a new task:

localhost/php-api/v1/tasks  -- select POST, then Body, ensure JSON data is selected, then add:

{
	"title":"New title for post test",
	"description":"this is the description",
    "completed":"N",
    "deadline":"19/01/2020 20:26"
}

// *** Users ***
To Create a new User:

localhost/php-api/v1/users -- select Post then body ensure JSON data is selected:

Structure for JSON request:
{
    "fullname":"First Last name",
    "username":"enter username",
    "password":"enter a password"
}

// *** Sessions ***
The following api endpoints are available for the Session endpoint:

/sesssions (POST) - to create a new session or log in.

/sesssions/3 (DELETE) - to log out a session/user using the id (3)
add into Header:

Authorization -- Access token

/sessions/3 (PATCH) - to refresh a session access token
add into Header:

Authorization -- access token
body:
{
	"refresh_token":"OGY5MmYyODk5OGI3ZDEyY2Q5MDVjMzI4MjA5ZmY1YWU3ZjQ5NDJlNmI3ZGIwYmFl1580056756"
}