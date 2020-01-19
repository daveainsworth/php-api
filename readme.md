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