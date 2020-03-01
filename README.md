# Examples: JWTVault

> see: [GitHub](https://github.com/sgrust01/jwtvault.git)

### Pre-requisite

    $ git clone https://github.com/sgrust01/jwtvault_examples.git
    
### Overview

* Example 1: Hello World - CLI application
* Example 2: Actix Server - Web server
* Example 3: Custom Vault - Create vault with custom logic
* Example 4: Postgres - CLI for postgres backend
* Example 5: Webserver - Actix server with postgres backend
    
### Example 1: Hello World

    $ cargo run 

##### Notes
___

This example exhibits the core ability of the crate, to run as a library. This requires no runtime, runs on rust stable and has no unsafe code.

* Public session information 
    * Information send back to client
    * Not secure and can be viewed
    * Do not send sensitive data 
    
* Private session information
    * Information about client retained on server 
    * Secure information


### Example 2: Actix Server

    $ cargo run --bin actix

##### Notes
___
This crate can integrate with any web-server.  
 
 ##### Workflow 1: User login
 
    $ curl -X GET http://127.0.0.1:8080/login/john_doe/john

* auth - Represents the authentication_token
    * To be used for execute request for server
    * To be used for logout
    
* ref - Represents the refresh_token
    * To be used for renewing token
    
 ##### Workflow 2: User Request execution
 
    $ curl -X GET http://127.0.0.1:8080/execute/john_doe/<authentication_token>
    
* authentication_token
    * Replace with the auth value from login step

 ##### Workflow 3: Renew user authentication token
 
      $ curl -X GET http://127.0.0.1:8080/renew/john_doe/<refresh_token>
      
* refresh_token
    * Replace with the ref value from login step

 ##### Workflow 4: Logout user
 
      $ curl -X GET http://127.0.0.1:8080/logout/john_doe/<authentication_token>

* authentication_token
    * Replace with the auth value from renew step

### Example 3: Custom Vault

##### Notes
___
Exhibit the feature for saving custom information in memory. The library user need to implement only one method

    $ cargo run --bin custom
    
* `check_user_valid` is used to validate user requesting the access is the same user as on the token
* User on the token can be encrypted based on the application requirement
* User on token can then be decrypted securely on server and compared with plain user

### Example 4: Postgres

##### Pre-requisite
___ 

* You need postgres installed and should be able to connect via cli
* If you need help with setup see [here](documentation/POSTGRES.md)
* Setup guide is not suitable for production installation
* Please update the .env file with appropriate values

```shell script
  $ create demodb
  $ psql demodb < ./documentation/setup.sql
```
  

##### Notes
___

* Exhibit sample code that can be copied over for managing async connection to postgres db
* Any complain about PRIMARY_KEY violation should be ignore

___***PLEASE NOTE:***___: 
The input strings are not sanitized in the example. 
All data from/to the web needs to be sanitized to avoid SQL Injection.

    $ cargo run --bin postgres


### Example 5: Webserver

##### Pre-requisite
___ 

* You need postgres installed and should be able to connect via cli
* If you need help with setup see [here](documentation/POSTGRES.md)
* Setup guide is not suitable for production installation
* Please update the .env file with appropriate values

```shell script
  $ create demodb
  $ psql demodb < ./documentation/setup.sql
```
  

##### Notes
___

* Exhibit sample code that can be copied over for hosting [actix](https://github.com/actix/actix) web-server 
with integration with [postgres](https://github.com/sfackler/rust-postgres)

___***PLEASE NOTE:***___: 
The input strings are not sanitized in the example. 
All data from/to the web needs to be sanitized to avoid SQL Injection.

    $ cargo run --bin postgres

##### Workflow 1: User signup
 
    $ curl -X GET http://127.0.0.1:8080/signup/john_doe/john

* user identifier is returned upon successful sign-up
* <user_id> needs to be replaced on all subsequent request

 ##### Workflow 2: User login
 
    $ curl -X GET http://127.0.0.1:8080/login/<user_id>/john

* auth - Represents the authentication_token
    * To be used for execute request for server
    * To be used for logout
    
* ref - Represents the refresh_token
    * To be used for renewing token
    
 ##### Workflow 3: User Request execution
 
    $ curl -X GET http://127.0.0.1:8080/execute/<user_id>/<authentication_token>
    
* authentication_token
    * Replace with the auth value from login step

 ##### Workflow 4: Renew user authentication token
 
      $ curl -X GET http://127.0.0.1:8080/renew/<user_id>/<refresh_token>
      
* refresh_token
    * Replace with the ref value from login step

 ##### Workflow 5: Logout user
 
      $ curl -X GET http://127.0.0.1:8080/logout/<user_id>/<authentication_token>

* authentication_token
    * Replace with the auth value from renew step
        