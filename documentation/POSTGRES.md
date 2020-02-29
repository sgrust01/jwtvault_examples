# Installations (on Ubuntu)

## Postgres

### Installations
* Install the db

`sudo apt install postgresql postgresql-contrib`

### Configurations
* Switch to postygres user

`sudo -i -u postgres`

* Create a admin

`createuser --interactive`

>Give a name preferably the id of the login user

>Select superuser

* Create a db

`createdb <username>`

>  use the same user

* Verify 

`sudo -i -u <user> psql`
                                      
* Change password

`ALTER USER <username> WITH PASSWORD 'password';`                                              


* Create app database

        $ createdb <dbname>

* Setup app database

        $ psql <dbname> < ./documentation/setup.sql