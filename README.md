This is for displaying vulnerabilities. It's a simple node app which reads username (without @) from your login, looks up machine names in table `users` and then looks those machines up in table `vulns`

## In all cases
To run as an app or as a container, you'll need to set the environment  

## Deploy as node app
Install MariaDB, and create the databases using the `db/mkdb.sh` script. You'll need a .env file for this (see `setup/setup-service.sh` for example contents)   
Run the `setup/setup-service.sh` command, copy your .env to `/etc/node-vuln/environment` file accordingly  
Import machine,username (without @), and vulnerabilities into the 'users' and 'vulns' table, following the schema in the `db/mkdb.sh` script. Example SQL is included in the `db/` folder  


## Building the container (needs fixing)
Edit the `docker-build.sh` file to match your needs - create the `.env` file (see `setup/setup-service.sh` for example contents)  
Run, and push to your repo of choice  
Use the included compose file to pull/run the container  

enjoy
