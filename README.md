This is for displaying vulnerabilities. It's a simple node app which reads username (without @) from your login, looks up machine names in table `users` and then looks those machines up in table `vulns`

## In all cases
To run as an app or as a container, you'll need the env file. You can create this from the `env-template`

## Running the app
Set up the application in Azure with the correct callback address to the public URL we will be running the app on. Store tenant, client in the env file. Secret is a random secret suggest using something like `openssl rand -base64 25`
Run the `db/mkdb.sh -a` script
create CSVs of machine,username (email without @) and vulnerabilities per the schema in the `db/mkdb.sh` files  
import tables using e.g.  
 `LOAD DATA INFILE '../vuln.csv' INTO TABLE vulnerabilities FIELDS ENCLOSED BY '"' TERMINATED BY ',' LINES TERMINATED BY '\n' IGNORE 1 ROWS  `

## Building the container
edit the `docker-build.sh` file to match your needs - leave the environment as that's used by the app  
Run, and push to your repo of choice  
Use the included compose file to pull/run the container  

enjoy
