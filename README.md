This is for displaying vulnerabilities  

Create .env file from env-template  
Set up the application in Azure with the correct callback address to the public URL we will be running the app on. Store tenant, client in the env file.  Secret is a random secret suggest using something like openssl rand -base64 25
Run the db/mkdb.sh -a script
create CSVs of machine,username (email without @) and vulnerabilities per the schema in the db/mkdb.sh files  
import tables using e.g.  
 LOAD DATA INFILE '../vuln.csv' INTO TABLE vulnerabilities FIELDS ENCLOSED BY '"' TERMINATED BY ',' LINES TERMINATED BY '\n' IGNORE 1 ROWS  
run  

enjoy  
