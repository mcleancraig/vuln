#!/bin/bash

bail() {
  echo "Bailing Out: $1"
  exit 1
}
 
# checks
[ ! -f ../.env ] && bail '../.env file not found'
source ../.env
mysql --version 2>&1>/dev/null || bail "cannot find mysql"
for var in DB_NAME DB_USER DB_PASSWORD DB_HOST ROOT_PASSWORD
do
  [ "x${!var}" = "x" ] && bail "$var not set"
done

# pp's
while getopts "fduva" o; do
  case "${o}" in 
    f)
      FORCE=true ;;
    d)
      D=true ;;
    v)
      V=true ;;
    u)
      U=true ;;
    a)
      V=true 
      D=true 
      U=true ;;
    *)
      usage ;;
  esac
done

usage() {
echo "Usage: $0 [-f] [ -d(atabase) | -u(sers table) | -v(ulns table) | -a(ll - defaul)"
}

createDb() {
echo "Creating Database"
[ "${FORCE}" != "true" ] && mysql -u root -h ${DB_HOST} -p${ROOT_PASSWORD} -e "use $DB_NAME" 2>&1 >/dev/null && bail "DB already exists - use -f to force"
mysql -u root -h ${DB_HOST} -p${ROOT_PASSWORD} << EOF 
 CREATE DATABASE IF NOT EXISTS ${DB_NAME};
 GRANT ALL PRIVILEGES on ${DB_NAME}.* to ${DB_USER}@'%' identified by "${DB_PASSWORD}" WITH GRANT OPTION;
EOF
[ $? -ne 0 ] && bail "DB Create failed!" ; echo "Success"
}

createUsers() {
echo "creating user table"
[ "${FORCE}" = "true" ] && mysql -u ${DB_USER} -h ${DB_HOST} -p${DB_PASSWORD} -e "USE ${DB_NAME}; DROP TABLE IF EXISTS users;" 
mysql -u ${DB_USER} -h ${DB_HOST} -p${DB_PASSWORD} << EOF 
USE ${DB_NAME};
CREATE TABLE IF NOT EXISTS users (
  host VARCHAR(255),
  user VARCHAR(255)
);
EOF
[ $? -ne 0 ] && bail "user table Create failed!" ; echo "Success"
}

createVulns() {
echo "creating vuln table"
[ "${FORCE}" = "true" ] && mysql -u ${DB_USER} -h ${DB_HOST} -p${DB_PASSWORD} -e "USE ${DB_NAME}; DROP TABLE IF EXISTS vulns;" 
mysql -u ${DB_USER} -h ${DB_HOST} -p${DB_PASSWORD} << EOF 
USE ${DB_NAME};
CREATE TABLE IF NOT EXISTS vulns (
    ip VARCHAR(255),
    hostname VARCHAR(255),
    plugin_id VARCHAR(255),
    plugin VARCHAR(255),
    owner VARCHAR(255),
    category_calc VARCHAR(255),
    exception VARCHAR(255),
    exc VARCHAR(255),
    cisa_ke VARCHAR(255),
    application VARCHAR(255),
    severity VARCHAR(255),
    patch_published VARCHAR(255),
    age INT(11),
    due_date VARCHAR(255),
    first_discovered VARCHAR(255),
    last_seen VARCHAR(255),
    details TEXT(100000),
    description TEXT(100000),
    synopsis TEXT(100000),
    remediation TEXT(10000),
    cve TEXT(1000),
    cpe TEXT(1000),
    category TEXT(100)  
);
EOF
}


[ "${D}" ] && createDb
[ "${U}" ] && createUsers
[ "${V}" ] && createVulns
