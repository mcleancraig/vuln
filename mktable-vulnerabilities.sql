USE vulntest;
# DROP TABLE vulnerabilities;
CREATE TABLE vulnerabilities (
    plugin VARCHAR(255),
    ip VARCHAR(255),
    hostname VARCHAR(255),
    description TEXT(100000),
    remediation TEXT(10000),
    first_discovered VARCHAR(255),
    last_seen VARCHAR(255),
    patch_published VARCHAR(255)
);
