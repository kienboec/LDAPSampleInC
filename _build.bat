@cls
@TITLE C Sample LDAP

docker stop ldap-sample-instance
docker rm   ldap-sample-instance

docker build -t ldap-sample-container:latest .
docker run --rm -ti --privileged -v c:\repos\LDAPSampleInC\src\:/src:rw -p 6543:6543/tcp --name ldap-sample-instance ldap-sample-container
