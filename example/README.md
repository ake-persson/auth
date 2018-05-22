## Start server

```bash
./genkeys.sh
./example -server ldap:389 -base dc=example,dc=com -domain example
```

## Login, verify and denied access

```bash
curl -k -d '{ "username": "my_username", "password": "my_password" }' -X POST https://localhost:8080/login >token
curl -i -k --header "Authorization: Bearer $(cat token)" https://localhost:8080/verify
curl -i -k --header "Authorization: Bearer $(cat token)" https://localhost:8080/admin
```
