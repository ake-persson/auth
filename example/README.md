## Start server:

```bash
./genkeys.sh
./example -server <server>:<port> -base <base> -domain <domain>
```

## Login and verify:

```bash
curl -k -d '{ "username": "<username>", "password": "<password>" }' -X POST https://localhost:8080/login >token
curl -i -k --header "Authorization: Bearer $(cat token)" https://localhost:8080/verify
```
