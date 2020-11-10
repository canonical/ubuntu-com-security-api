# security.ubuntu.com
The API for CVEs and USNs data.

To check the API documentation go to https://security.ubuntu.com/docs

# Local development
The simplest way to run the API locally is using dotrun:

```
docker-compose up -d
dotrun
```

Once the server has started, you can visit http://0.0.0.0:8030 in your browser.

After you close the server with `<ctrl>+c` you should run `docker-compose down` to stop the database.

Documentation spec is available at http://0.0.0.0:8030/spec

Documentation is available at http://0.0.0.0:8030/docs