# security.ubuntu.com
The API for CVEs and USNs data.

To check the API documentation go to https://ubuntu.com/security/api/docs

# Local development
The simplest way to run the API locally is using dotrun:

``` bash
dotrun
```

It's quite likely you might also want to put some sample data in the database:

``` bash
# In another terminal window, while the DB is running
dotrun exec scripts/generate-sample-security-data.py
```

Once the server has started, you can visit http://0.0.0.0:8030 in your browser.

After you close the server with `<ctrl>+c` you should run `docker-compose down` to stop the database.

Documentation spec is available at http://0.0.0.0:8030/security/api/spec.json

Documentation is available at http://0.0.0.0:8030/security/api/docs

