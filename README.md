# OneLogin-Duo-Sync
Syncing Script between OneLogin and Duo

## How to Use This Sync

Dependencies:
- Python 2.7+
- 'requests'
- 'duo_client'

For installing dependencies I recommend using pip ( https://pip.pypa.io/en/stable/installing/ ) then you can use `pip install requests` and `pip install duo_client` to install. This will install it system-wide. For localized installations you can refer to the documentation for each package on bulding locally.

- duo_client: https://github.com/duosecurity/duo_client_python
- requests: http://docs.python-requests.org/en/master/user/install/#pip-install-requests

After the dependencies are installed you will need to get the 2 API keys from OneLogin, and then fill in these two values in the old_sync.py file. The application will generate a session token each time it runs.

```
ONE_LOGIN_CLIENT_ID = 'YOUR_LOGIN_CLIENT_ID_GOES_HERE'
ONE_LOGIN_CLIENT_SECRET = 'YOUR_LOGIN_CLIENT_SECRET_GOES_HERE'
```

Then you will have to create a new AdminAPI application in Duo. This will give you the information for the following entries:

```
DUO_IKEY = "XXXXXXXXXXXXXXXXXX"
DUO_SKEY = "XXXXXXXXXXXXXXXXXX"
DUO_APIHOSTNAME = "XXXXXXXXXXXXXXXXXX"
```

Once that information has been supplied you should be able to run the tool to sync user's group membership from OneLogin over to Duo.

## Troubleshooting:
Since we are generating a session token for the sync, in cases where the sync can take inordinately long to complete the session token may need to be reissued. You can try to shorten the wait time in the various sleep() functions, or build a try/catch block around the script to handle the error.
