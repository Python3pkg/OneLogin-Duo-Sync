# Make API calls to the OneLogin Instance from OneLogin

import OneLogin

keys = {'client_id' : 'XXXXXXXXXXXXXXXXXX',
        'client_secret' : 'XXXXXXXXXXXXXXXXXX',
        'shard' : 'us'}

ol = OneLogin.OneLogin()
#token = OneLogin.Token(**ol)
t = OneLogin.Token(**keys)
t.get_token()

users = OneLogin.User(t)
print users.get_all_users()
