# Connect to OneLogin and mirror user/group orgs in Duo if the user is present.
#
# This script will build groups in Duo, but will not create any users.
# When a username is not present on Duo a note will be output to stdout, but
# the applicaiton will continue to run.
# To add a user to Duo the inline enrollment or other standard method will be
# used.

# This file requires the OneLogin.py script to run, as well as having'requests'
# library installed from pip.

# imports needed for the OneLogin API calls
import OneLogin
import json

# imports for the Duo AdminAPI calls
import duo_client

# We use this to create a faux limiter for making API calls
# and for disabling those annoying cert warnings for the OneLogin connection
import time
import logging

logging.captureWarnings(True)

# Constants for OneLogin and Duo API calls
ONE_LOGIN_CLIENT_ID = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
ONE_LOGIN_CLIENT_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

DUO_IKEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
DUO_SKEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
DUO_APIHOSTNAME = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


# Build OneLogin API key object
keys = {'client_id' : ONE_LOGIN_CLIENT_ID,
        'client_secret' : ONE_LOGIN_CLIENT_SECRET,
        'shard' : 'us'}


# Print out timestamp information in case we are logging this
print "=============================="
print "Starting OneLogin --> Duo Sync"
print time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime())
print "=============================="

# Generate the OneLogin token
ol = OneLogin.OneLogin()
t = OneLogin.Token(**keys)
t.get_token()

# get all of the users from OneLogin
users = OneLogin.User(t)
userJSON = users.get_all_users()

# get all of the groups from OneLogin
groups = OneLogin.Group(t)
groupsJSON = groups.get_all_groups()


# build the dictionary of group_id -> name
groupList = {}
for key in groupsJSON['data']:
    if key['id'] not in groupList:
        groupList[key['id']] = key['name']

# add users to their corresponding group names from OneLogin
userList = {}
for page in userJSON:
    for key in userJSON[page]['data']:
        if key['group_id'] not in userList:
            userList[ groupList[key['group_id']] ] = [ key['openid_name'] ]
        else:
            userList[ groupList[key['group_id']] ].append(key['openid_name'])


# authorization information for Duo API call
duoAPI = duo_client.Admin(
    ikey=DUO_IKEY,
    skey=DUO_SKEY,
    host=DUO_APIHOSTNAME
)

#Get list of groups from Duo
duoGroups = duoAPI.get_groups()

# build dictionary of username -> group_id
duoGroupList = {}
for group in duoGroups:
    if group['name'] not in duoGroupList:
        duoGroupList[group['name']] = group['group_id']


# Get all user info
duoUsers = duoAPI.get_users()

# build dictionary of username -> { user_id, groups }
duoUserList = {}
for user in duoUsers:
    if user['username'] not in duoUserList:
        groupList = []
        for group in user['groups']:
            groupList.append(group['name'])
        duoUserList[user['username']] = { 'user_id' : user['user_id'], 'groups' : groupList }

# Compare OneLogin with existing groups in Duo. Create as necessary.
for groupName in userList.keys():
    if groupName not in duoGroupList:
        print "creating " + str(groupName)
        time.sleep(3)
        duoAPI.create_group(groupName)

# Get the groups again now that we possibly made some new ones
duoGroups = duoAPI.get_groups()
duoGroupList = {}
for group in duoGroups:
    if group['name'] not in duoGroupList:
        duoGroupList[group['name']] = group['group_id']


# All users and groups accounted for. Assign users to group(s)
for groupName in userList:
    for user in userList[groupName]:
        if user in duoUserList.keys():
            if groupName not in duoUserList[user]['groups']:
                print "Adding user " + str(user) + " to group " + str(groupName)
                time.sleep(3)
                duoAPI.add_user_group(duoUserList[user]['user_id'], duoGroupList[groupName])
        else:
            print "User " + str(user) + " not in Duo"
