# Python iRODS API 

This project leverages iRODS `icommands` and Python client API to expose basic command line tools for manipulating the relationships between resources, users and groups. Ultimately, access verification will be added, but is not included in this preliminary version. If this interface is used exclusively, however, proper security verification is present.

## Command Line Tools

* `add_to_group       group_name user_name`
* `remove_from_group  group_name user_name`
* `share_with_user    path       user_name`
* `unshare_with_user  path       user_name`
* `share_with_group   path       group_name`
* `unshare_with_group path       group_name`

### Notes

* All command line utilities assume admin privileges at this time.
* The `resource`, `user`, and `group` arguments are all strings i.e. a path, user name, or group name respectively.
* Each is a basic wrapper for the API call


## Python API

* `share_with_user    (sess, resource, user)`
* `unshare_with_user  (sess, resource, user)`
* `share_with_group   (sess, resource, group)`
* `unshare_with_group (sess, resource, group)`
* `add_to_group       (group, user)`
* `remove_from_group  (group, user)`

### Notes

* For those calls which require a session, use:
  ```python
  from irods.session import iRODSSession
  sess = iRODSSession(host='localhost', port=1247, user='[user]', password='[password]', zone='tempZone')
  ```
* The `resource`, `user`, and `group` arguments are all strings i.e. a path, user name, or group name respectively.
