"""
The HSAccess library implements access control logic for scientific data sharing. It includes

1. user registration and privilege handling

2. group creation and management

3. resource registration and access control. 

"""
__author__ = 'Alva Couch'


import psycopg2
import psycopg2.extras
import uuid
from pprint import pprint


##################################################################
# assertion logic for filesystem protection model
# This code implements a filesystem protection model.
# It is in essence a data model; the routines herein are
# get and put methods for various kinds of data.
# The key to the interface is an idempotent assertion model
# in which repeating an assertion has no effect.
# Assertions are facts about the protection of resources.
# An assertion is either made true, or an exception is raised
# indicating why it cannot be made true.
##################################################################
# to be done:
# deep logic for ownership: do not allow the last owner to disown
# - for groups
# - for resources
# turn off privileges for
# - inactive groups
# - inactive users
# invite/accept logic for groups
# access control for groups: don't allow unauthorized people to ls
# rationalize group membership: one database rather than two
##################################################################

# exception class specifically for access control exceptions


class HSAException(Exception):
    """
    Exception class for HSAccess class: documents prohibited actions according to HSAccess engine logic
    """
    def __init__(self, value):
        """
        Sets the exception value to a given string. 
        """
        self.value = value

    def __str__(self):
        return repr(self.value)

# class encapsulates all access control actions


class HSAccess:
    """
    Access control class for HydroShare Resources, Groups
    """
    _PRIVILEGE_NONE = 100          # code that no privilege is asserted
    _PRIVILEGE_OWN = 1             # owner of thing
    _PRIVILEGE_RW = 2              # can read and write thing
    _PRIVILEGE_RO = 3              # can read thing
    _PRIVILEGE_NS = 4              # can read but not share with others

    def __init__(self, irods_user, irods_password,
                 db_database, db_user, db_password, db_host, db_port):
        try:
            self._irods_user = irods_user
            # print 'irods_user is ', irods_user
            # could authenticate against irods here
            self._conn = None
            self._cur = None
            self._conn = psycopg2.connect(database=db_database, user=db_user, password=db_password,
                                          host=db_host, port=db_port)
            self._cur = self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except:
            raise HSAException("unable to connect to the database")
        self._user_id = self._get_user_id_from_login(irods_user)
        self._user_uuid = self._get_user_uuid_from_login(irods_user)

    def __del__(self):
        if self._conn is not None:
            self._conn.close()

    ###########################################################
    # user handling
    ###########################################################

    ###########################################################
    # fetch a list of all user logins
    # CLI: hs_users
    ###########################################################

    def _get_user_logins(self):
        """
        PRIVATE: Get a list of all registered user logins

        :return: list: of login names

        Gets a list of user login names. These are used internally as unique 
        identifiers but not accepted as command parameters. 
        """
        self._cur.execute("SELECT user_login FROM users")
        result = []
        rows = self._cur.fetchall()
        for row in rows:
            result += [row['user_login']]
        return result

    ###########################################################
    # fetch a list of all user metadata
    # CLI: hs_users
    ###########################################################
    def get_users(self):
        """
        Get the registered user list

        :return: list of user metadata dictionaries

        Return format is a list of dictionaries of the form::

            {
            'login': *user_login*,
            'uuid': *user uuid*,
            'name': *user name*,
            'active': *true if user is active*,
            'admin':  *true if user is admin* 
            }
        
        These entries can be edited and used as input to 'assert_user_metadata'. 
        """
        self._cur.execute("SELECT user_uuid, user_login, user_name, user_active, user_admin FROM users")
        result = []
        rows = self._cur.fetchall()
        for row in rows:
            result += [
                {
                    'login': row['user_login'],
                    'uuid': row['user_uuid'],
                    'name': row['user_name'],
                    'active': row['user_active'],
                    'admin': row['user_admin']
                }
            ]
        return result

    def get_user_metadata(self, user_uuid=None):
        """
        Get metadata for a user as a dict record

        :type user_uuid: str
        :param user_uuid: uuid of user for which to fetch metadata; If None, then return data on current user. 
        :return: Dict of metadata for the login specified

        This gives more complete information than 'get_users', including the date of user creation. 
        The extra data is not utilize in 'assert_user_metadata'. 
        """
        if user_uuid is None: 
            user_uuid = self._user_uuid
        self._cur.execute("""select u.user_login, u.user_uuid, u.user_name, u.user_active, u.user_admin,
          a.user_login as user_assertion_login, a.user_uuid as user_assertion_uuid, u.assertion_time
          from users u left join users a on u.assertion_user_id = a.user_id
          where u.user_uuid=%s""", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self._cur.rowcount > 0:
            row = self._cur.fetchone()
            return {'uuid':  row['user_uuid'],
                    'login': row['user_login'],
                    'name': row['user_name'],
                    'active': row['user_active'],
                    'admin': row['user_admin'],
                    'asserting_login': row['user_assertion_login'],
                    'asserting_uuid': row['user_assertion_uuid'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such user uuid " + user_uuid)

    def assert_user_metadata(self, metadata):
        """
        Assert changes in user metadata

        :type metadata: dict<str, str> 
        :param metadata: a metadata record returned by get_user_metadata
        :return:

        Permissible assertions are those permissible to the currently logged-in user. 
        """
        user_uuid = metadata['uuid']
        if not self.user_exists(user_uuid):
            raise HSAException("user does not exist")
        if user_uuid != self._user_uuid and not self.user_is_admin(self._user_uuid):
            raise HSAException("Cannot assert metadata for user other than self: operation requires privilege")
        if metadata['admin'] and not self.user_is_admin():
            raise HSAException("cannot raise non-admin to admin without admin privilege")
        if not metadata['active'] and not self.user_is_admin():
            raise HSAException("only administrative users can deactivate a user")
        self.assert_user(metadata['login'], metadata['name'],
                         metadata['active'], metadata['admin'], metadata['uuid'])

    # get a specific login id for use as an entity id for recording actions
    def _get_user_id_from_login(self, login):
        """
        PRIVATE: get user database id from login name

        :type login: str
        :param login: string login name
        :return: integer user id
        """
        self._cur.execute("select user_id from users where user_login=%s", (login,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_id']
        else:
            raise HSAException("User login '" + login + "' does not exist")

    # get a specific login id for use as an entity id for recording actions
    def _get_user_id_from_uuid(self, user_uuid=None):
        """
        PRIVATE: get user database id from user uuid

        :type user_uuid: str
        :param user_uuid: uuid of user; omit to report on current user 
        :return: int: user id

        The return value of this function is used as the internal key in the 
        access control database, but never, ever exposed to users. It is 
        an integer for speed of joins. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("select user_id from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_id']
        else:
            raise HSAException("User uuid '" + user_uuid + "' does not exist")

    # get a specific login for use as a logging aid
    def _get_user_login_from_uuid(self, user_uuid=None):
        """
        PRIVATE: get user login name from user uuid e

        :type user_uuid: str
        :param user_uuid: uuid of user; omit to report on current user 
        :return: str: user login

        This returns the login name for a given user uuid. This is currently an iRODS login and has no 
        meaning in the system. It is used as a last resort in 'assert_user' to insure that we do not 
        create users with identical login names, but is otherwise ignored. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("select user_login from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_login']
        else:
            raise HSAException("User uuid '" + user_uuid + "' does not exist")

    # get a specific login uuid for use in requesting actions
    def _get_user_uuid_from_login(self, login):
        """
        PRIVATE: get user database id from login name

        :type login: str
        :param login: string login name
        :return: str: user uuid

        This returns the user uuid from the login name. While this works reliably 
        because login names are unique, this is only used to construct test cases. 
        """
        self._cur.execute("select user_uuid from users where user_login=%s", (login,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_uuid']
        else:
            raise HSAException("User login '" + login + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def user_exists(self, user_uuid=None):
        """
        Determine whether a login name is registered in the HSAccess database

        :type user_uuid: str
        :param user_uuid: uuid of user; omit to report on current user 
        :return: bool: True if user exists

        This checks a uuid and returns True if it exists. This is used to avoid 
        unintentional exceptions from use of a non-existent uuid. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("select user_id from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    # test whether a user login has administrative privileges
    def user_is_admin(self, user_uuid=None):
        """
        Determine whether a user identified by uuid has admin privileges

        :type user_uuid: str
        :param user_uuid: uuid of user; omit to report on current user 
        :return: bool

        This reports whether the given user has administrative privileges. 
        Administrative users can, for example: 

        1. register new users with 'assert_user'

        2. impersonate a given user and perform selected operations by proxy for the user. 

        """
        if user_uuid is None:
            user_uuid = self._user_uuid

        self._cur.execute("select user_admin from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            if self._cur.fetchone()['user_admin']:
                return True
            else:
                return False
        else:
            raise HSAException("user uuid '" + user_uuid + "' does not exist")

    # test whether a user login is entitled to make changes
    def user_is_active(self, user_uuid=None):
        """
        Determine whether a user uuid is an active user

        :type user_uuid: str
        :param user_uuid: uuid of user; omit to report on current user 
        :return: bool

        This reports whether a given user is active. Inactive users cannot login or access anything, 
        but their privileges and owned documents are kept intact. It is legal for a resource or group 
        to be owned by an inactive user, and groups and resources originally created by an inactive user 
        continue to be available to others. Whether a group is active is independent of whether its 
        owner is active. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("select user_active from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            if self._cur.fetchone()['user_active']:
                return True
            else:
                return False
        else:
            raise HSAException("user uuid '" + user_uuid + "' does not exist")

    # this is a no-frills assert of a user record without object use
    # CLI: this will normally be done by django. But we need a debugging command
    # 'hs_register_user' for our own use.
    def assert_user(self, user_login, user_name,  user_active=True, user_admin=False, user_uuid=None):
        """
        Register or update the registration of a user

        :type user_login: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool
        :type user_uuid: str
        :param user_login: user login name
        :param user_name: str: user print name
        :param user_active: bool: whether user is active
        :param user_admin: bool: whether user is an admin
        :param user_uuid: uuid to register or update; leave out to register a new user 
        :return:

        This is used in two forms: 

        1. with user_uuid absent, it attempts to register a new user. Note if the specified 
           login is found, that is utilized as a unique key and that record is updated instead. 

        2. with user_uuid present, it updates the metadata record for that user. 

        The access control model disallows certain changes to this record: 

        1. Changes to whether a user is active or an administrator can only be made by an administrative user. 

        2. Regular users can only change their print names (user_name).

        :todo: check logic for what a user can change.
        """
        if not self.user_exists(self._user_uuid):
            raise HSAException("Asserting uuid '" + self._user_uuid + "' does not exist")
        if not (self.user_is_active(self._user_uuid)):
            raise HSAException("Asserting uuid '" + self._user_uuid + "' is inactive")
        if not (self.user_is_admin(self._user_uuid)):
            raise HSAException("User uuid '" + self._user_uuid
                               + "' is not an administrator; operation requires privilege")

        if user_uuid is None:
            # try the other keys to see if it is defined
            try:
                user_uuid = self._get_user_uuid_from_login(user_login)
            except HSAException:
                user_uuid = uuid.uuid4().hex
        # print "resource uuid is", resource_uuid

        assert_id = self._get_user_id_from_uuid(self._user_uuid)

        if self.user_exists(user_uuid):
            self._assert_user_update(assert_id, user_uuid, user_login, user_name, user_active, user_admin)
        else:
            self._assert_user_add(assert_id, user_uuid, user_login, user_name, user_active, user_admin)

        return user_uuid

    def _assert_user_add(self, assertion_user_id, user_uuid, user_login, user_name, user_active=True, user_admin=False):
        """
        PRIVATE: add a new user record 

        :type assertion_user_id: int
        :type user_uuid: str
        :type user_login: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool
        :param assertion_user_id: internal user id of user adding the login name
        :param user_uuid: uuid of user to add
        :param user_login: user login string: must be unique
        :param user_name: user print name
        :param user_active: whether user is active
        :param user_admin: whether user is an administrator
        :return:

        Add a new previously non-existent user record to the registered users. user_uuid and user_login 
        must both be independently unique. 

        This routine is not subject to access control restrictions. 
        """
        self._cur.execute("""insert into users values (DEFAULT, %s, %s, %s, %s, %s, %s, DEFAULT)""",
                          (user_uuid, user_login, user_name, user_active, user_admin, assertion_user_id))
        self._conn.commit()

    # this is the general idea but can be cleaned up with conditional code.
    def _assert_user_update(self, assertion_user_id, user_uuid, user_login, user_name, user_active=True,
                            user_admin=False):
        """
        PRIVATE: update an existing user record

        :type user_login: str
        :type assertion_user_id: int
        :type user_uuid: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool
        :param user_login: login of user to update (primary key)
        :param assertion_user_id: user adding the login name
        :param user_uuid: user uuid string: must be unique
        :param user_name: user print name
        :param user_active: whether user is active
        :param user_admin: whether user is an administrator
        :return:

        Update an existing user record in the registered users table. user_uuid and user_login must 
        remain independently unique. 

        This routine is not subject to access control restrictions. 
        """
        self._cur.execute("""update users set user_login =%s, user_name=%s, user_active=%s, user_admin=%s,
                          assertion_user_id=%s, assertion_time=CURRENT_TIMESTAMP
                          where user_uuid=%s""",
                          (user_login, user_name, user_active, user_admin, assertion_user_id, user_uuid))
        self._conn.commit()

    ###########################################################
    # user group handling
    ###########################################################
    # should it be possible for a group to go inactive?
    # answer: refactored for group_active in records; 
    # if group is not active, protections for that group are 
    # downgraded to ro from whatever they were before. 
    ###########################################################

    # fetch a list of all group uuids
    def get_groups(self):
        """
        Get information on all existing groups

        :return: a list of all group uuids and names , as dictionary objects

        This returns a list of elements of the form::

            { 'uuid': *uuid of group*, 'name': *name of group* } 

        sorted in order of group name. Group names do not have to be unique. 

        The 'uuid' element can be used as input to 'get_group_metadata' to learn more about the group. 

        Note: this method is not currently subject to access control. The access control document does
        not limit group visibility; just membership. 
        """
        self._cur.execute("SELECT group_uuid, group_name FROM groups ORDER BY group_name, group_uuid")
        result = []
        rows = self._cur.fetchall()
        for row in rows:
            result += [{'uuid': row['group_uuid'], 'name': row['group_name']}]
        return result

    def get_groups_for_user(self, user_uuid=None):
        """
        Get a list of groups relevant to a specific user

        :param user_uuid: the user to report on; omit to report on current user. 
        :return: list of dicts describing groups

        This returns a list of groups in the following format::  
            { 'name': *name of group*, 'uuid': *uuid of group* } ]
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("""select g.group_uuid, g.group_name, x.privilege_code
                          from groups g
                          left join user_membership_in_group m on m.group_id=g.group_id
                          left join users u on u.user_id = m.user_id
                          left join user_group_privilege p on p.user_id=u.user_id and p.group_id=g.group_id
                          left join privileges x on x.privilege_id=p.privilege_id
                          where u.user_uuid=%s
                          order by g.group_name, g.group_uuid""",
                          (user_uuid,))
        rows = self._cur.fetchall()
        result = []
        for row in rows:
            result += [{'uuid': row['group_uuid'], 'name': row['group_name'], 'code': row['privilege_code']}]
        return result

    def get_group_metadata(self, group_uuid):
        """
        Get metadata for a group as a dict record

        :param group_uuid: uuid of group 
        :return: dict of group metadata 

        This returns a dictionary record with the structure::

            {
                'uuid': *uuid of group*,
                'name': *name of group*,
                'active': *whether group is active*, 
                'asserting_login': *login of user who last changed metadata*, 
                'asserting_uuid': *uuid of user who last changed metadata*, 
                'assertion_time': *time of last metadata change*
            } 

        This value can be edited and used as an argument to 'assert_group_metadata'. 
        """
        self._cur.execute("""select g.group_uuid, g.group_name, g.group_active,
          a.user_login as user_assertion_login, a.user_uuid as user_assertion_uuid, g.assertion_time
          from groups g left join users a on g.assertion_user_id = a.user_id
          where g.group_uuid=%s""", (group_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group uuid")
        if self._cur.rowcount > 0:
            row = self._cur.fetchone()
            return {'uuid':  row['group_uuid'],
                    'name': row['group_name'],
                    'active': row['group_active'],
                    'asserting_login': row['user_assertion_login'],
                    'asserting_uuid': row['user_assertion_uuid'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such group " + group_uuid)

    def assert_group_metadata(self, metadata):
        """
        Assert changes in user metadata

        :param metadata: a metadata record as returned by get_group_metadata
        :return:

        This asserts changes in group metadata subject to the restrictions in 'assert_group'.  
        It can be used to create new groups as well as to edit group metadata. 
        """
        user_uuid = self._user_uuid
        self.assert_group(metadata['name'], metadata['active'], group_uuid=metadata['uuid'], user_uuid=user_uuid)

    # get a specific login id for use as an entity id for recording actions
    def _get_group_id_from_uuid(self, group_uuid):
        """
        PRIVATE: translate from group object identifier to database id

        :type group_uuid: str
        :param group_uuid: group object identifier
        :return: int: group_id in HSAccess database

        This returns the private identifier for a group that is used internally as 
        a join target. This is an integer for speed. This identifier is never exposed
        to users or administrators of the system. 
        """
        self._cur.execute("select group_id from groups where group_uuid=%s", (group_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['group_id']
        else:
            raise HSAException("Group uuid '" + group_uuid + "' does not exist")

    # get a specific login id for use as an entity id for recording actions
    def _get_group_name_from_uuid(self, group_uuid):
        """
        PRIVATE: translate from group object identifier to database id

        :type group_uuid: str
        :param group_uuid: group object identifier
        :return: str: group name

        This returns the name of a group from its uuid. Group names are not generally unique and 
        cannot be used as keys from which to locate groups. 
        """
        self._cur.execute("select group_name from groups where group_uuid=%s", (group_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['group_name']
        else:
            raise HSAException("Group uuid '" + group_uuid + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def group_exists(self, group_uuid):
        """
        Determine whether group identifier (uuid) is registered

        :type group_uuid: str
        :param group_uuid: group object identifier
        :return: bool: whether group object identifier is registered

        This is used to avoid execution exceptions by ensuring that a group uuid 
        is valid before performing further actions. 
        """
        self._cur.execute("select group_id from groups where group_uuid=%s", (group_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group uuid")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    # this is a no-frills assert user without object use
    # CLI: hs_create_group and hs_modify_group
    def assert_group(self, group_name, group_active=True, group_uuid=None, user_uuid=None):
        """
        Register or update a group

        :type group_name: str
        :type group_active: bool
        :type group_uuid: str
        :type user_uuid: str
        :param group_name: str: name of group
        :param group_active: bool: whether group is active
        :param group_uuid: str: group identifier, if omitted or unset, then a new group_uuid is created and returned. 
        :param user_uuid: user identifier; omit to utilize current user. 
        :return: str: uuid of group just modified; created if necessary. 

        This creates a new group subject to several conventions: 

        1. if group_uuid is None, then a new group uuid is created.

        2. if user_uuid is not None and the current user has admin privilege,
           then the operation is undertaken on behalf of the stated user.

        This is also subject to access control limits: 

        1. Any regular user can create a group 

        2. After the group is created, a regular user can only change its name. 

        3. All other changes to a group require administrative privilege. 

        4. The group_uuid is set forever and cannot change. 

        :todo: ensure that regular users cannot change too much!
        """
        if not (self.user_exists(self._user_uuid)):
            raise HSAException("Asserting login '" + self._irods_user + "' does not exist")
        # requesting_user_id = self._get_user_id_from_uuid(self._user_uuid)
        if user_uuid is not None and user_uuid != self._user_uuid and not (self.user_is_admin()):
            raise HSAException("Asserting login '"+self._irods_user+"' does not have admin privilege")
        if user_uuid is None:
            user_uuid = self._user_uuid
        # requesting_user_id = self._get_user_id_from_uuid(user_uuid)
        if group_uuid is None:
            group_uuid = uuid.uuid4().hex

        assert_id = self._get_user_id_from_uuid(user_uuid)
        if self.group_exists(group_uuid):
            if self.user_is_admin(self._user_uuid) or self.group_is_owned(group_uuid):
                self._assert_group_update(assert_id, group_uuid, group_name, group_active)
            else:
                raise HSAException("Insufficient privilege to complete operation")
        else:
            # NEW GROUP:
            # 1) add new group to group list
            self._assert_group_add(assert_id, group_uuid, group_name, group_active)

            # 2) make the asserting user the owner
            # it is necessary to run around protections for this one step
            # because of a chicken-and-egg problem
            privilege_id = self._get_privilege_id_from_code('own')
            group_id = self._get_group_id_from_uuid(group_uuid)
            self._share_group_user_add(assert_id, assert_id, group_id, privilege_id)

            # 3) put the asserting user into the group as well.
            # since that person is now the owner, this is straightforward.
            # self._assert_user_in_group(group_uuid, self._user_uuid)
            # refactoring to remove duplication among membership and access
        return group_uuid

    def _assert_group_add(self, assertion_user_id, group_uuid, group_name, group_active):
        """
        PRIVATE: add a new group to the registry

        :type assertion_user_id: int
        :type group_uuid: str
        :type group_name: str
        :type group_active: bool
        :param assertion_user_id: internal id of requesting user
        :param group_uuid: group identifier
        :param group_name: name of group
        :param group_active: whether group is active. 
        :return:

        Notes: 

        1. This is not subject to access control. 

        2. An exception is raised if the group uuid already exists. 

        """
        self._cur.execute("""insert into groups values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (group_uuid, group_name, group_active, assertion_user_id))
        self._conn.commit()

    def _assert_group_update(self, assertion_user_id, group_uuid, group_name, group_active):
        """
        PRIVATE: update a group record in the registry

        :type assertion_user_id: int
        :type group_uuid: str
        :type group_name: str
        :type group_active: bool
        :param assertion_user_id: internal id of requesting user
        :param group_uuid: group identifier
        :param group_name: name of group
        :param group_active: group active or retired 
        :return:

        Notes: 

        1. This is not subject to access control. 

        2. An exception is raised if the group uuid does not exist. 


        """
        self._cur.execute("""update groups set group_name=%s,
                          group_active=%s,
                          assertion_user_id=%s,
                          assertion_time=CURRENT_TIMESTAMP
                          where group_uuid=%s""",
                          (group_name, group_active, assertion_user_id, group_uuid))
        self._conn.commit()

    # CLI: hs_delete_group
    # unsure whether this should be a possibility; 
    # consider deactivate_group instead. 
    def retract_group(self, group_uuid):
        """
        Delete a group and all membership information

        :type group_uuid: str
        :param group_uuid: uuid of group to delete
        :return:

        Retractions are handled via database cascade logic. This deletes all information about the 
        group, including every resource held with that group. 

        *Consider making a group inactive instead of using this routine.*

        Restrictions: 

        1. Only the owner of the group or an administrator can do this. 

        :todo: fix cascade logic in database so that this always works correctly. Currently 
               there is a band-aid fix that does the cascade in the application. 
        """
        # only an owner or administrator can retract a group
        if not self.user_is_admin(self._user_uuid) \
                and not self.group_is_owned(group_uuid, self._user_uuid):
            raise HSAException("cannot retract groups owned by other users")
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""delete from user_access_to_group where group_id=%s""", (group_id,))
        # user_membership_in_group is now a view
        # self._cur.execute("""delete from user_membership_in_group where group_id=%s""", (group_id,))
        self._cur.execute("""delete from groups where group_id=%s""", (group_id,))

    ###########################################################
    # resource handling
    ###########################################################

    def _get_resource_id_from_uuid(self, resource_uuid):
        """
        PRIVATE: get resource_id from resource digital identifier (uuid)

        :type resource_uuid: str
        :param resource_uuid:  resource object identifier
        :return: int: private resource_id in HSAccess database

        This returns the private and internal unique identifier of the resource object. 
        This id is never exposed to users. 

        Note: this method is not subject to access control. 
        """
        self._cur.execute("select resource_id from resources where resource_uuid=%s", (resource_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['resource_id']
        else:
            raise HSAException("Resource uuid '" + resource_uuid + "' does not exist")

    def _get_resource_uuid_from_path(self, resource_path):
        """
        PRIVATE: get resource_uuid from (unique) resource path

        :type resource_path: str
        :param resource_path: str: resource object path in iRODS
        :return: int: resource_uuid in HSAccess database

        Paths in iRODS are assumed to be unique. This does the same thing as '_get_resource_id_from_uuid' 
        but for paths rather than uuids. 

        Note: this method is not subject to access control. 
        """
        self._cur.execute("select resource_uuid from resources where resource_path=%s", (resource_path,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['resource_uuid']
        else:
            raise HSAException("Resource uuid '" + resource_path + "' does not exist")

    def resource_exists(self, resource_uuid):
        """
        Determine whether a resource is registered in the database

        :type resource_uuid: str
        :param resource_uuid: resource identifier
        :return: bool: whether resource is registered

        This determines whether a given resource uuid corresponds to an existing resource. 
        """
        self._cur.execute("select resource_id from resources where resource_uuid=%s", (resource_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    def resource_is_immutable(self, resource_uuid):
        """
        Whether resource is flagged as immutable

        :type resource_uuid: str
        :param resource_uuid:  resource identifier
        :return: bool: whether resource has been flagged as immutable

        If a resource is immutable: 

        1. All write access is denied by all users regardless of privilege. This includes
           resource deletion and any changes to any aspect of the resource. Even owners have no 
           privileges other than read over an immutable resource. 

        2. Only an administrative user can promote a resource from immutable to mutable. 
           Other users must instead copy the resource to a new location. 

        The spirit of the immutable flag is that the affected resource's landing page can then safely be 
        issued a data citation. 
        """
        # print "checking that " + login + " exists"
        self._cur.execute("select resource_immutable from resources where resource_uuid=%s", (resource_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            if self._cur.fetchone()['resource_immutable']:
                return True
            else:
                return False
        else:
            raise HSAException("resource uuid '" + resource_uuid + "' does not exist")

    def get_resource_metadata(self, resource_uuid):
        """
        Get metadata for a group as a dict record

        :type resource_uuid: str
        :param resource_uuid: group identifier for which to fetch metadata
        :return: dict

        This returns a dictionary item of the format::

            {
            'title': *title of resource*,
            'uuid': *uuid of resource*,
            'path': *path of resource*,
            'immutable': *whether resource is immutable*,
            'asserting_login': *login of user who made last change to metadata*,
            'asserting_uuid': *uuid of user who made last change to metadata*,
            'assertion_time': *time of last change to metadata*
            }

        The record returned from 'get_resource_metadata' is suitable for use in 
        'assert_resource_metadata' and may be used for things like cloning resources. 
        
        The 'asserting_uuid' is not used during 'assert_resource_metadata'; this is a record 
        of "who to blame" for the last change. 

        """
        self._cur.execute("""select r.resource_uuid, r.resource_path,
          r.resource_title, r.resource_immutable,
          a.user_login as user_assertion_login,
          a.user_uuid as user_assertion_uuid,
          r.assertion_time
          from resources r left join users a on r.assertion_user_id = a.user_id
          where r.resource_uuid=%s""", (resource_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            row = self._cur.fetchone()
            return {'title': row['resource_title'],
                    'uuid':  row['resource_uuid'],
                    'path': row['resource_path'],
                    'immutable': row['resource_immutable'],
                    'asserting_login': row['user_assertion_login'],
                    'asserting_uuid': row['user_assertion_uuid'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such resource " + resource_uuid)

    def assert_resource_metadata(self, metadata):
        """
        Assert changes in resource metadata

        :type metadata: dict
        :param metadata: a metadata record as returned by get_resource_metadata
        :return:
       
        This is a wrapper for 'assert_resource' that connects it to a return value 
        format from 'get_resource_metadata'. This can be used to edit resource
        fields incrementally. 

        """
        self.assert_resource(metadata['uuid'], metadata['path'], metadata['title'], metadata['immutable'])

    # a primitive resource instantiation without objects
    # CLI: currently this can only be done properly through django
    # but we need a debugging command "hs register path" for our own use

    def assert_resource(self, resource_path, resource_title, resource_immutable=False,
                        resource_uuid=None, user_uuid=None):
        """
        Add or modify a resource in the resource registry

        :type resource_path: str
        :type resource_title: str
        :type resource_immutable: str
        :type resource_uuid: str
        :type user_uuid: str
        :param resource_path: path to resource in iRODS  title
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :param resource_uuid: resource identifier
        :param user_uuid: user identifier of asserting user; omit to use current user. 
        :return: str: resource identifier used

        This routine creates or changes resource parameters.

        This is subject to several access control rules: 

        1. If resource_uuid is not None, it takes this parameter as the uuid of the resource.

        2. If resource_uuid is None, it first tries to locate the path in the resources table.
           Notwithstanding that, it creates a new resource uuid.

        Then it creates or updates a record and returns the resource uuid

        Regular users can: 

        1. Create a new resource. 

        2. Edit the title only of an existing resource. 
        
        Administrative users can: 

        1. Act as proxy for other users. 

        2. Edit any part of the resource registration. 

        If user_uuid is not None, then the operation is done on behalf of the stated user
        as an administrator. If admin privileges are not present in this case, 
        an exception is raised. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        if not (self.user_exists(user_uuid)):
            raise HSAException("Asserting uuid '" + user_uuid + "' does not exist")
        requesting_user_id = self._get_user_id_from_uuid(user_uuid)

        # check for admin privilege or user match
        if user_uuid != self._user_uuid and not (self.user_is_admin()):
            raise HSAException("Asserting login '"+self._irods_user+"' does not have admin privilege")

        if resource_uuid is None:
            # try the other keys to see if it is defined
            try:
                resource_uuid = self._get_resource_uuid_from_path(resource_path)
            except HSAException:
                resource_uuid = uuid.uuid4().hex
        # print "resource uuid is", resource_uuid
        if self.resource_exists(resource_uuid):
            if self.resource_is_immutable(resource_uuid):
                raise HSAException("permission denied: resource is marked as immutable")
            # only admin users or owners can change the resource name
            if self.user_is_admin(self._user_uuid) or self.resource_is_owned(resource_uuid):
                self._assert_resource_update(requesting_user_id, resource_uuid,
                                             resource_path, resource_title, resource_immutable)
            else:
                raise HSAException("Insufficient privileges to modify resource: must be owner or admin")
        else:
            # NEW RESOURCE
            # 1) put the resource into the registry
            self._assert_resource_add(requesting_user_id, resource_uuid,
                                      resource_path, resource_title, resource_immutable)
            # 2) make it owned by the asserting user
            # get the newly minted resource id
            resource_id = self._get_resource_id_from_uuid(resource_uuid)
            privilege_id = self._get_privilege_id_from_code('own')
            # This bypasses checks because this user created the resource.
            self._share_resource_user_add(requesting_user_id, requesting_user_id, resource_id, privilege_id)
            # add owner logic here
        return resource_uuid

    # subfunction: add a resource whose uuid (primary key) does not exist
    # this has no inherent protection and is used internally for some
    # initial creation tasks.
    def _assert_resource_add(self, requesting_user_id, resource_uuid,
                             resource_path, resource_title, resource_immutable=False):
        """
        PRIVATE: add a new resource to the registry

        :param requesting_user_id: user id of adding person
        :param resource_uuid: resource identifier
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return:

        This adds a new and previously non-existent resource to the resource registry. resource_uuid and 
        resource_path must be unique. If these are not unique, an exception is raised. 

        Note: this routine is not subject to access control restrictions. 
        """
        self._cur.execute("""insert into resources values (DEFAULT, %s, %s, %s, %s, %s, DEFAULT)""",
                          (resource_uuid, resource_path, resource_title, resource_immutable, requesting_user_id))
        self._conn.commit()

    # subfunction: update a resource whose uuid is known
    def _assert_resource_update(self, requesting_user_id, resource_uuid,
                                resource_path, resource_title, resource_immutable=False):
        """
        PRIVATE: add a new resource to the registry

        :type requesting_user_id: int
        :type resource_uuid: str
        :type resource_path: str
        :type resource_title: str
        :type resource_immutable: bool
        :param requesting_user_id: user id of adding person
        :param resource_uuid: resource identifier
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return:

        This updates an existing resource to the resource registry. resource_uuid and 
        resource_path must be unique and a record for resource_uuid must be present. 
        If these requirements are not met, an exception is raised. 

        Note: this routine is not subject to access control restrictions. 
        """
        self._cur.execute("""update resources set resource_path=%s, resource_title=%s, resource_immutable=%s,
                         assertion_user_id=%s, assertion_time=CURRENT_TIMESTAMP
                         where resource_uuid=%s""",
                          (resource_path, resource_title, resource_immutable, requesting_user_id, resource_uuid))
        self._conn.commit()

    ###########################################################
    # user privilege over resources
    ###########################################################
    def _get_privilege_id_from_code(self, code):
        """
        PRIVATE: translate from privilege code to database id

        :type code: str: 
        :param code: str: code for privilege level: own, rw, ro, ns
        :return: int: privilege_id in database system

        This routine translates a privilege code into an integer. Current privilege codes include: 

            own
                owner of resource (1) 

            rw
                read-write (with sharing privilege) (2)

            ro 
                read-only (with sharing privilege) (3) 

            ns
                read-only without privilege to share. (4)

        The privilege level for an object is a minimum of all the privilege levels assigned by different people.

        For example, if 

        * one owner assigns ownership privilege and, unbeknownst to this owner, 

        * another owner assigns read-only privilege, 

        Then the resulting privilege is "owner". 

        Note that although these codes are used consistently for privileges over groups and resources, 
        there is no reasonable meaning for 

        1. group ownership of a resource

        2. no sharing for a group 

        Thus, one may not assert these states. 
        """
        self._cur.execute("select privilege_id from privileges where privilege_code=%s", (code,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific privilege code")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['privilege_id']
        else:
            raise HSAException("Privilege code '" + code + "' does not exist")

    # utilize a join view to summarize user privilege over a resource
    # this utilizes the immutable flag and does not even allow the owner to
    # redefine immutability. Only an admin can do that.
    def get_user_privilege_over_resource(self, resource_uuid, user_uuid=None):
        """
        Summarize privileges of a user over a resource

        :type resource_uuid: str
        :type user_uuid: str
        :param resource_uuid: uuid of resource
        :param user_uuid: uuid of user; omit to report on current user 
        :return: int: privilege number 1-100

        The access privileges are the minimum (most powerful) privilege granted by any one user. 
        These include: 

        1. Privileges granted specifically to the user. 

        2. Privileges granted via membership in a group. 

        Note: this routine is not subject to access control. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid

        user_id = self._get_user_id_from_uuid(user_uuid)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        # user_resource_privilege is a UNION of user and group privileges and contains duplicates
        # collapse the duplicates with a MIN function
        self._cur.execute("""select min(privilege_id) as privilege_id from user_resource_privilege
                          where user_id=%s and resource_id=%s
                          group by user_id, resource_id""",
                          (user_id, resource_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user/resource pair")
        if self._cur.rowcount > 0:
            # print self._cur.fetchone()
            priv = self._cur.fetchone()['privilege_id']

            # GROUP BY makes this unnecessary
            # if priv is None:
            #     priv = self._PRIVILEGE_NONE

            if self.resource_is_immutable(resource_uuid):
                return max(priv, self._PRIVILEGE_RO)  # eliminate write privileges from base privilege word.
            else:
                return priv
        else:
            # print "no privilege"
            return self._PRIVILEGE_NONE  # no privilege

    def resource_accessible(self, user_uuid, resource_uuid, code):
        """
        Check if resource is accessible to a specific user in a specific way

        :type user_uuid: str
        :type resource_uuid: str
        :type code: str
        :param user_uuid: user uuid, key to users table
        :param resource_uuid: resource uuid: key to resources table
        :param code: privilege code: key to privileges table
        :return: bool: True if resource is accessible to user in the mode indicated by code

        This routine checks if a resource is accessible at a given level. 
        The codes include:

            own
                ownership

            rw 
                read-write (with sharing) 

            ro 
                read-only (with sharing) 

            ns 
                read-only (no sharing) 

        """
        # OBSOLETE: user_id = self._get_user_id_from_login(login)
        # OBSOLETE: resource_id = self._get_resource_id_from_uuid(uuid)
        privilege_id = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_resource(resource_uuid, user_uuid)
        # print "desired privilege", privilege_id, "actual privilege", actual_priv
        if actual_priv <= privilege_id:
            return True
        else:
            return False

    def resource_is_owned(self, resource_uuid, user_uuid=None):
        """
        Check whether a given resource is owned by a specific user

        :type resource_uuid: str
        :type user_uuid: str
        :param resource_uuid: resource identifier for resource to be checked for access
        :param user_uuid: uuid of user whose privileges should be checked; omit to check current user 
        :return: bool: True if user owns resource. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self.resource_accessible(user_uuid, resource_uuid, 'own')

    def resource_is_readwrite(self, resource_uuid, user_uuid=None):
        """
        Check whether a given resource is read/write to a specific user

        :type resource_uuid: str
        :type user_uuid: str
        :param resource_uuid: resource identifier for resource to be checked for access
        :param user_uuid: uuid of user whose privileges should be checked; omit to check current user 
        :return: bool: True if user has readwrite privilege over resource.
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self.resource_accessible(user_uuid, resource_uuid, 'rw')

    def resource_is_readable(self, resource_uuid, user_uuid=None):
        """
        Check whether a given resource is readable by a specific user

        :type resource_uuid: str
        :type user_uuid: str
        :param resource_uuid: resource identifier for resource to be checked for access
        :param user_uuid: uuid of user whose privileges should be checked; omit to check current user 
        :return: bool: True if user has read-only privilege over resource.
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self.resource_accessible(user_uuid, resource_uuid, 'ro')

    def resource_is_readable_without_sharing(self, resource_uuid, user_uuid=None):
        """
        Check whether a given resource is readable without sharing

        :type resource_uuid: str
        :type user_uuid: str
        :param resource_uuid: resource identifier for resource to be checked for access
        :param user_uuid: uuid of user whose privileges should be checked; omit to check current user 
        :return: bool: True if user has read-only without sharing privileges over resource. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self.resource_accessible(user_uuid, resource_uuid, 'ns')

    ###########################################################
    # Share a resource with a specific user.
    # CLI: hs_share_resource
    # business logic:
    # we can share a resource with a user
    # - at a privilege that we already enjoy for the resource.
    # - unless your privilege is "ns".
    # - or you have admin privileges.
    # users who shared a resource with another user can downgrade or upgrade that sharing as desired.
    # The sharing privileges for a user are a logical OR of all granted sharing privileges from all sources
    ###########################################################

    def share_resource_with_user(self, resource_uuid, user_uuid, privilege_code='ns'):
        """
        Share a specific resource with a specific user

        :param resource_uuid: str: uuid of resource to affect (key to resource table)
        :param user_uuid: str: login name of user to gain access (key to users table)
        :param privilege_code: str: privilege to grant (key to privileges table)
        :return:

        This shares a resource with a user other than self. The current user is implicitly 
        the initiator of the sharing. 

        This is subject to several restrictions: 

        1. A user may not share a resource with self. 

        2. A user may not share a resource at a higher privilege level than that held by the user. 

        3. A user may only update records created by that user, e.g., to upgrade or downgrade sharing
           privileges for another user. 

        4. An administrative user may arbitrarily change sharing parameters. 

        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_is_admin(self._user_uuid)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_resource(resource_uuid)
            if user_priv >= self._PRIVILEGE_NS:
                raise HSAException("Cannot share a resource to which one has no sharing privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource at this level")
        # sufficient privileges present to share this resource
        if self._user_access_to_resource_exists(user_id, resource_id, requesting_id):
            # don't let user remove last owner.
            if self.get_number_of_resource_owners(resource_uuid) > 1 \
                    or self.get_user_privilege_over_resource(resource_uuid, user_uuid) > 1:
                self._share_resource_user_update(requesting_id, user_id, resource_id, privilege_id)
            else:
                raise HSAException("cannot remove last resource owner, including self")
        else:
            self._share_resource_user_add(requesting_id, user_id, resource_id, privilege_id)

    def _user_access_to_resource_exists(self, user_id, resource_id, asserting_user_id):
        """
        PRIVATE: Determine whether there is a record currently sharing the resource, by this user

        :type user_id: int 
        :type resource_id: int
        :type asserting_user_id
        :param user_id: id of user to gain privilege
        :param resource_id: id of resource on which to grant privilege
        :param asserting_user_id: id of user granting privilege
        :return: bool: True if there is a current record for this triple

        This is a helper routine for "share_resource_with_user".
        Note: this routine is not subject to access control.
        """
        self._cur.execute(
            """select privilege_id from user_access_to_resource where user_id=%s
            and resource_id=%s and assertion_user_id=%s""",
            (user_id, resource_id, asserting_user_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific privilege code")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    def _share_resource_user_update(self, requesting_id, user_id, resource_id, privilege_id):
        """
        PRIVATE: update a user record

        :type requesting_id: int
        :type user_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: user id of requesting user
        :param user_id: user id of affected user
        :param resource_id: resource id of affected resource
        :param privilege_id: privilege id to assign
        :return:

        This is a helper routine for "share_resource_with_user". If the resource record 
        to be updated does not exist, an exception is raised. 
         
        Note: this routine is not subject to access control.
        """
        self._cur.execute("""update user_access_to_resource set privilege_id = %s,
          assertion_time=CURRENT_TIMESTAMP where user_id=%s and resource_id=%s and assertion_user_id=%s""",
                          (privilege_id, user_id, resource_id, requesting_id))
        self._conn.commit()

    def _share_resource_user_add(self, requesting_id, user_id, resource_id, privilege_id):
        """
        PRIVATE: add a user record

        :type requesting_id: int
        :type user_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: user id of requesting user
        :param user_id: user id of affected user
        :param resource_id: resource id of affected resource
        :param privilege_id: privilege id to assign
        :return:

        This is a helper routine for 'share_resource_with_user'. If the resource record 
        to be updated does not exist, an exception is raised. 
         
        Note: this routine is not subject to access control.
        """
        self._cur.execute("""insert into user_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (user_id, resource_id, privilege_id, requesting_id))
        self._conn.commit()

    def unshare_resource_with_user(self,  resource_uuid, user_uuid=None):
        """
        Remove all sharing with user (owner only)

        :type resource_uuid: str
        :type user_uuid: str 
        :param resource_uuid: resource to change
        :param user_uuid: user with whom resource is currently shared; omit for current user 
        :return:

        Note: since sharing is cumulative, each user sharing a document with another must separately retract sharing
        before all sharing is removed. It is possible that a user will have several different paths to a resource.

        This routine unshares a resource under three possible conditions; either:
        1. user is admin, or 

        2. user owns resource, or 

        3. user is the sharing target: one should be able to "forget" a share if necessary

        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        # assert_id = self._get_user_id_from_uuid(self._user_uuid)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        user_id = self._get_user_id_from_uuid(user_uuid)
        if self.user_is_admin(self._user_uuid) \
                or self.resource_is_owned(resource_uuid) \
                or user_uuid == self._user_uuid:
            if self.get_number_of_resource_owners(resource_uuid) > 1 \
                    or not self.resource_is_owned(resource_uuid, user_uuid):
                self._cur.execute("""delete from user_access_to_resource where user_id = %s and resource_id = %s""",
                                  (user_id, resource_id))
                self._conn.commit()
            else:
                raise HSAException("cannot remove last owner of a resource")
        else:
            raise HSAException("insufficient privilege to unshare resource with user")

    ###########################################################
    # group privilege
    ###########################################################

    # ##########################################################
    # share a resource with a group of users
    # CLI: hs_share_resource
    # business logic:
    # you can share a resource with a group if
    # - you are in the group and
    # - you have sharing privilege over the resource equal or greater than what you wish to assign or
    # - you are an administrator
    # ##########################################################

    def share_resource_with_group(self, resource_uuid, group_uuid, privilege_code='ns'):
        """
        Share a resource with a group of users

        :type resource_uuid: str
        :type group_uuid: str
        :type privilege_code: str
        :param resource_uuid: the resource to be shared
        :param group_uuid: the group with which to share it: self._user_uuid must be a member.
        :param privilege_code: the privilege to assign: must be less than or equal to self._user_uuid's privilege
        :return:

        Share a resource with a group as the current user. 

        Preconditions:

        1. Current user must be a member of the group, or have administrative privilege. 

        2. Current user must have the same or more comprehensive access to the resource than for the share, 
           or administrative privilege. 

        Postconditions: resource is shared with all members of the group. Privileges changes for all group members
        as individuals, simultaneously. 

        This works the same whether this is the first or a subsequent time the resource is shared. A user can 
        downgrade or upgrade sharing privileges for a resource at will. 

        Note: if a user shares a privilege that is then revoked for that user, the sharing privilege persists 
        for the object.  It is possible to downgrade privilege assigned by a user whose privilege has been 
        downgraded, but this has not been implemented. 
        """
        group_id = self._get_group_id_from_uuid(group_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # access control logic: cannot grant sharing above own privilege
        if privilege_id == self._PRIVILEGE_OWN:
            raise HSAException("Cannot assert 'ownership' privilege for a group")
        if not self.user_is_admin(self._user_uuid):
            if not self.user_in_group(group_uuid, self._user_uuid):
                raise HSAException("User must be a member of a group to share something with the group")
            if not (self.user_is_admin(self._user_uuid)):
                # use join to access privilege records
                user_priv = self.get_user_privilege_over_resource(resource_uuid)
                if user_priv >= self._PRIVILEGE_NS:
                    raise HSAException("Cannot share a group for which user has no sharing privileges")
                else:
                    if user_priv > privilege_id:
                        raise HSAException("User has insufficient privilege to share this resource at this level")
        # sufficient privileges present to share this resource
        if self._group_access_to_resource_exists(requesting_id,  resource_id, group_id):
            self._share_resource_group_update(requesting_id, group_id, resource_id, privilege_id)
        else:
            self._share_resource_group_add(requesting_id, group_id, resource_id, privilege_id)

    def _group_access_to_resource_exists(self, requesting_id, resource_id, group_id):
        """
        PRIVATE: Check whether there is already a privilege record for asserting user, group, and resource

        :type group_id: int
        :type resource_id: int
        :type requesting_id: int
        :param group_id: internal group id of affected group
        :param resource_id: internal resource id of affected resource
        :param requesting_id: internal id of user requesting change
        :return:

        This is a helper routine for 'share_resource_with_group'.
        """
        self._cur.execute(
            """select privilege_id from group_access_to_resource where group_id=%s
            and resource_id=%s and assertion_user_id=%s""",
            (group_id, resource_id, requesting_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for "
                               + "specific group, resource, and user")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    def _share_resource_group_update(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: update group sharing record for a resource

        :type requesting_id: int
        :type group_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: id of requesting user
        :param group_id: id of group to modify
        :param resource_id: id of resource to modify
        :param privilege_id: privilege to assign
        :return:

        This is a helper routine for 'share_resource_with_group'.

        The group sharing record must exist or an exception is raised. 
        """
        self._cur.execute("""update group_access_to_resource set privilege_id = %s,
                          assertion_time=CURRENT_TIMESTAMP where group_id=%s
                          and resource_id=%s and assertion_user_id=%s""",
                          (privilege_id, group_id, resource_id, requesting_id))
        self._conn.commit()

    def _share_resource_group_add(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: add a new group sharing record for a resource

        :type requesting_id: int
        :type group_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: id of requesting user
        :param group_id: id of group to modify
        :param resource_id: id of resource to modify
        :param privilege_id: privilege to assign
        :return:

        This is a helper routine for 'share_resource_with_group'.

        The group sharing record must not exist or an exception is raised. 
        """
        self._cur.execute("""insert into group_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (group_id, resource_id, privilege_id, requesting_id))
        self._conn.commit()

    def unshare_resource_with_group(self, resource_uuid, group_uuid):
        """
        Remove all sharing with user (owner or administrator only)

        :type resource_uuid: str
        :type group_uuid: str
        :param resource_uuid: resource to change
        :param group_uuid: group with whom resource is currently potentially shared
        :return:

        Only a group owner or administrator may revoke all privileges over a resource.  This 
        includes all grants of privilege no matter what the source within the group. 
        """
        # assert_id = self._get_user_id_from_uuid(self._user_uuid)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        if self.user_is_admin(self._user_uuid) or self.resource_is_owned(resource_uuid):
            self._cur.execute("""delete from group_access_to_resource where group_id = %s and resource_id=%s""",
                              (group_id, resource_id))
            self._conn.commit()
        else:
            raise HSAException("insufficient privilege to unshare resource with group: must be owner or admin")

    ###########################################################
    # group membership
    ###########################################################
    # refactored to remove duplication between group privilege and membership
    def user_in_group(self, group_uuid, user_uuid=None):
        """
        Check whether a user is a member of a group

        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of a valid user, omit to check current user 
        :param group_uuid: group uuid of a valid group
        :return: bool: True if the uuid is in the group
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select privilege_id from user_group_privilege where user_id=%s and group_id=%s""",
                          (user_id, group_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one group membership record "
                               + "for a user and group")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    # # OLD VERSION with specific user_membership_in_group table
    # # REPLACED with conflation of privilege with membership
    # # to avoid potential data skwews
    # def user_in_group(self, group_uuid, user_uuid=None):
    #     """
    #     Check whether a user is a member of a group
    #
    #     :type user_uuid: str
    #     :type group_uuid: str
    #     :param user_uuid: uuid of a valid user
    #     :param group_uuid: group uuid of a valid group
    #     :return: True if the uuid is in the group
    #     """
    #     if user_uuid is None:
    #         user_uuid = self._user_uuid
    #     user_id = self._get_user_id_from_uuid(user_uuid)
    #     group_id = self._get_group_id_from_uuid(group_uuid)
    #     self._cur.execute("""select id from user_membership_in_group where user_id=%s and group_id=%s""",
    #                       (user_id, group_id))
    #     if self._cur.rowcount > 1:
    #         raise HSAException("Database integrity violation: more than one group membership record "
    #                            + "for a user and group")
    #     if self._cur.rowcount > 0:
    #         return True
    #     else:
    #         return False
    #
    # def assert_user_in_group(self, group_uuid, user_uuid=None):
    #     """
    #     Add a user to a group if not present already
    #
    #     :type user_uuid: str
    #     :type group_uuid: str
    #     :param user_uuid: user to be added to the group
    #     :param group_uuid: group to which to add user
    #     :return:
    #     """
    #     if user_uuid is None:
    #         user_uuid = self._user_uuid
    #     # if not self.user_is_active(self._user_uuid):
    #     #     raise HSAException("User login '"+self._get_user_login_from_uuid(self._user_uuid)+"' is not active")
    #     if not self.user_exists(user_uuid):
    #         raise HSAException("User uuid '"+user_uuid+"' does not exist")
    #     if not self.user_is_active(user_uuid):
    #         raise HSAException("User login '"+self._get_user_login_from_uuid(user_uuid)+"' is not active")
    #     if not self.group_is_readwrite(group_uuid, self._user_uuid):
    #         raise HSAException("Group '"+self._get_group_name_from_uuid(group_uuid)
    #                            + "' is not writeable to user login '"
    #                            + self._get_user_login_from_uuid(self._user_uuid)+"'")
    #     self._assert_user_in_group(group_uuid, user_uuid)
    #
    # # need this in certain system routines to avoid protection chicken-and-egg problems
    # def _assert_user_in_group(self, group_uuid, user_uuid=None):
    #     """
    #     Override protection scheme to insert first user into group
    #   
    #     :param user_uuid:
    #     :param group_uuid:
    #     :return:
    #     """
    #     if user_uuid is None:
    #         user_uuid = self._user_uuid
    #     requesting_id = self._get_user_id_from_uuid(self._user_uuid)
    #     user_id = self._get_user_id_from_uuid(user_uuid)
    #     group_id = self._get_group_id_from_uuid(group_uuid)
    #     if not (self.user_in_group(group_uuid, user_uuid)):
    #         self._cur.execute("insert into user_membership_in_group VALUES (DEFAULT, %s, %s, %s, DEFAULT)",
    #                           (user_id, group_id, requesting_id))
    #         self._conn.commit()
    #     # self.share_group_with_user(group_uuid, user_uuid, 'ro')
    #
    # # CLI: hs_remove_user_from_group
    # def retract_user_from_group(self, user_uuid, group_uuid):
    #     """
    #     Remove a user from a group if not absent already
    #
    #     :type user_uuid: str
    #     :type group_uuid: str
    #     :param user_uuid: user to be removed from the group
    #     :param group_uuid: group from which to remove user
    #     :return:
    #     """
    #
    #     user_id = self._get_user_id_from_uuid(user_uuid)
    #     group_id = self._get_group_id_from_uuid(group_uuid)
    #
    #     # for now, let people remove themselves
    #     if self._user_uuid == user_uuid and self.user_in_group(group_uuid, user_uuid):
    #         self._cur.execute("delete from user_membership_in_group where user_id=%s and group_id=%s",
    #                           (user_id, group_id))
    #     else:
    #         raise HSAException("Insufficient privilege to retract user from group")
    #     self.unshare_group_with_user(group_uuid, user_uuid)

    ###########################################################
    # group access
    # in current version this is synonymous with membership
    ###########################################################

    # utilize a join view to summarize user privilege
    def get_user_privilege_over_group(self, group_uuid, user_uuid=None):
        """
        Get the privilege that is specified for a user over a specific group
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user for which to obtain privilege
        :param group_uuid: group to which to allow access
        :return: int: privilege code 1-100
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select privilege_id from user_group_privilege where user_id=%s and group_id=%s""",
                          (user_id, group_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one protection int for a user and group")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['privilege_id']
        else:
            return self._PRIVILEGE_NONE  # no privilege

    # utility routine returns numeric code for privilege
    def _group_accessible(self, user_uuid, group_uuid, code):
        """
        PRIVATE: check whether a group is accessible to a user
        :type user_uuid: str
        :type group_uuid: str
        :type code: str
        :param user_uuid: uuid of user for whom to check privilege (key to users table)
        :param group_uuid: uuid of group for which to check privilege (key to groups table)
        :param code: privilege code (key to privileges table)
        :return: bool: True if group is accessible to user in the provided mode
        """
        requested_priv = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_group(group_uuid, user_uuid)
        # print user_uuid, group_uuid, "requested priv=", requested_priv, "actual priv=", actual_priv
        if actual_priv <= requested_priv:
            return True
        else:
            return False

    # can remove group and disinvite group members.
    def group_is_owned(self, group_uuid, user_uuid=None):
        """
        Check whether a group is owned by a user
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is owned by user uuid
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self._group_accessible(user_uuid, group_uuid, 'own')

    # can invite members to group
    def group_is_readwrite(self, group_uuid, user_uuid=None):
        """
        Check whether a group is owned by a user
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is read/write to user uuid
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self._group_accessible(user_uuid, group_uuid, 'rw')

    # minimal group membership: can see members but cannot add/invite them
    def group_is_readable(self, group_uuid, user_uuid=None):
        """
        Check whether a group is owned by a user
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is readable by user uuid
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        return self._group_accessible(user_uuid, group_uuid, 'ro')

    # # this is a meaningless protection
    # def group_is_readable_without_sharing(self, group_uuid, user_uuid=None):
    #     """
    #     Check whether a group is readable without sharing by a user
    #     :type user_uuid: str
    #     :type group_uuid: str
    #     :param user_uuid: uuid of user to check
    #     :param group_uuid: group uuid of group to check
    #     :return: True if group uuid is readable without sharing to user uuid
    #     """
    #     if user_uuid is None:
    #         user_uuid = self._user_uuid
    #     return self._group_accessible(user_uuid, group_uuid, 'ns')

    # CLI: hs invite ....
    def invite_user_to_group(self, group_uuid, user_uuid, privilege_code='ro'):
        """
        Invite a user into a group. The user must accept in a separate step
        :param group_uuid:
        :param user_uuid:
        :param privilege_code:
        :return:
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # sanity logic: no such thing as 'ns' access.
        if privilege_code == 'ns':
            raise HSAException("privilege 'readable without sharing' does not apply to groups")
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_is_admin(self._user_uuid)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_group(group_uuid)
            if user_priv >= self._PRIVILEGE_RO:  # read-only or no-sharing
                raise HSAException("user lacks read/write privilege necessary to invite to this group")
            else:
                if user_priv > privilege_id:
                    raise HSAException("user must hold a privilege in order to share it")
        # sufficient privileges present to share this resource
        if self._user_invite_to_group_exists(requesting_id, group_id, user_id):
            self._invite_group_user_update(requesting_id, user_id, group_id, privilege_id)
        else:
            self._invite_group_user_add(requesting_id, user_id, group_id, privilege_id)

    def _invite_group_user_update(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: update user access to a group
        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :type privilege_id: int
        :param requesting_id: id of user requesting change
        :param user_id: id of user to be enabled
        :param group_id: id of group to be modified
        :param privilege_id: id of privilege to be installed
        :return: None
        """
        self._cur.execute("""update user_invitations_to_group set privilege_id = %s,
                          assertion_time=CURRENT_TIMESTAMP where user_id=%s and group_id=%s and assertion_user_id=%s""",
                          (privilege_id, user_id, group_id, requesting_id))
        self._conn.commit()

    def _invite_group_user_add(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: add new user access for a group
        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :type privilege_id: int
        :param requesting_id: int: id of user requesting change
        :param user_id: int: id of user to be enabled
        :param group_id: int: id of group to be modified
        :param privilege_id: int: id of privilege to be installed
        :return: None
        """
        self._cur.execute("""insert into user_invitations_to_group values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (user_id, group_id, privilege_id, requesting_id))
        self._conn.commit()

    # determine whether an invitation exists already
    def _user_invite_to_group_exists(self, requesting_id, group_id, user_id):
        """
        Test whether there is an access record for a specific user, group, and asserting user
        :type user_id: int
        :type group_id: int
        :type requesting_id: int
        :param user_id: user id of user who needs privilege
        :param group_id: group id of group to which privilege will be assigned
        :param requesting_id: user id of user assigning privilege
        :return:
        """
        self._cur.execute(
            """select privilege_id from user_invitations_to_group where user_id=%s and group_id=%s
            and assertion_user_id=%s""",
            (user_id, group_id, requesting_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a group privilege triple")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    def _get_privilege_from_group_invite(self, requesting_id, user_id, group_id):
        """
        Test whether there is an access record for a specific user, group, and asserting user
        :type user_id: int
        :type group_id: int
        :type requesting_id: int
        :param user_id: user id of user who needs privilege
        :param group_id: group id of group to which privilege will be assigned
        :param requesting_id: user id of user assigning privilege
        :return:
        """
        self._cur.execute(
            """select privilege_id from user_invitations_to_group where user_id=%s and group_id=%s
            and assertion_user_id=%s""",
            (user_id, group_id, requesting_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a group privilege triple")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['privilege_id']
        else:
            raise HSAException("no existing group invitation")

    # a user can only revoke one's own invitations
    # CLI: hs uninvite ....
    def uninvite_user_to_group(self, group_uuid, user_uuid):
        """
        Uninvite a user the current user invited; does not undo other invitations
        Revoke an invitation to join a group
        :param group_uuid: uuid of group
        :param user_uuid: uuid of user
        :return:
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        self._uninvite_user_to_group(requesting_id, group_id, user_id)

    def _uninvite_user_to_group(self, requesting_id, group_id, user_id):
        if self._user_invite_to_group_exists(requesting_id, group_id, user_id):
            self._cur.execute("""delete from user_invitations_to_group where user_id=%s
                              and group_id=%s and assertion_user_id=%s""",
                              (user_id, group_id, requesting_id))
            self._conn.commit()

    # CLI hs ls invitations
    def get_group_invitations_for_user(self, user_uuid=None):
        """
        Get a list of invitations to join groups that can be accepted or refused

        :type user_uuid: str
        :param user_uuid: uuid of user; omit for current user. 
        :return:

        List group invitations in the form::

            {'group': 
                {'uuid': {uuid of group},
                 'name': {name of group},
                 'privilege': {privilege_code}},
             'host': 
                { 'uuid': {uuid of inviting user},
                  'name': {name of inviting user},
                  'login': {login of inviting user}}
            }

        Note: this is scheduled for refactoring for easier acceptance, rejection, and uninviting of users

        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        self._cur.execute("""select g.group_uuid, g.group_name, p.privilege_code, a.user_uuid, a.user_name, a.user_login
                          from user_invitations_to_group i
                          left join groups g on i.group_id=g.group_id
                          left join users u on u.user_id = i.user_id
                          left join users a on a.user_id = i.assertion_user_id
                          left join privileges p on p.privilege_id=i.privilege_id
                          where u.user_uuid=%s
                          order by i.assertion_time desc""",
                          (user_uuid,))
        rows = self._cur.fetchall()
        result = []
        for row in rows:
            result += [{'group': {'uuid': row['group_uuid'],
                                  'name': row['group_name'],
                                  'privilege': row['privilege_code']},
                        'host': { 'uuid': row['user_uuid'],
                                  'name': row['user_name'],
                                  'login': row['user_login']}}]
        return result

    # CLI: hs accept ...
    def accept_invitation_to_group(self, group_uuid, host_uuid):
        """
        Accept an invitation to join a group

        :type group_uuid: str
        :type host_uuid: str
        :param group_uuid: uuid of group for which to accept invitation
        :param host_uuid: user uuid of person who invited you
        :return:

        Accept an invitation to a group previously made by another user via 
        'invite_user_to_group'
        """
        user_id = self._get_user_id_from_uuid(self._user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(host_uuid)
        privilege_id = self._get_privilege_from_group_invite(requesting_id, user_id, group_id)
        if self._user_invite_to_group_exists(requesting_id, group_id, user_id):
            self._share_group_with_user(requesting_id, user_id, group_id, privilege_id)
            # remove invitation after acting on it
            self._uninvite_user_to_group(requesting_id, group_id, user_id)
        else:
            raise HSAException("no group invitation exists for user")

    # CLI: hs refuse
    def refuse_invitation_to_group(self, group_uuid, host_uuid):
        """
        Refuse an invitation to join a group

        :param group_uuid:
        :param host_uuid: user uuid of person who invited
        :return:

        Refuse an invitation created with 'invite_user_to_group'. 
        """
        user_id = self._get_user_id_from_uuid(self._user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(host_uuid)
        if self._user_invite_to_group_exists(requesting_id, group_id, user_id):
            # remove invitation without acting on it
            self._uninvite_user_to_group(requesting_id, group_id, user_id)
        else:
            raise HSAException("no group invitation exists for user")

    #  for now, couple group membership with group privilege
    # self.assert_user_in_group(group_uuid, user_uuid)
    def share_group_with_user(self, group_uuid, user_uuid, privilege_code='ro'):
        """
        DEPRECATED: Attempt to share a group with a user: this allows read/write to the group membership list

        :type group_uuid: str
        :type user_uuid: str
        :type privilege_code: str
        :param group_uuid: group identifier of group to which privilege should be assigned
        :param user_uuid: uuid of user to whom privilege should be granted
        :param privilege_code: privilege to be granted.
        :return: None

        This routine has been replaced by the invite/accept/refuse/uninvite interface, including: 
        * invite_user_to_group (for inviter) 
        * uninvite_user_to_group (for inviter) 
        * accept_invitation_to_group (for invitee) 
        * refuse_invitation_to_group (for invitee) 
        * get_invitations_to_group (for invitee) 

        This is a direct sharing of a group without user permission. 

        Preconditions: 

        1. current user must have equivalent or stronger access to group (or admin privileges). 

        Postconditions: 

        2. User is made a member of the group at the chosen level.

        This may be repeated without harm to downgrade or upgrade members one has previously invited. 

        :todo: not safe from removing last owner 
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # sanity logic: no such thing as 'ns' access.
        if privilege_code == 'ns':
            raise HSAException("privilege 'readable without sharing' does not apply to groups")
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_is_admin(self._user_uuid)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_group(group_uuid)
            if user_priv >= self._PRIVILEGE_RO:  # read-only or no-sharing
                raise HSAException("user lacks read/write privilege necessary to share this group")
            else:
                if user_priv > privilege_id:
                    raise HSAException("user has insufficient privilege to share this group in this way")
        self._share_group_with_user(requesting_id, user_id, group_id, privilege_id)
        # for now, couple group membership with group privilege; the following is obsolete
        # self.assert_user_in_group(group_uuid, user_uuid)

    def _user_access_to_group_exists(self, requesting_id, user_id, group_id):
        """
        PRIVATE: Test whether there is an access record for a specific user, group, and asserting user

        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :param requesting_id: user id of user assigning privilege
        :param user_id: user id of user who needs privilege
        :param group_id: group id of group to which privilege will be assigned
        :return: None

        This is a helper routine for 'share_group_with_user'
        """
        self._cur.execute(
            """select privilege_id from user_access_to_group where user_id=%s and group_id=%s
            and assertion_user_id=%s""",
            (user_id, group_id, requesting_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a group privilege triple")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    def _share_group_with_user(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: unpoliced share of group with user

        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :param requesting_id: internal id of requesting user 
        :param user_id: internal id of user to gain privilege 
        :param group_id: internal id of group to which to grant privilege 
        :return:

        This is a helper routine for 'share_group_with_user'. It does not have access control. 
        """
        if self._user_access_to_group_exists(requesting_id, user_id, group_id):
            self._share_group_user_update(requesting_id, user_id, group_id, privilege_id)
        else:
            self._share_group_user_add(requesting_id, user_id, group_id, privilege_id)

    def _share_group_user_update(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: update user access to a group

        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :type privilege_id: int
        :param requesting_id: id of user requesting change
        :param user_id: id of user to be enabled
        :param group_id: id of group to be modified
        :param privilege_id: id of privilege to be installed
        :return: None

        This is a helper routine for 'share_group_with_user'. It does not have access control. 
        There must already be a privilege record for the user, group, and current user. 
        """
        self._cur.execute("""update user_access_to_group set privilege_id = %s,
                          assertion_time=CURRENT_TIMESTAMP where user_id=%s and group_id=%s and assertion_user_id=%s""",
                          (privilege_id, user_id, group_id, requesting_id))
        self._conn.commit()

    def _share_group_user_add(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: add new user access for a group

        :type requesting_id: int
        :type user_id: int
        :type group_id: int
        :type privilege_id: int
        :param requesting_id: int: id of user requesting change
        :param user_id: int: id of user to be enabled
        :param group_id: int: id of group to be modified
        :param privilege_id: int: id of privilege to be installed
        :return: None

        This is a helper routine for 'share_group_with_user'. It does not have access control. 
        There must not already be a privilege record for the user, group, and current user. 
        """
        self._cur.execute("""insert into user_access_to_group values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (user_id, group_id, privilege_id, requesting_id))
        self._conn.commit()

    # CLI: hs group remove ...
    def unshare_group_with_user(self, group_uuid, user_uuid=None):
        """
        Attempt to unshare a group with a user

        :type group_uuid: str
        :type user_uuid: str
        :param group_uuid: group identifier of group for which privilege should be removed.
        :param user_uuid: uuid of user for whom privilege should be removed; omit for current user. 
        :return: None

        There are three conditions under which one can unshare a group with a user, either: 

        1. user has admin, or 

        2. user owns the group, or

        3. user is the user in question and wishes to leave the group

        """
        if user_uuid is None:
            user_uuid = self._user_uuid

        # these serve as argument checks
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        # requesting_id = self._get_user_id_from_uuid(self._user_uuid)

        # access control logic:
        if self.user_is_admin(self._user_uuid) \
                or self.group_is_owned(group_uuid) \
                or (user_uuid == self._user_uuid and self.user_in_group(group_uuid, user_uuid)):
            if self.get_number_of_group_owners(group_uuid) > 1 or not self.group_is_owned(group_uuid, user_uuid):
                self._cur.execute("delete from user_access_to_group where group_id=%s and user_id=%s",
                                  (group_id, user_id))
                self._conn.commit()
            else:
                raise HSAException("cannot remove last group owner")
            # self.retract_user_from_group(user_uuid, group_uuid)
        else:
            raise HSAException("insufficient privilege to unshare group '"
                               + self.get_group_print_name(group_uuid)
                               + "' with user '"
                               + self.get_user_print_name(user_uuid))

    ###########################################################
    # faceted information retrieval
    ###########################################################
    # CLI: hs ls resources
    def resources_held_by_user(self, user_uuid=None):
        """
        Make a list of resources held by user, sorted by title

        :type user_uuid: str
        :param user_uuid: uuid of user; omit for current user. 
        :return: List of resources containing dict items

        This returns a list of resource dict records, in the format::

            {
            'uuid': *uuid of resource*,
            'title': *title of resource*,
            'path': *path of resource*,
            'privilege': *privilege code*
            }
           
        Note: this is not subject to access control. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select distinct r.resource_uuid, r.resource_title, r.resource_path, p.privilege_code
          from user_resource_privilege u
          left join resources r on r.resource_id = u.resource_id
          left join privileges p on p.privilege_id = u.privilege_id
          where user_id=%s order by r.resource_uuid""", (user_id,))
        result = []
        for row in self._cur:
            result.append({'uuid': row['resource_uuid'],
                           'title': row['resource_title'],
                           'path': row['resource_path'],
                           'privilege': row['privilege_code']})
        return result

    def resources_held_by_group(self, group_uuid):
        """
        Retrieve resources accessible to a specific group

        :type group_uuid: str
        :param group_uuid: uuid of the group to check
        :return: list: structure of resources

        This returns a list of resources accessible to a specific group, in the format::

            {
            'uuid': *uuid of resource*,
            'title': *title of resource*,
            'path': *path of resource*,
            'privilege': *privilege code*
            }

        Note: this is not subject to access control. 
        """
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select r.resource_title, r.resource_uuid, r.resource_path, q.privilege_code
                          from resources r inner join group_resource_privilege p
                          on r.resource_id = p.resource_id
                          left join privileges q on p.privilege_id = q.privilege_id
                          where p.group_id = %s""",
                          (group_id,))
        # map this into a dict structure
        result = []
        for row in self._cur:
            result.append({'uuid': row['resource_uuid'],
                           'title': row['resource_title'],
                           'path': row['resource_path'],
                           'privilege': row['privilege_code']})
        return {}

    # CLI: hs ls groups
    def groups_of_user(self, user_uuid=None):
        """
        Make a list of groups in which a user is a member.

        :type user_uuid: str
        :param user_uuid: uuid of user, or None to use current authorized user 
        :return: list of dict entries, one per group

        This returns a list of dictionaries, each of the form::

            {
            'uuid': *group's uuid*, 
            'name': *group's name*
            }

        for use in displaying group data. 

        """
        # default to irods user if no uuid given
        if user_uuid is None:
            user_uuid = self._user_uuid
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select distinct g.group_uuid, g.group_name
            from user_membership_in_group m left join groups g on m.group_id=g.group_id
            where user_id=%s order by g.group_name, g.group_uuid""", (user_id,))
        result = []
        for row in self._cur:
            result.append({'uuid': row['group_uuid'], 'name': row['group_name']})
        return result

    # ##########################################################
    # stubs for folder subsystem
    # ##########################################################
    def assert_folder(self, folder_name):
        """
        STUB: Create a folder in the user_folders relation

        :type folder_name: str
        :param folder_name: The name of the folder
        :return: None

        Uses self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def retract_folder(self, folder_name):
        """
        STUB: Remove a folder; things in the folder become "unfiled"

        :type folder_name: str
        :param folder_name: The name of the folder
        :return: None

        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def assert_resource_in_folder(self, resource_uuid, folder_name):
        """
        STUB: Put a resource into a previously created folder

        :type resource_uuid: str
        :type folder_name: str
        :param resource_uuid: identifier of resource to put into folder
        :param folder_name: name of the folder
        :return: None

        Uses self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def retract_resource_in_folder(self, resource_uuid, folder_name):
        """
        STUB: Remove a resource from a folder; it becomes unfiled.

        :type resource_uuid: str
        :type folder_name: str
        :param resource_uuid: identifier of resource to put into folder
        :param folder_name: name of the folder
        :return: None
        """
        return

    def get_folders(self):
        """
        STUB: Return a list of folders for this user

        :return: A list of folder names

        Uses self._user_uuid: current user identity
        """
        return

    def get_resources_in_folders(self, folder=None):
        """
        STUB: Get a structured dictionary of folders and their contents

        :type folder: str
        :param folder: the optional name of a folder to use as the top of the hierarchy
        :return: A dict object of contents

        Uses self._user_uuid: the current user.

        This returns a dictionary structure of the form::

            { folder: { resource_uuid : { title : *resource title*, 'access' : *access code* }}}

        1. If folder is None, report on the whole hierarchy of user folders 

        2.  If folder is not None, report on only one chosen folder.

        """
        return

    # ##########################################################
    # stubs for tag subsystem
    # ##########################################################
    def assert_tag(self, tag_name):
        """
        STUB: Create a tag in the user_tags relation

        :type tag_name: str
        :param tag_name: The name of the tag
        :return: None

        Uses self._user_uuid: the identity of the current user.

        Registers a tag for later uses. This assures that tags are unambiguous when applied. 
        Folders are local to the current user.
        """
        return

    def retract_tag(self, tag_name):
        """
        STUB: Remove a tag; things in the tag become "untagged"

        :type tag_name: str
        :param tag_name: The name of the tag
        :return: None

        Uses self._user_uuid: the identity of the current user.

        Unregisters a tag along with all of uses of that tag on resources. 
        Folders are local to the current user.
        """
        return

    def assert_resource_has_tag(self, resource_uuid, tag_name):
        """
        STUB: Assign a resource a previously created tag

        :type resource_uuid: str
        :type tag_name: str
        :param resource_uuid: identifier of resource to put into tag
        :param tag_name: name of the tag
        :return: None

        Uses self._user_uuid: the identity of the current user.
        Tags are local to the current user.
        Multiple asserts with different tags apply all of them
        """
        return

    def retract_resource_has_tag(self, resource_uuid, tag_name):
        """
        STUB: Remove a tag from a resource; it becomes untagged.

        :type resource_uuid: str
        :type tag_name: str
        :param resource_uuid: identifier of resource to put into tag
        :param tag_name: name of the tag
        :return: None

        Uses self._user_uuid: the identity of the current user.
        Tags are local to the current user.
        This removes an assertion of one tag while leaving the others alone. 
        """
        return

    def get_tags(self):
        """
        STUB: Return a list of tags for this user

        :return: A list of tag names

        Uses self._user_uuid: current user identity
        """
        return

    def get_resources_by_tag(self, tag=None):
        """
        STUB: Get a structured dictionary of tags and their contents

        :type tag: str
        :param tag: the name of a tag to use
        :return: A dict object of contents

        Uses: self._user_uuid: the current user.
        This returns a dictionary structure of the form::

            { "tag": { resource_uuid : { title : *resource title*, 'access' : *access code* }}}

        If tag argument is not None, report on only one tag.
        """
        return

    ####################################################################
    # statistics
    ####################################################################

    def get_number_of_resource_owners(self, resource_uuid):
        """
        Count the number of resource owners for a resource, for reporting purposes. 

        :type resource_uuid: str
        :param resource_uuid: identifier of resource to report upon 
        :return: int: number of owners
        """
        if not self.resource_exists(resource_uuid):
            raise HSAException("resource uuid '" + resource_uuid + "' does not exist")
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        self._cur.execute("""select count(distinct user_id) as count from user_resource_privilege
                          where resource_id=%s and privilege_id=1""",
                          (resource_id,))
        return self._cur.fetchone()['count']

    def get_number_of_group_owners(self, group_uuid):
        """
        Count the number of resource owners for a resource, for reporting purposes. 

        :type group_uuid: str
        :param group_uuid: identifier of group to report upon 
        :return: int: number of owners
        """
        if not self.group_exists(group_uuid):
            raise HSAException("group uuid '" + group_uuid + "' does not exist")
        resource_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select count(distinct user_id) as count from user_group_privilege
                          where group_id=%s and privilege_id=1""",
                          (resource_id,))
        return self._cur.fetchone()['count']

    def get_number_of_resources_owned_by_user(self, user_uuid=None):
        """
        Count the number of resources owned by a user. 

        :type user_uuid: str
        :param user_uuid: identifier of group to report upon; None reports upon current user 
        :return: int: number of resources owned

        Note: this reports on any user independent of the privilege of the current user. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        if not self.user_exists(user_uuid):
            raise HSAException("user uuid '" + user_uuid + "' does not exist")
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select count(distinct resource_id) as count from user_resource_privilege
                          where user_id=%s and privilege_id=1""",
                          (user_id,))
        return self._cur.fetchone()['count']

    # get the number of groups the user owns
    def get_number_of_groups_owned_by_user(self, user_uuid=None):
        """
        Count the number of groups owned by a user. 

        :type user_uuid: str
        :param user_uuid: identifier of group to report upon; None reports upon current user 
        :return: int: number of groups owned

        Note: this reports on any user independent of the privilege of the current user. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        if not self.user_exists(user_uuid):
            raise HSAException("user uuid '" + user_uuid + "' does not exist")
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select count(distinct group_id) as count from user_group_privilege
                          where user_id=%s and privilege_id=1""",
                          (user_id,))
        return self._cur.fetchone()['count']

    # measure the number of resources the user can access
    def get_number_of_resources_held_by_user(self, user_uuid=None):
        """
        Count the number of resources held by a user. 

        :type user_uuid: str
        :param user_uuid: identifier of group to report upon; None reports upon current user 
        :return: int: number of resources held

        Note: this reports on any user independent of the privilege of the current user. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        if not self.user_exists(user_uuid):
            raise HSAException("user uuid '" + user_uuid + "' does not exist")
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select count(distinct resource_id) as count from user_resource_privilege
                          where user_id=%s""",
                          (user_id,))
        return self._cur.fetchone()['count']

    # measure the number of resources the user can access
    # note: group membership and access are currently synonymous
    # I am utilizing group access as the count.

    def get_number_of_groups_of_user(self, user_uuid=None):
        """
        Count the number of groups in which a user is a member

        :type user_uuid: str
        :param user_uuid: identifier of group to report upon; None reports upon current user 
        :return: int: number of groups joined 

        Note: this reports on any user independent of the privilege of the current user. 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        if not self.user_exists(user_uuid):
            raise HSAException("user uuid '" + user_uuid + "' does not exist")
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select count(distinct group_id) as count from user_group_privilege
                          where user_id=%s""",
                          (user_id,))
        return self._cur.fetchone()['count']

    ##################################################################################
    # quick utility routines for obtaining current user information
    ##################################################################################

    def get_uuid(self):
        """
        Returns the uuid of the current user 

        :return: str: uuid of current user 
        """
        return self._user_uuid

    def get_login(self):
        """
        Returns the (iRODS) login name of the current user 

        :return: str: login name of current user 
        """
        return self._irods_user

    def get_user_print_name(self, user_uuid=None):
        """
        Constructs a print name for any given user

        :type user_uuid: str
        :param user_uuid: identifier of user, None for current user 
        :return: str: print name for requested user 
        """
        if user_uuid is None:
            user_uuid = self._user_uuid
        meta = self.get_user_metadata(user_uuid)
        return meta['name'] + '(' + meta['uuid'] + ')'

    def get_resource_print_name(self, resource_uuid):
        """
        Constructs a print name for any given resource

        :type resource_uuid: str
        :param resource_uuid: identifier of resource
        :return: str: print name for requested resource 
        """
        meta = self.get_resource_metadata(resource_uuid)
        return meta['title'] + '(' + meta['uuid'] + ')'

    def get_group_print_name(self, group_uuid):
        """
        Constructs a print name for any given group

        :type group_uuid: str
        :param group_uuid: identifier of group
        :return: str: print name for requested group 
        """
        meta = self.get_group_metadata(group_uuid)
        return meta['name'] + '(' + meta['uuid'] + ')'

    #################################################
    # reset everything for testing
    #################################################

    def _global_reset(self, are_you_sure):
        """
        PRIVATE: Delete all data from the database except for starting situation, for testing.

        :type are_you_sure: str
        :param are_you_sure: a string that must have the value "yes, I'm sure"

        This clears the database to an install state. This is used for testing,
        and never in production. 
        """
        if (self.user_is_admin(self._user_uuid)):
            if (are_you_sure == "yes, I'm sure"):
                self._cur.execute("delete from user_tags_of_resource")
                self._cur.execute("delete from user_folder_of_resource")
                self._cur.execute("delete from group_access_to_resource")
                # self._cur.execute("delete from user_membership_in_group")
                self._cur.execute("delete from user_invitations_to_group")
                self._cur.execute("delete from user_access_to_group")
                self._cur.execute("delete from user_access_to_resource")
                self._cur.execute("delete from user_folders")
                self._cur.execute("delete from user_tags")
                self._cur.execute("delete from groups")
                self._cur.execute("delete from resources")
                self._cur.execute("delete from users where user_id != 1")
                self._conn.commit()
        else:
            raise HSAException("operation requires admin privilege")
