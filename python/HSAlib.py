__author__ = 'Alva Couch'

import psycopg2
import psycopg2.extras

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

# exception class specifically for access control exceptions


class HSAException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# class encapsulates all access control actions
class HSAccess:
    """
    Access control class for HydroShare Resources, Groups
    """
    _NO_PRIVILEGE = 100  # code that no privilege is asserted
    _OWN = 1  # owner of thing
    _RW = 2   # can read and write thing
    _RO = 3   # can read thing
    _NS = 4   # can read but not share with others

    def __init__(self, database, user, password, host, port):
        try:
            self.conn = psycopg2.connect(database=database, user=user, password=password, host=host, port=port)
            self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except:
            raise HSAException("unable to connect to the database")

    def __del__(self):
        if self.conn is not None:
            self.conn.close()

    ###########################################################
    # user handling
    ###########################################################
    # fetch a list of all user logins
    def get_user_logins(self):
        """
        Get a list of all registered user logins
        :return: list of login names
        """
        self.cur.execute("SELECT user_login FROM users")
        result = []
        rows = self.cur.fetchall()
        for row in rows:
            result += [row['user_login']]
        return result

    def get_user_metadata(self, login):
        """
        Get metadata for a user as a dict record
        :param login: login name of user for which to fetch metadata
        :return: None
        """
        self.cur.execute("""select u.user_login, u.user_guid, u.user_name, u.user_active, u.user_admin,
          a.user_login as user_assertion_login, u.assertion_time
          from users u left join users a on u.assertion_user_id = a.user_id
          where u.user_login=%s""", (login,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self.cur.rowcount > 0:
            row = self.cur.fetchone()
            return {'login': row['user_login'],
                    'guid':  row['user_guid'],
                    'name': row['user_name'],
                    'active': row['user_active'],
                    'admin': row['user_admin'],
                    'asserting_login': row['assertion_user_id'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such user login " + login)

    def assert_user_metadata(self, requesting_login, metadata):
        """
        Assert changes in user metadata
        :param requesting_login: str: login of requesting user
        :param metadata: a metadata record returned by get_user_metadata
        :return: None
        """
        self.assert_user(metadata['login'], requesting_login,
                         metadata['guid'], metadata['name'],
                         metadata['active'], metadata['admin'])

    # get a specific login id for use as an entity id for recording actions
    def _get_user_id_from_login(self, login):
        """
        PRIVATE: get user database id from login name
        :param login: string login name
        :return: integer user id
        """
        self.cur.execute("select user_id from users where user_login=%s", (login,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['user_id']
        else:
            raise HSAException("User login '" + login + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def user_exists(self, login):
        """
        Determine whether a login name is registered in the HSAccess database
        :param login: str login name
        :return: bool
        """
        self.cur.execute("select user_id from users where user_login=%s", (login,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    # test whether a user login has administrative privileges
    def user_login_is_admin(self, login):
        """
        Determine whether a login name has admin privileges
        :param login: str login name
        :return: bool
        """
        self.cur.execute("select user_admin from users where user_login=%s", (login,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self.cur.rowcount > 0:
            if self.cur.fetchone()['user_admin']:
                return True
            else:
                return False
        else:
            raise HSAException("user login '" + login + "' does not exist")

    # test whether a user login is entitled to make changes
    def user_login_is_active(self, login):
        """
        Determine whether a user login is an active user
        :param login: str login name
        :return: bool
        """
        self.cur.execute("select user_active from users where user_login=%s", (login,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self.cur.rowcount > 0:
            if self.cur.fetchone()['user_active']:
                return True
            else:
                return False
        else:
            raise HSAException("user login '" + login + "' does not exist")

    # this is a no-frills assert of a user record without object use
    def assert_user(self, user_login, assert_login, user_guid, user_name, user_active=True, user_admin=False):
        """
        Register or update the registration of a user login name
        :param user_login: str login name to register or update
        :param assert_login: str login name of asserting user
        :param user_guid: str: user guid string
        :param user_name: str: user print name
        :param user_active: bool: whether user is active
        :param user_admin: bool: whether user is an admin
        :return: None
        """
        if not self.user_exists(assert_login):
            raise HSAException("Asserting login '" + assert_login + "' does not exist")
        if not (self.user_login_is_active(assert_login)):
            raise HSAException("Asserting login '" + assert_login + "' is inactive")
        if user_admin is True and not (self.user_login_is_admin(assert_login)):
            raise HSAException("User login '" + user_login + "' is not an administrator; operation requires privilege")
        assert_id = self._get_user_id_from_login(assert_login)

        if self.user_exists(user_login):
            self._assert_user_update(user_login, assert_id, user_guid, user_name, user_active, user_admin)
        else:
            self._assert_user_add(user_login, assert_id, user_guid, user_name, user_active, user_admin)

    def _assert_user_add(self, user_login, assertion_user_id, user_guid, user_name, user_active=True, user_admin=False):
        """
        PRIVATE: add a user record
        :param user_login: str: login of user to add
        :param assertion_user_id: str: user adding the login name
        :param user_guid: str: user guid string: must be unique
        :param user_name: str: user print name
        :param user_active: bool: whether user is active
        :param user_admin: bool: whether user is an administrator
        :return: None
        """
        self.cur.execute("""insert into users values (DEFAULT, %s, %s, %s, %s, %s, %s, DEFAULT)""",
                         (user_login, user_guid, user_name, user_active, user_admin, assertion_user_id))
        self.conn.commit()

    # this is the general idea but can be cleaned up with conditional code.
    def _assert_user_update(self, user_login, assertion_user_id, user_guid, user_name, user_active=True,
                            user_admin=False):
        """
        PRIVATE: update an existing user record
        :param user_login: str: login of user to update (primary key)
        :param assertion_user_id: str: user adding the login name
        :param user_guid: str: user guid string: must be unique
        :param user_name: str: user print name
        :param user_active: bool: whether user is active
        :param user_admin: bool: whether user is an administrator
        :return: None
        """
        self.cur.execute("""update users set user_guid =%s, user_name=%s, user_active=%s, user_admin=%s,
                         assertion_user_id=%s, assertion_time=CURRENT_TIMESTAMP
                         where user_login=%s""",
                         (user_guid, user_name, user_active, user_admin, assertion_user_id, user_login))
        self.conn.commit()

    ###########################################################
    # user group handling
    ###########################################################
    # should it be possible for a group to go inactive?

    # fetch a list of all group guids
    def get_groups(self):
        """
        Get information on all existing groups
        :return: a list of all group guids and titles, as dictionary objects
        """
        self.cur.execute("SELECT group_guid, group_name FROM groups ORDER BY group_name, group_guid")
        result = []
        rows = self.cur.fetchall()
        for row in rows:
            result += [{'group_guid': row['group_guid'], 'group_name': row['group_name']}]
        return result

    def get_group_metadata(self, guid):
        """
        Get metadata for a group as a dict record
        ;param login: login of requesting user
        :return: None
        """
        self.cur.execute("""select g.group_guid, g.group_name,
          a.user_login as user_assertion_login, g.assertion_time
          from groups g left join users a on g.assertion_user_id = a.user_id
          where g.group_guid=%s""", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group guid")
        if self.cur.rowcount > 0:
            row = self.cur.fetchone()
            return {'name': row['group_name'],
                    'guid':  row['group_guid'],
                    'asserting_login': row['user_assertion_login'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such group " + guid)

    def assert_group_metadata(self, login, metadata):
        """
        Assert changes in user metadata
        ;param login: login of requesting user
        :param metadata: a metadata record as returned by get_group_metadata
        :return: None
        """
        self.assert_group(metadata['guid'], login, metadata['name'])

    # get a specific login id for use as an entity id for recording actions
    def _get_group_id_from_guid(self, guid):
        """
        PRIVATE: translate from group object identifier to database id
        :param guid: str: group object identifier
        :return: int: group_id in HSAccess database
        """
        self.cur.execute("select group_id from groups where group_guid=%s", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group guid")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['group_id']
        else:
            raise HSAException("Group guid '" + guid + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def group_exists(self, guid):
        """
        Determine whether group identifier (guid) is registered
        :param guid: str: group object identifier
        :return: bool: whether group object identifier is registered
        """
        self.cur.execute("select group_id from groups where group_guid=%s", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group guid")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    # this is a no-frills assert user without object use
    def assert_group(self, group_guid, assert_login, group_name):
        """
        Register or update a group
        :param group_guid: str: group identifier
        :param assert_login: str: login of requesting user
        :param group_name: str: name of group
        :return: None
        """
        if not (self.user_login_is_admin(assert_login)):
            raise HSAException("Insufficient privilege to complete operation")
        assert_id = self._get_user_id_from_login(assert_login)
        if self.group_exists(group_guid):
            self._assert_group_update(group_guid, assert_id, group_name)
        else:
            self._assert_group_add(group_guid, assert_id, group_name)

    def _assert_group_add(self, group_guid, assertion_user_id, group_name):
        """
        PRIVATE: add a new group to the registry
        :param group_guid: str: group identifier
        :param assertion_user_id: int: id of requesting user
        :param group_name: str: name of group
        :return: None
        """
        self.cur.execute("""insert into groups values (DEFAULT, %s, %s, %s, DEFAULT)""",
                         (group_name, group_guid, assertion_user_id))
        self.conn.commit()

    def _assert_group_update(self, group_guid, assertion_user_id, group_name):
        """
        PRIVATE: update a group record in the registry
        :param group_guid: str: group identifier
        :param assertion_user_id: int: id of requesting user
        :param group_name: str: name of group
        :return: None
        """
        self.cur.execute("""update groups set group_name=%s,
                         assertion_user_id=%s, assertion_time=CURRENT_TIMESTAMP
                         where group_guid=%s""",
                         (group_name, assertion_user_id, group_guid))
        self.conn.commit()

    def retract_group(self, login, guid):
        """
        Delete a group and all membership information
        ;param login: str: requesting login
        :param guid: str: guid of group to delete
        :return: None
        Retractions are handled via database cascade logic
        """
        # only an owner can retract a group

        if self.group_is_owned(login, guid):
            self.cur.execute("""delete from groups where group_guid=%s""", (guid,))
        else:
            raise HSAException("Only group owners can remove a group")

    ###########################################################
    # resource handling
    ###########################################################
    def _get_resource_id_from_guid(self, guid):
        """
        PRIVATE: get resource_id from resource digital identifier (guid)
        :param guid: str: resource object identifier
        :return: int: resource_id in HSAccess database
        """
        self.cur.execute("select resource_id from resources where resource_guid=%s", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource guid")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['resource_id']
        else:
            raise HSAException("Resource guid '" + guid + "' does not exist")

    def resource_exists(self, guid):
        """
        Whether resource is registered in the database
        :param guid: str: resource identifier
        :return: bool: whether resource is registered
        """
        self.cur.execute("select resource_id from resources where resource_guid=%s", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource guid")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    def resource_is_immutable(self, guid):
        """
        Whether resource is flagged as immutable
        :param guid: str: resource identifier
        :return: bool: whether resource has been flagged as immutable
        """
        # print "checking that " + login + " exists"
        self.cur.execute("select resource_immutable from resources where resource_guid=%s", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource guid")
        if self.cur.rowcount > 0:
            if self.cur.fetchone()['resource_immutable']:
                return True
            else:
                return False
        else:
            raise HSAException("resource guid '" + guid + "' does not exist")

    def get_resource_metadata(self, guid):
        """
        Get metadata for a group as a dict record
        :param guid: group identifier for which to fetch metadata
        :return: None
        """
        self.cur.execute("""select r.resource_guid, r.resource_path,
          r.resource_title, r.resource_immutable,
          a.user_login as user_assertion_login, r.assertion_time
          from resources r left join users a on r.assertion_user_id = a.user_id
          where r.resource_guid=%s""", (guid,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource guid")
        if self.cur.rowcount > 0:
            row = self.cur.fetchone()
            return {'title': row['resource_title'],
                    'guid':  row['resource_guid'],
                    'path': row['resource_path'],
                    'immutable': row['resource_immutable'],
                    'asserting_login': row['user_assertion_login'],
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such group " + guid)

    def assert_resource_metadata(self, requesting_login, metadata):
        """
        Assert changes in resource metadata
        :param requesting_login: login of user requesting the change
        :param metadata: a metadata record as returned by get_resource_metadata
        :return: None
        """
        self.assert_resource(metadata['guid'], requesting_login,
                             metadata['path'], metadata['title'], metadata['immutable'])

    # a primitive resource instantiation without objects
    def assert_resource(self, resource_guid, assert_login,
                        resource_path, resource_title, resource_immutable=False):
        """
        Add or modify a resource in the registry
        :param resource_guid: resource identifier
        :param assert_login: str: user login of adding person
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: None
        """
        if not (self.user_exists(assert_login)):
            raise HSAException("Asserting login '" + assert_login + "' does not exist")
        assert_id = self._get_user_id_from_login(assert_login)

        if self.resource_exists(resource_guid):
            # add update privilege logic here
            self._assert_resource_update(resource_guid, assert_id,
                                         resource_path, resource_title, resource_immutable)
        else:
            self._assert_resource_add(resource_guid, assert_id,
                                      resource_path, resource_title, resource_immutable)
            # add owner logic here

    # subfunction: add a resource whose guid (primary key) does not exist
    def _assert_resource_add(self, resource_guid, assertion_user_id,
                             resource_path, resource_title, resource_immutable=False):
        """
        PRIVATE: add a new resource to the registry
        :param resource_guid: resource identifier
        :param assertion_user_id: user id of adding person
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: None
        """
        self.cur.execute("""insert into resources values (DEFAULT, %s, %s, %s, %s, %s, DEFAULT)""",
                         (resource_guid, resource_path, resource_title, resource_immutable, assertion_user_id))
        self.conn.commit()

    # subfunction: update a resource whose guid is known
    def _assert_resource_update(self, resource_guid, assertion_user_id, resource_path, resource_title,
                                resource_immutable=False):
        """
        PRIVATE: update an existing resource in the registry
        :param resource_guid: resource identifier
        :param assertion_user_id: user id of adding person
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: None
        """
        self.cur.execute("""update resources set resource_path=%s, resource_title=%s, resource_immutable=%s,
            assertion_user_id=%s, assertion_time=CURRENT_TIMESTAMP
            where resource_guid=%s""",
                         (resource_path, resource_title, resource_immutable, assertion_user_id, resource_guid))
        self.conn.commit()

    ###########################################################
    # user privilege over resources
    ###########################################################
    def _get_privilege_id_from_code(self, code):
        """
        PRIVATE: translate from privilege code to database id
        :param code: str: code for privilege level: own, rw, ro, ns
        :return: int: privilege_id in database system
        """
        self.cur.execute("select privilege_id from privileges where privilege_code=%s", (code,))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific privilege code")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['privilege_id']
        else:
            raise HSAException("Privilege code '" + code + "' does not exist")

    def _user_access_to_resource_exists(self, user_id, resource_id, asserting_user_id):
        """
        Determine whether there is a record currently sharing the resource, by this user
        :param user_id: int: id of user to gain privilege
        :param resource_id: int: id of resource on which to grant privilege
        :param asserting_user_id: int: id of user granting privilege
        :return: bool: True if there is a current record for this triple
        """
        self.cur.execute(
            """select privilege_id from user_access_to_resource where user_id=%s
            and resource_id=%s and assertion_user_id=%s""",
            (user_id, resource_id, asserting_user_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific privilege code")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    # def _get_user_access_to_resource_privilege(self, user_id, resource_id, asserting_user_id):
    # self.cur.execute("""select privilege_id from user_access_to_resource where user_id=%s and resource_id=%s
    #                   and assertion_user_id=%s""",
    #                      (user_id, resource_id, asserting_user_id))
    #     if self.cur.rowcount>0:
    #         return self.cur.fetchone()['privilege_id']
    #     else:
    #         raise HSAException("no privileges recorded for user_id "+user_id+", resource_id "+resource_id
    #               +", granting user id "+asserting_user_id)

    # utilize a join view to summarize user privilege
    def get_user_privilege_over_resource(self, user_login, resource_guid):
        """
        Summarize privileges of a user over a resource
        :param user_login: str: login of user
        :param resource_guid: str: guid of resource
        :return: int: privilege number 1-100
        """
        user_id = self._get_user_id_from_login(user_login)
        resource_id = self._get_resource_id_from_guid(resource_guid)
        self.cur.execute("""select min(privilege_id) as privilege_id from user_resource_privilege
                         where user_id=%s and resource_id=%s""",
                         (user_id, resource_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user/resource pair")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['privilege_id']
        else:
            return self._NO_PRIVILEGE  # no privilege

    def resource_accessible(self, login, guid, code):
        """
        Check if resource is accessible to a specific user in a specific way
        :param login: str: user login name, key to users table
        :param guid: str: resource guid: key to resources table
        :param code: str: privilege code: key to privileges table
        :return: bool: True if resource is accessible to login in the mode indicated by code
        """
        # OBSOLETE: user_id = self._get_user_id_from_login(login)
        # OBSOLETE: resource_id = self._get_resource_id_from_guid(guid)
        privilege_id = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_resource(login, guid)
        if actual_priv <= privilege_id:
            return True
        else:
            return False

    def resource_is_owned(self, login, guid):
        """
        Check whether a given resource is owned by a specific user
        :param login: login name of user whose privileges should be checked
        :param guid: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(login, guid, 'own')

    def resource_is_readwrite(self, login, guid):
        """
        Check whether a given resource is read/write to a specific user
        :param login: login name of user whose privileges should be checked
        :param guid: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(login, guid, 'rw')

    def resource_is_readable(self, login, guid):
        """
        Check whether a given resource is readable by a specific user
        :param login: login name of user whose privileges should be checked
        :param guid: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(login, guid, 'ro')

    def resource_is_readable_without_sharing(self, login, guid):
        """
        Check whether a given resource is readable without sharing
        :param login: login name of user whose privileges should be checked
        :param guid: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(login, guid, 'ns')

    def share_resource_with_user(self, requesting_login, resource_guid, user_login, privilege_code='ns'):
        """
        Share a specific resource with a specific user
        :param requesting_login: str: login name of requesting user (key to users table)
        :param resource_guid: str: guid of resource to affect (key to resource table)
        :param user_login: str: login name of user to gain access (key to users table)
        :param privilege_code: str: privilege to grant (key to privileges table)
        :return:
        """
        user_id = self._get_user_id_from_login(user_login)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_guid(resource_guid)
        requesting_id = self._get_user_id_from_login(requesting_login)
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_login_is_admin(requesting_login)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_resource(requesting_id, resource_id)
            # OBSOLETE: user_priv = min(user_priv, self.get_user_group_privilege_over_resource(requesting_id,
            # resource_id))
            if user_priv >= self._NS:
                raise HSAException("Cannot share a resource to which one has no sharing privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource")
        # sufficient privileges present to share this resource
        if self._user_access_to_resource_exists(user_id, resource_id, requesting_id):
            self._share_resource_user_update(requesting_id, user_id, resource_id, privilege_id)
        else:
            self._share_resource_user_add(requesting_id, user_id, resource_id, privilege_id)

    def _share_resource_user_update(self, requesting_id, user_id, resource_id, privilege_id):
        self.cur.execute("""update user_access_to_resource set privilege_id = %s,
          assertion_time=CURRENT_TIMESTAMP where user_id=%s and resource_id=%s and assertion_user_id=%s""",
                         (privilege_id, user_id, resource_id, requesting_id))
        self.conn.commit()

    def _share_resource_user_add(self, requesting_id, user_id, resource_id, privilege_id):
        self.cur.execute("""insert into user_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                         (user_id, resource_id, privilege_id, requesting_id))
        self.conn.commit()

    ###########################################################
    # group privilege
    ###########################################################
    # change assertion_time to assertion_time to be consistent
    def _group_access_to_resource_exists(self, group_id, resource_id, asserting_user_id):
        self.cur.execute(
            """select privilege_id from group_access_to_resource where group_id=%s
            and resource_id=%s and assertion_user_id=%s""",
            (group_id, resource_id, asserting_user_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for "
                               + "specific group, resource, and user")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    # def _get_group_access_to_resource_privilege(self, group_id, resource_id, asserting_user_id):
    #     """ PRIVATE Check low-level access to a group by a user: used only in share_resource_with_group
    #     :param group_id: the group for which to check privilege
    #     :param resource_id: the resource id for which to check privilege
    #     :param asserting_user_id: the asserting user looking to change privilege
    #     :return: an integer between 1 and self._NO_PRIVILEGE, denoting privilege level
    #     """
    #     self.cur.execute("""select privilege_id from group_access_to_resource where group_id=%s
    #                       and resource_id=%s and assertion_user_id=%s""",
    #                      (group_id, resource_id, asserting_user_id))
    #     if self.cur.rowcount>0:
    #         return self.cur.fetchone()['privilege_id']
    #     else:
    #         raise HSAException("no privileges recorded for group_id "+group_id+", resource_id "+resource_id
    #               +", granting user id "+asserting_user_id)

    # # utilize a join view to summarize user privilege
    # # OBSOLETE due to refactoring of get_user_privilege_over_resource
    # def _get_user_group_privilege_over_resource(self, user_login, resource_guid):
    #     """ Get the privileges over a resource resulting from all group memberships
    #     :param user_login: the user on which to report
    #     :param resource_guid: the resource on which to report
    #     :return: an integer between 1 and self._NO_PRIVILEGE, denoting a privilege level
    #     """
    #     user_id = self._get_user_id_from_login(user_login)
    #     resource_id = self._get_resource_id_from_guid(resource_guid)
    #     self.cur.execute(
    #         """select privilege_id from user_group_privilege_over_resource where user_id=%s and resource_id=%s""",
    #         (user_id, resource_id))
    #     if self.cur.rowcount > 0:
    #         return self.cur.fetchone()['privilege_id']
    #     else:
    #         return self._NO_PRIVILEGE  # no privilege

    # share a resource with a group of users
    def share_resource_with_group(self, requesting_login, resource_guid, group_guid, privilege_code='ns'):
        """
        Share a resource with a group of users
        :param requesting_login: the user asking to share the resource: must have access
        :param resource_guid: the resource to be shared
        :param group_guid: the group with which to share it: requesting_login must be a member.
        :param privilege_code: the privilege to assign: must be less than or equal to requesting_login's privilege
        :return: None
        """
        group_id = self._get_group_id_from_guid(group_guid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_guid(resource_guid)
        requesting_id = self._get_user_id_from_login(requesting_login)
        # access control logic: cannot grant sharing above own privilege
        if privilege_id == self._OWN:
            raise HSAException("Cannot assert resource owner privilege for a group")
        if not (self.user_login_is_admin(requesting_login)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_resource(requesting_id, privilege_id)
            # OBSOLETE: user_priv = min(user_priv, self._get_user_group_privilege_over_resource(requesting_id,
            # privilege_id))
            if user_priv >= self._NS:
                raise HSAException("Cannot share a group for which user has no sharing privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource in this manner")
        # sufficient privileges present to share this resource
        if self._group_access_to_resource_exists(group_id, resource_id, requesting_id):
            self._share_resource_group_update(requesting_id, group_id, resource_id, privilege_id)
        else:
            self._share_resource_group_add(requesting_id, group_id, resource_id, privilege_id)

    def _share_resource_group_update(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: update group sharing record for a resource
        :param requesting_id: int: id of requesting user
        :param group_id: int: id of group to modify
        :param resource_id: int: id of resource to modify
        :param privilege_id: int: privilege to assign
        :return: None
        """
        self.cur.execute("""update group_access_to_resource set privilege_id = %s,
          assertion_time=CURRENT_TIMESTAMP where group_id=%s and resource_id=%s and assertion_user_id=%s""",
                         (privilege_id, group_id, resource_id, requesting_id))
        self.conn.commit()

    def _share_resource_group_add(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: add a new group sharing record for a resource
        :param requesting_id: int: id of requesting user
        :param group_id: int: id of group to modify
        :param resource_id: int: id of resource to modify
        :param privilege_id: int: privilege to assign
        :return: None
        """
        self.cur.execute("""insert into group_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                         (group_id, resource_id, privilege_id, requesting_id))
        self.conn.commit()

    ###########################################################
    # group membership
    ###########################################################
    def user_in_group(self, login, guid):
        """
        Check whether a user is a member of a group
        :param login: login name of a valid user
        :param guid: group guid of a valid group
        :return: True if the login is in the group
        """
        user_id = self._get_user_id_from_login(login)
        group_id = self._get_group_id_from_guid(guid)
        self.cur.execute("select id from user_membership_in_group where user_id=%s and group_id=%s",
                         (user_id, group_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one group membership record "
                               + "for a user and group")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    def assert_user_in_group(self, requesting_login, user_login, group_guid):
        """
        Add a user to a group if not present already
        :param requesting_login: user requesting change
        :param user_login: user to be added to the group
        :param group_guid: group to which to add user
        :return: None
        """
        requesting_id = self._get_user_id_from_login(requesting_login)
        user_id = self._get_user_id_from_login(user_login)
        group_id = self._get_group_id_from_guid(group_guid)
        if not (self.user_in_group(user_login, group_guid)):
            self.cur.execute("insert into user_membership_in_group VALUES (DEFAULT, %s, %s, %s, DEFAULT)",
                             (user_id, group_id, requesting_id))

    def retract_user_from_group(self, requesting_login, user_login, group_guid):
        """
        Remove a user from a group if not absent already
        :param requesting_login: user requesting change
        :param user_login: user to be removed from the group
        :param group_guid: group from which to remove user
        :return: None
        """
        # OBSOLETE requesting_id = self._get_user_id_from_login(requesting_login)
        user_id = self._get_user_id_from_login(user_login)
        group_id = self._get_group_id_from_guid(group_guid)

        # for now, let people remove themselves
        if requesting_login == user_login and self.user_in_group(user_login, group_guid):
            self.cur.execute("delete from user_membership_in_group where user_id=%s and group_id=%s",
                             (user_id, group_id))
        else:
            raise HSAException("Insufficient privilege to retract group")

    ###########################################################
    # group access
    ###########################################################

    def _user_access_to_group_exists(self, user_id, group_id, asserting_user_id):
        """
        Test whether there is an access record for a specific user, group, and asserting user
        :param user_id: user id of user who needs privilege
        :param group_id: group id of group to which privilege will be assigned
        :param asserting_user_id: user id of user assigning privilege
        :return:
        """
        self.cur.execute(
            """select privilege_id from user_access_to_group where user_id=%s and group_id=%s
            and assertion_user_id=%s""",
            (user_id, group_id, asserting_user_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a group privilege triple")
        if self.cur.rowcount > 0:
            return True
        else:
            return False

    # def _get_user_access_to_group_privilege(self, user_id, group_id, asserting_user_id):
    #     self.cur.execute("""select privilege_id from user_access_to_group where user_id=%s and group_id=%s
    #                       and assertion_user_id=%s""",
    #                      (user_id, group_id, asserting_user_id))
    #     if self.cur.rowcount>0:
    #         return self.cur.fetchone()['privilege_id']
    #     else:
    #         raise HSAException("no privileges recorded for user_id "+user_id+", group_id "+group_id+",
    #               granting user id "+asserting_user_id)

    # utilize a join view to summarize user privilege
    def get_user_privilege_over_group(self, user_login, group_guid):
        """
        Get the privilege that is specified for a user over a specific group
        :param user_login: login of user for which to obtain privilege
        :param group_guid:  group to which to allow access
        :return: int: privilege code 1-199
        """
        user_id = self._get_user_id_from_login(user_login)
        group_id = self._get_group_id_from_guid(group_guid)
        self.cur.execute("""select privilege_id from user_privilege_over_group where user_id=%s and group_id=%s""",
                         (user_id, group_id))
        if self.cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one protection int for a user and group")
        if self.cur.rowcount > 0:
            return self.cur.fetchone()['privilege_id']
        else:
            return self._NO_PRIVILEGE  # no privilege

    def group_accessible(self, login, guid, code):
        """
        Check whether a group is accessible to a user
        :param login: str: login of user for whom to check privilege (key to users table)
        :param guid: str: gui of group for which to check privilege (key to groups table)
        :param code: str: privilege code (key to privileges table)
        :return: bool: True if group is accessible to user in the provided mode
        """
        # OBSOLETE user_id = self._get_user_id_from_login(login)
        # OBSOLETE group_id = self._get_group_id_from_guid(guid)
        privilege_id = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_group(login, guid)
        if actual_priv <= privilege_id:
            return True
        else:
            return False

    def group_is_owned(self, login, guid):
        """
        Check whether a group is owned by a user
        :param login: str: login name of user to check
        :param guid: str: group guid of group to check
        :return: bool: True if group guid is owned by login
        """
        return self.group_accessible(login, guid, 'own')

    def group_is_readwrite(self, login, guid):
        """
        Check whether a group is owned by a user
        :param login: str: login name of user to check
        :param guid: str: group guid of group to check
        :return: bool: True if group guid is owned by login
        """
        return self.group_accessible(login, guid, 'rw')

    def group_is_readable(self, login, guid):
        """
        Check whether a group is owned by a user
        :param login: str: login name of user to check
        :param guid: str: group guid of group to check
        :return: bool: True if group guid is readable by login
        """
        return self.group_accessible(login, guid, 'ro')

    def group_is_readable_without_sharing(self, login, guid):
        """
        Check whether a group is readable without sharing by a user
        :param login: str: login name of user to check
        :param guid: str: group guid of group to check
        :return: True if group guid is readable without sharing
        """
        return self.group_accessible(login, guid, 'ns')

    def share_group_with_user(self, requesting_login, group_guid, user_login, privilege_code='ns'):
        """
        Attempt to share a group with a user: this allows read/write to the group membership list
        :param requesting_login: str: login of user trying to grant the privilege
        :param group_guid:  str: group identifier of group to which privilege should be assigned
        :param user_login: str: login of user to whom privilege should be granted
        :param privilege_code: str: privilege to be granted.
        :return: None
        """
        user_id = self._get_user_id_from_login(user_login)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        group_id = self._get_group_id_from_guid(group_guid)
        requesting_id = self._get_user_id_from_login(requesting_login)
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_login_is_admin(requesting_login)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_group(requesting_id, group_id)
            if user_priv >= self._RO:  # read-only or no-sharing
                raise HSAException("Cannot modify a group without read/write privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource")
        # sufficient privileges present to share this resource
        if self._user_access_to_group_exists(user_id, group_id, requesting_id):
            self._share_group_user_update(requesting_id, user_id, group_id, privilege_id)
        else:
            self._share_group_user_add(requesting_id, user_id, group_id, privilege_id)

    def _share_group_user_update(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: update user access to a group
        :param requesting_id: int: id of user requesting change
        :param user_id: int: id of user to be enabled
        :param group_id: int: id of group to be modified
        :param privilege_id: int: id of privilege to be installed
        :return: None
        """
        self.cur.execute("""update user_access_to_group set privilege_id = %s,
          assertion_time=CURRENT_TIMESTAMP where user_id=%s and group_id=%s and assertion_user_id=%s""",
                         (privilege_id, user_id, group_id, requesting_id))
        self.conn.commit()

    def _share_group_user_add(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: add new user access for a group
        :param requesting_id: int: id of user requesting change
        :param user_id: int: id of user to be enabled
        :param group_id: int: id of group to be modified
        :param privilege_id: int: id of privilege to be installed
        :return: None
        """
        self.cur.execute("""insert into user_access_to_group values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                         (user_id, group_id, privilege_id, requesting_id))
        self.conn.commit()

    ###########################################################
    # faceted information retrieval
    ###########################################################
    def resources_held_by_user(self, user_login):
        """
        Make a list of resources held by user, sorted by title
        :param user_login: str: login of user
        :return: List of resources containing dict items
        """
        user_id = self._get_user_id_from_login(user_login)
        self.cur.execute("""select distinct r.resource_guid, r.resource_title, r.resource_path
          from user_resource_privilege u
          left join resources r on r.resource_id = u.resource_id
          where user_id=%s order by r.resource_guid""", (user_id,))
        result = []
        for row in self.cur:
            result.append({'guid': row['resource_guid'],
                           'title': row['resource_title'],
                           'path': row['resource_path']})
        return result

    def groups_of_user(self, user_login):
        """
        Make a list of groups in which a user is a member.
        :param user_login: str: login of user
        :return: list of dict entries, one per group
        """
        user_id = self._get_user_id_from_login(user_login)
        self.cur.execute("""select distinct g.group_guid, g.group_name
          from user_membership_in_group m left join groups g on m.group_id=g.group_id
          where user_id=%s order by g.group_name, g.group_guid""", (user_id,))
        result = []
        for row in self.cur:
            result.append({'guid': row['group_guid'], 'name': row['group_name']})
        return result
