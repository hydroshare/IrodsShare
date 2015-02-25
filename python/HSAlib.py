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
    _PRIVILEGE_NONE = 100          # code that no privilege is asserted
    _PRIVILEGE_OWN = 1             # owner of thing
    _PRIVILEGE_RW = 2              # can read and write thing
    _PRIVILEGE_RO = 3              # can read thing
    _PRIVILEGE_NS = 4              # can read but not share with others

    def __init__(self, irods_user, irods_password,
                 db_database, db_user, db_password, db_host, db_port):
        try:
            self._irods_user = irods_user
            print 'irods_user is ', irods_user
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

    def get_user_logins(self):
        """
        Get a list of all registered user logins
        :type self: HSAccess
        :return: list of login names
        """
        self._cur.execute("SELECT user_login FROM users")
        result = []
        rows = self._cur.fetchall()
        for row in rows:
            result += [row['user_login']]
        return result

    def get_user_metadata(self, user_uuid):
        """
        Get metadata for a user as a dict record
        :type self: HSAccess
        :type login: str
        :param login: login name of user for which to fetch metadata
        :return: Dict of metadata for the login specified
        """
        self._cur.execute("""select u.user_login, u.user_uuid, u.user_name, u.user_active, u.user_admin,
          a.user_login as user_assertion_login, u.assertion_time
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
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such user uuid " + user_uuid)

    def assert_user_metadata(self, metadata, user_uuid=None):
        """
        Assert changes in user metadata
        :type self: HSAccess
        :type metadata: list
        :param metadata: a metadata record returned by get_user_metadata
        :return: None

        Uses self._user_uuid to authorize actions
        """
        if user_uuid is None and self.user_is_admin(self._user_uuid):
            user_uuid = self._user_uuid
        else:
            if user_uuid != self._user_uuid and not self.user_is_admin(self._user_uuid):
                raise HSAException("Cannot assert metadata for user other than self: operation requires privilege")
        self.assert_user(user_uuid,
                         metadata['uuid'], metadata['login'], metadata['name'],
                         metadata['active'], metadata['admin'])

    # get a specific login id for use as an entity id for recording actions
    def _get_user_id_from_login(self, login):
        """
        PRIVATE: get user database id from login name
        :type self: HSAccess
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
    def _get_user_id_from_uuid(self, user_uuid):
        """
        PRIVATE: get user database id from login name
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: integer user id
        """
        self._cur.execute("select user_id from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_id']
        else:
            raise HSAException("User uuid '" + user_uuid + "' does not exist")

    # get a specific login id for use as an entity id for recording actions
    def _get_user_uuid_from_login(self, login):
        """
        PRIVATE: get user database id from login name
        :type self: HSAccess
        :type login: str
        :param login: string login name
        :return: integer user id
        """
        self._cur.execute("select user_uuid from users where user_login=%s", (login,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user login")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['user_uuid']
        else:
            raise HSAException("User login '" + login + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def user_exists(self, user_uuid):
        """
        Determine whether a login name is registered in the HSAccess database
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: bool
        """
        self._cur.execute("select user_id from users where user_uuid=%s", (user_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user uuid")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    # test whether a user login has administrative privileges
    def user_is_admin(self, user_uuid):
        """
        Determine whether a user uuid has admin privileges
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: bool
        """
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
    def user_is_active(self, user_uuid):
        """
        Determine whether a user uuid is an active user
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: bool
        """
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
    def assert_user(self, user_uuid, user_login, user_name,  user_active=True, user_admin=False):
        """
        Register or update the registration of a user
        :type self: HSAccess
        :type user_uuid: str
        :type user_uuid: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool
        :param user_uuid: str uuid to register or update
        :param user_login: user login name
        :param user_name: str: user print name
        :param user_active: bool: whether user is active
        :param user_admin: bool: whether user is an admin
        :return: None
        """
        if not self.user_exists(self._user_uuid):
            raise HSAException("Asserting uuid '" + self._user_uuid + "' does not exist")
        if not (self.user_is_active(self._user_uuid)):
            raise HSAException("Asserting uuid '" + self._user_uuid + "' is inactive")
        if user_admin is True and not (self.user_is_admin(self._user_uuid)):
            raise HSAException("User uuid '" + self._user_uuid + "' is not an administrator; operation requires privilege")
        assert_id = self._get_user_id_from_uuid(self._user_uuid)

        if self.user_exists(user_uuid):
            self._assert_user_update(assert_id, user_uuid, user_login, user_name, user_active, user_admin)
        else:
            self._assert_user_add(assert_id, user_uuid, user_login, user_name, user_active, user_admin)

    def _assert_user_add(self, assertion_user_id, user_uuid, user_login, user_name, user_active=True, user_admin=False):
        """
        PRIVATE: add a user record
        :type self: HSAccess

        :type assertion_user_id: int
        :type user_uuid: str
        :type user_login: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool
        :param assertion_user_id: user adding the login name
        :param user_uuid: uuid of user to add
        :param user_login: user login string: must be unique
        :param user_name: user print name
        :param user_active: whether user is active
        :param user_admin: whether user is an administrator
        :return: None
        """
        self._cur.execute("""insert into users values (DEFAULT, %s, %s, %s, %s, %s, %s, DEFAULT)""",
                          (user_uuid, user_login, user_name, user_active, user_admin, assertion_user_id))
        self._conn.commit()

    # this is the general idea but can be cleaned up with conditional code.
    def _assert_user_update(self, assertion_user_id, user_uuid, user_login, user_name, user_active=True,
                            user_admin=False):
        """
        PRIVATE: update an existing user record
        :type self: HSAccess
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
        :return: None
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
        :return: a list of all group uuids and titles, as dictionary objects
        """
        self._cur.execute("SELECT group_uuid, group_name FROM groups ORDER BY group_name, group_uuid")
        result = []
        rows = self._cur.fetchall()
        for row in rows:
            result += [{'group_uuid': row['group_uuid'], 'group_name': row['group_name']}]
        return result

    def get_group_metadata(self, group_uuid):
        """
        Get metadata for a group as a dict record
        ;param login: login of requesting user
        :return: None
        """
        self._cur.execute("""select g.group_uuid, g.group_name, g.group_active,
          a.user_login as user_assertion_login, g.assertion_time
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
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such group " + group_uuid)

    def assert_group_metadata(self, metadata):
        """
        Assert changes in user metadata
        ;param login: login of requesting user
        :param metadata: a metadata record as returned by get_group_metadata
        :return: None
        """
        self.assert_group(metadata['uuid'], metadata['name'], metadata['active'])

    # get a specific login id for use as an entity id for recording actions
    def _get_group_id_from_uuid(self, group_uuid):
        """
        PRIVATE: translate from group object identifier to database id
        :param group_uuid: str: group object identifier
        :return: int: group_id in HSAccess database
        """
        self._cur.execute("select group_id from groups where group_uuid=%s", (group_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific group uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['group_id']
        else:
            raise HSAException("Group uuid '" + group_uuid + "' does not exist")

    # test whether a login exists without recovering its id or metadata
    def group_exists(self, group_uuid):
        """
        Determine whether group identifier (uuid) is registered
        :param group_uuid: str: group object identifier
        :return: bool: whether group object identifier is registered
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
    def assert_group(self, group_uuid, group_name, group_active=True):
        """
        Register or update a group
        :param group_uuid: str: group identifier
        :param group_name: str: name of group
        :return: None
        """

        assert_id = self._get_user_id_from_uuid(self._user_uuid)
        if self.group_exists(group_uuid):
            if self.user_is_admin(self._user_uuid) or self.group_is_owned(self._user_uuid, group_uuid):
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
            self.assert_user_in_group(self._user_uuid, group_uuid)

    def _assert_group_add(self, assertion_user_id, group_uuid, group_name, group_active):
        """
        PRIVATE: add a new group to the registry
        :param group_uuid: str: group identifier
        :param assertion_user_id: int: id of requesting user
        :param group_name: str: name of group
        :return: None
        """
        self._cur.execute("""insert into groups values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (group_uuid, group_name, group_active, assertion_user_id))
        self._conn.commit()

    def _assert_group_update(self, assertion_user_id, group_uuid, group_name, group_active):
        """
        PRIVATE: update a group record in the registry
        :param group_uuid: str: group identifier
        :param assertion_user_id: int: id of requesting user
        :param group_name: str: name of group
        :param group_active: bool: is group active or retired 
        :return: None
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
    def retract_group(self, group_uuid, login=None):
        """
        Delete a group and all membership information
        :param group_uuid: str: uuid of group to delete
        :return: None
        Retractions are handled via database cascade logic
        """
        # only an owner or administrator can retract a group
        if login is not None:
            if not self.user_is_admin(self._user_uuid) and login is not self._irods_user:
                raise HSAException("cannot retract groups for other users: this requires privilege")
        else:
            # act as self
            login = self._irods_user

        # this depends upon cascading in the database system.
        user_uuid = self._get_user_id_from_login(login)
        if self.group_is_owned(user_uuid, group_uuid) or self.user_is_admin(self._user_uuid):
            self._cur.execute("""delete from groups where group_uuid=%s""", (group_uuid,))
        else:
            raise HSAException("Only group owners can remove a group")

    ###########################################################
    # resource handling
    ###########################################################

    def _get_resource_id_from_uuid(self, resource_uuid):
        """
        PRIVATE: get resource_id from resource digital identifier (uuid)
        :param resource_uuid: str: resource object identifier
        :return: int: resource_id in HSAccess database
        """
        self._cur.execute("select resource_id from resources where resource_uuid=%s", (resource_uuid,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific resource uuid")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['resource_id']
        else:
            raise HSAException("Resource uuid '" + resource_uuid + "' does not exist")

    def resource_exists(self, resource_uuid):
        """
        Whether resource is registered in the database
        :param resource_uuid: str: resource identifier
        :return: bool: whether resource is registered
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
        :param resource_uuid: str: resource identifier
        :return: bool: whether resource has been flagged as immutable
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
        :param resource_uuid: group identifier for which to fetch metadata
        :return: None
        """
        self._cur.execute("""select r.resource_uuid, r.resource_path,
          r.resource_title, r.resource_immutable,
          a.user_login as user_assertion_login, r.assertion_time
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
                    'assertion_time': row['assertion_time']}
        else:
            raise HSAException("no such group " + resource_uuid)

    def assert_resource_metadata(self, metadata):
        """
        Assert changes in resource metadata
        :param metadata: a metadata record as returned by get_resource_metadata
        :return: None
        """
        self.assert_resource(metadata['uuid'], metadata['path'], metadata['title'], metadata['immutable'])

    # a primitive resource instantiation without objects
    # CLI: currently this can only be done properly through django
    # but we need a debugging command "hs_register_resource" for our own use
    def assert_resource(self, resource_uuid,
                        resource_path, resource_title, resource_immutable=False):
        """
        Add or modify a resource in the registry
        :param resource_uuid: resource identifier
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: int
        """
        if not (self.user_exists(self._user_uuid)):
            raise HSAException("Asserting login '" + self._irods_user + "' does not exist")

        requesting_user_id = self._get_user_id_from_uuid(self._user_uuid)

        if self.resource_exists(resource_uuid):
            # only admin users or owners can change the resource name
            if self.user_is_admin(self._user_uuid) or self.resource_is_owned(resource_uuid):
                self._assert_resource_update(requesting_user_id, resource_uuid,
                                             resource_path, resource_title, resource_immutable)
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

    # subfunction: add a resource whose uuid (primary key) does not exist
    # this has no inherent protection and is used internally for some
    # initial creation tasks.
    def _assert_resource_add(self, requesting_user_id, resource_uuid,
                             resource_path, resource_title, resource_immutable=False):
        """
        PRIVATE: add a new resource to the registry
        :param resource_uuid: resource identifier
        :param requesting_user_id: user id of adding person
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: None
        """
        self._cur.execute("""insert into resources values (DEFAULT, %s, %s, %s, %s, %s, DEFAULT)""",
                          (resource_uuid, resource_path, resource_title, resource_immutable, requesting_user_id))
        self._conn.commit()

    # subfunction: update a resource whose uuid is known
    def _assert_resource_update(self, requesting_user_id, resource_uuid,
                                resource_path, resource_title, resource_immutable=False):
        """
        PRIVATE: update an existing resource in the registry
        :param resource_uuid: resource identifier
        :param requesting_user_id: user id of adding person
        :param resource_path: path in iRODS
        :param resource_title: human-readable title
        :param resource_immutable: whether resource is immutable
        :return: None
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
        :param code: str: code for privilege level: own, rw, ro, ns
        :return: int: privilege_id in database system
        """
        self._cur.execute("select privilege_id from privileges where privilege_code=%s", (code,))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific privilege code")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['privilege_id']
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

    # utilize a join view to summarize user privilege over a resource
    def get_user_privilege_over_resource(self, user_login, resource_uuid):
        """
        Summarize privileges of a user over a resource
        :param user_login: str: login of user
        :param resource_uuid: str: uuid of resource
        :return: int: privilege number 1-100
        """
        user_id = self._get_user_id_from_login(user_login)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        # user_resource_privilege is a UNION of user and group privileges and contains duplicates
        # collapse the duplicates with a MIN function
        self._cur.execute("""select min(privilege_id) as privilege_id from user_resource_privilege
                         where user_id=%s and resource_id=%s""",
                          (user_id, resource_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one record for a specific user/resource pair")
        if self._cur.rowcount > 0:
            priv = self._cur.fetchone()['privilege_id']
            if self.resource_is_immutable(resource_uuid):
                return max(priv, self._PRIVILEGE_RO)  # eliminate write privileges from base privilege word.
            else:
                return priv
        else:
            return self._PRIVILEGE_NONE  # no privilege

    def resource_accessible(self, user_uuid, resource_uuid, code):
        """
        Check if resource is accessible to a specific user in a specific way
        :param user_uuid: str: user uuid, key to users table
        :param resource_uuid: str: resource uuid: key to resources table
        :param code: str: privilege code: key to privileges table
        :return: bool: True if resource is accessible to user in the mode indicated by code
        """
        # OBSOLETE: user_id = self._get_user_id_from_login(login)
        # OBSOLETE: resource_id = self._get_resource_id_from_uuid(uuid)
        privilege_id = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_resource(user_uuid, resource_uuid)
        if actual_priv <= privilege_id:
            return True
        else:
            return False

    def resource_is_owned(self, user_uuid, resource_uuid):
        """
        Check whether a given resource is owned by a specific user
        :param user_uuid: login name of user whose privileges should be checked
        :param resource_uuid: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(user_uuid, resource_uuid, 'own')

    def resource_is_readwrite(self, user_uuid, resource_uuid):
        """
        Check whether a given resource is read/write to a specific user
        :type self: HSAccess
        :param user_uuid: str: uuid of user whose privileges should be checked
        :param resource_uuid: str: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(user_uuid, resource_uuid, 'rw')

    def resource_is_readable(self, user_uuid, resource_uuid):
        """
        Check whether a given resource is readable by a specific user
        :type self: HSAccess
        :param user_uuid: str: uuid of user whose privileges should be checked
        :param resource_uuid: str: resource identifier for resource to be checked for access
        :return:
        """
        return self.resource_accessible(user_uuid, resource_uuid, 'ro')

    def resource_is_readable_without_sharing(self, user_uuid, resource_uuid):
        """
        Check whether a given resource is readable without sharing
        :type self: HSAccess
        :param user_uuid: str: uuid of user whose privileges should be checked
        :param resource_uuid: str: resource identifier for resource to be checked for access
        :return:
        """
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
        :type self: HSAccess
        :param resource_uuid: str: uuid of resource to affect (key to resource table)
        :param user_uuid: str: login name of user to gain access (key to users table)
        :param privilege_code: str: privilege to grant (key to privileges table)
        :return:
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_is_admin(self._user_uuid)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_resource(requesting_id, resource_id)
            if user_priv >= self._PRIVILEGE_NS:
                raise HSAException("Cannot share a resource to which one has no sharing privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource at this level")
        # sufficient privileges present to share this resource
        if self._user_access_to_resource_exists(user_id, resource_id, requesting_id):
            self._share_resource_user_update(requesting_id, user_id, resource_id, privilege_id)
        else:
            self._share_resource_user_add(requesting_id, user_id, resource_id, privilege_id)

    def _share_resource_user_update(self, requesting_id, user_id, resource_id, privilege_id):
        """
        PRIVATE: update a user record
        :type self: HSAccess
        :param requesting_id: int: user id of requesting user
        :param user_id: int: user id of affected user
        :param resource_id: int: resource id of affected resource
        :param privilege_id: int: privilege id to assign
        :return: None
        """
        self._cur.execute("""update user_access_to_resource set privilege_id = %s,
          assertion_time=CURRENT_TIMESTAMP where user_id=%s and resource_id=%s and assertion_user_id=%s""",
                          (privilege_id, user_id, resource_id, requesting_id))
        self._conn.commit()

    def _share_resource_user_add(self, requesting_id, user_id, resource_id, privilege_id):
        """
        PRIVATE: add a user record
        :type self: HSAccess
        :param requesting_id: int: user id of requesting user
        :param user_id: int: user id of affected user
        :param resource_id: int: resource id of affected resource
        :param privilege_id: int: privilege id to assign
        :return: None
        """
        self._cur.execute("""insert into user_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (user_id, resource_id, privilege_id, requesting_id))
        self._conn.commit()

    def unshare_resource_with_user(self,  resource_uuid, user_uuid):
        """
        Remove all sharing with user (owner only)
        :param resource_uuid: resource to change
        :param user_uuid: user with whom resource is currently shared
        :return: None
        """
        victim_id = self._get_user_id_from_uuid(user_uuid)
        if self.user_is_admin(self._user_uuid) or self.resource_is_owned(self._user_uuid, resource_uuid):
            self._cur.execute("""delete from user_access_to_resource where user_id = %s""", (victim_id,))
        else:
            raise HSAException("insufficient privilege to remove user")

    ###########################################################
    # group privilege
    ###########################################################

    def _group_access_to_resource_exists(self, requesting_id, resource_id, group_id):
        """
        Check whether there is already a privilege record for asserting user, group, and resource
        :type self: HSAccess
        :type group_id: int
        :type resource_id: int
        :type requesting_id: int
        :param group_id: group id of affected group
        :param resource_id: resource id of affected resource
        :param requesting_id: id of user requesting change
        :return:
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
        :type self: HSAccess
        :type resource_uuid: str
        :type group_uuid: str
        :type privilege_code: str
        :param resource_uuid: the resource to be shared
        :param group_uuid: the group with which to share it: self._user_uuid must be a member.
        :param privilege_code: the privilege to assign: must be less than or equal to self._user_uuid's privilege
        :return: None
        """
        group_id = self._get_group_id_from_uuid(group_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        resource_id = self._get_resource_id_from_uuid(resource_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # access control logic: cannot grant sharing above own privilege
        if privilege_id == self._PRIVILEGE_OWN:
            raise HSAException("Cannot assert 'ownership' privilege for a group")
        if not self.user_is_admin(self._user_uuid):
            if not self.user_in_group(self._user_uuid, group_uuid):
                raise HSAException("User must be a member of a group to share something with the group")
            if not (self.user_is_admin(self._user_uuid)):
                # use join to access privilege records
                user_priv = self.get_user_privilege_over_resource(requesting_id, resource_id)
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

    def _share_resource_group_update(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: update group sharing record for a resource
        :type self: HSAccess
        :type requesting_id: int
        :type group_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: id of requesting user
        :param group_id: id of group to modify
        :param resource_id: id of resource to modify
        :param privilege_id: privilege to assign
        :return: None
        """
        self._cur.execute("""update group_access_to_resource set privilege_id = %s,
                          assertion_time=CURRENT_TIMESTAMP where group_id=%s
                          and resource_id=%s and assertion_user_id=%s""",
                          (privilege_id, group_id, resource_id, requesting_id))
        self._conn.commit()

    def _share_resource_group_add(self, requesting_id, group_id, resource_id, privilege_id):
        """
        PRIVATE: add a new group sharing record for a resource
        :type self: HSAccess
        :type requesting_id: int
        :type group_id: int
        :type resource_id: int
        :type privilege_id: int
        :param requesting_id: id of requesting user
        :param group_id: id of group to modify
        :param resource_id: id of resource to modify
        :param privilege_id: privilege to assign
        :return: None
        """
        self._cur.execute("""insert into group_access_to_resource values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (group_id, resource_id, privilege_id, requesting_id))
        self._conn.commit()

    ###########################################################
    # group membership
    ###########################################################
    def user_in_group(self, user_uuid, group_uuid):
        """
        Check whether a user is a member of a group
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of a valid user
        :param group_uuid: group uuid of a valid group
        :return: True if the uuid is in the group
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select id from user_membership_in_group where user_id=%s and group_id=%s""",
                          (user_id, group_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one group membership record "
                               + "for a user and group")
        if self._cur.rowcount > 0:
            return True
        else:
            return False

    # CLI: hs_add_user_to_group
    def assert_user_in_group(self, user_uuid, group_uuid):
        """
        Add a user to a group if not present already
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: user to be added to the group
        :param group_uuid: group to which to add user
        :return: None
        """
        if not self.user_is_active(self._user_uuid):
            raise HSAException("User '"+self._irods_user+"' is not active")
        if not self.user_is_active(user_uuid):
            raise HSAException("User '"+user_uuid+"' is not active")
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        if not (self.user_in_group(user_uuid, group_uuid)):
            self._cur.execute("insert into user_membership_in_group VALUES (DEFAULT, %s, %s, %s, DEFAULT)",
                              (user_id, group_id, requesting_id))

    # CLI: hs_remove_user_from_group
    def retract_user_from_group(self, user_uuid, group_uuid):
        """
        Remove a user from a group if not absent already
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: user to be removed from the group
        :param group_uuid: group from which to remove user
        :return: None
        """

        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)

        # for now, let people remove themselves
        if self._user_uuid == user_uuid and self.user_in_group(user_uuid, group_uuid):
            self._cur.execute("delete from user_membership_in_group where user_id=%s and group_id=%s",
                              (user_id, group_id))
        else:
            raise HSAException("Insufficient privilege to retract user from group")

    ###########################################################
    # group access
    ###########################################################

    def _user_access_to_group_exists(self, requesting_id, user_id, group_id):
        """
        Test whether there is an access record for a specific user, group, and asserting user
        :type self: HSAccess
        :type user_id: int
        :type group_id: int
        :type requesting_id: int
        :param user_id: user id of user who needs privilege
        :param group_id: group id of group to which privilege will be assigned
        :param requesting_id: user id of user assigning privilege
        :return:
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

    # utilize a join view to summarize user privilege
    def get_user_privilege_over_group(self, user_uuid, group_uuid):
        """
        Get the privilege that is specified for a user over a specific group
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user for which to obtain privilege
        :param group_uuid: group to which to allow access
        :return: int: privilege code 1-100
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        group_id = self._get_group_id_from_uuid(group_uuid)
        self._cur.execute("""select privilege_id from user_privilege_over_group where user_id=%s and group_id=%s""",
                          (user_id, group_id))
        if self._cur.rowcount > 1:
            raise HSAException("Database integrity violation: more than one protection int for a user and group")
        if self._cur.rowcount > 0:
            return self._cur.fetchone()['privilege_id']
        else:
            return self._PRIVILEGE_NONE  # no privilege

    def group_accessible(self, user_uuid, group_uuid, code):
        """
        Check whether a group is accessible to a user
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :type code: str
        :param user_uuid: uuid of user for whom to check privilege (key to users table)
        :param group_uuid: uuid of group for which to check privilege (key to groups table)
        :param code: privilege code (key to privileges table)
        :return: bool: True if group is accessible to user in the provided mode
        """
        privilege_id = self._get_privilege_id_from_code(code)
        actual_priv = self.get_user_privilege_over_group(user_uuid, group_uuid)
        if actual_priv <= privilege_id:
            return True
        else:
            return False

    def group_is_owned(self, user_uuid, group_uuid):
        """
        Check whether a group is owned by a user
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is owned by user uuid
        """
        return self.group_accessible(user_uuid, group_uuid, 'own')

    def group_is_readwrite(self, user_uuid, group_uuid):
        """
        Check whether a group is owned by a user
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is read/write to user uuid
        """
        return self.group_accessible(user_uuid, group_uuid, 'rw')

    def group_is_readable(self, user_uuid, group_uuid):
        """
        Check whether a group is owned by a user
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: bool: True if group uuid is readable by user uuid
        """
        return self.group_accessible(user_uuid, group_uuid, 'ro')

    def group_is_readable_without_sharing(self, user_uuid, group_uuid):
        """
        Check whether a group is readable without sharing by a user
        :type self: HSAccess
        :type user_uuid: str
        :type group_uuid: str
        :param user_uuid: uuid of user to check
        :param group_uuid: group uuid of group to check
        :return: True if group uuid is readable without sharing to user uuid
        """
        return self.group_accessible(user_uuid, group_uuid, 'ns')

    # CLI: share_group
    def share_group_with_user(self, group_uuid, user_uuid, privilege_code='ns'):
        """
        Attempt to share a group with a user: this allows read/write to the group membership list
        :type self: HSAccess
        :type group_uuid:  str
        :type user_uuid: str
        :type privilege_code: str
        :param group_uuid: group identifier of group to which privilege should be assigned
        :param user_uuid: uuid of user to whom privilege should be granted
        :param privilege_code: privilege to be granted.
        :return: None
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        privilege_id = self._get_privilege_id_from_code(privilege_code)
        group_id = self._get_group_id_from_uuid(group_uuid)
        requesting_id = self._get_user_id_from_uuid(self._user_uuid)
        # access control logic: cannot grant sharing above own privilege
        if not (self.user_is_admin(self._user_uuid)):
            # use join to access privilege records
            user_priv = self.get_user_privilege_over_group(requesting_id, group_id)
            if user_priv >= self._PRIVILEGE_RO:  # read-only or no-sharing
                raise HSAException("Cannot modify a group without read/write privileges")
            else:
                if user_priv > privilege_id:
                    raise HSAException("User has insufficient privilege to share this resource")
        # sufficient privileges present to share this resource
        if self._user_access_to_group_exists(requesting_id, user_id, group_id):
            self._share_group_user_update(requesting_id, user_id, group_id, privilege_id)
        else:
            self._share_group_user_add(requesting_id, user_id, group_id, privilege_id)

    def _share_group_user_update(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: update user access to a group
        :type self: HSAccess
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
        self._cur.execute("""update user_access_to_group set privilege_id = %s,
                          assertion_time=CURRENT_TIMESTAMP where user_id=%s and group_id=%s and assertion_user_id=%s""",
                          (privilege_id, user_id, group_id, requesting_id))
        self._conn.commit()

    def _share_group_user_add(self, requesting_id, user_id, group_id, privilege_id):
        """
        PRIVATE: add new user access for a group
        :type self: HSAccess
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
        self._cur.execute("""insert into user_access_to_group values (DEFAULT, %s, %s, %s, %s, DEFAULT)""",
                          (user_id, group_id, privilege_id, requesting_id))
        self._conn.commit()

    # ##########################################################
    # faceted information retrieval
    # ##########################################################
    # CLI: hs_ls
    def resources_held_by_user(self, user_uuid):
        """
        Make a list of resources held by user, sorted by title
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: List of resources containing dict items
        """
        user_id = self._get_user_id_from_uuid(user_uuid)
        self._cur.execute("""select distinct r.resource_uuid, r.resource_title, r.resource_path
          from user_resource_privilege u
          left join resources r on r.resource_id = u.resource_id
          where user_id=%s order by r.resource_uuid""", (user_id,))
        result = []
        for row in self._cur:
            result.append({'uuid': row['resource_uuid'],
                           'title': row['resource_title'],
                           'path': row['resource_path']})
        return result

    # CLI: hs_groups
    def groups_of_user(self, user_uuid=None):
        """
        Make a list of groups in which a user is a member.
        :type self: HSAccess
        :type user_uuid: str
        :param user_uuid: uuid of user
        :return: list of dict entries, one per group
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
        Create a folder in the user_folders relation
        :param folder_name: The name of the folder
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def retract_folder(self, folder_name):
        """
        Reemove a folder; things in the folder become "unfiled"
        :param folder_name: The name of the folder
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def assert_resource_in_folder(self, resource_uuid, folder_name):
        """
        Put a resource into a previously created folder
        :param resource_uuid: identifier of resource to put into folder
        :param folder_name: name of the folder
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def retract_resource_in_folder(self, resource_uuid, folder_name):
        """
        Remove a resource from a folder; it becomes unfiled.
        :param resource_uuid: identifier of resource to put into folder
        :param folder_name: name of the folder
        :return: None
        """
        return

    def get_folders(self):
        """
        Return a list of folders for this user
        :return: A list of folder names
        Uses: self._user_uuid: current user identity
        """
        return


    def get_resources_in_folders(self, folder=None):
        """
        Get a structured dictionary of folders and their contents
        :param folder: the name of a folder to use
        :return: A dict object of contents
        Uses: self._user_uuid: the current user.
        This returns a dictionary structure of the form
        { folder: { resource_uuid : { title : "resource title", 'access' : "access code" }}}
        If folder is not None, report on only one folder.
        """
        return

    # ##########################################################
    # stubs for tag subsystem
    # ##########################################################
    def assert_tag(self, tag_name):
        """
        Create a tag in the user_tags relation
        :param tag_name: The name of the tag
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def retract_tag(self, tag_name):
        """
        Reemove a tag; things in the tag become "untagged"
        :param tag_name: The name of the tag
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        """
        return

    def assert_resource_has_tag(self, resource_uuid, tag_name):
        """
        Put a resource into a previously created tag
        :param resource_uuid: identifier of resource to put into tag
        :param tag_name: name of the tag
        :return: None
        Uses: self._user_uuid: the identity of the current user.
        Folders are local to the current user.
        Multiple asserts with different tags apply all of them
        """
        return

    def retract_resource_has_tag(self, resource_uuid, tag_name):
        """
        Remove a resource from a tag; it becomes unfiled.
        :param resource_uuid: identifier of resource to put into tag
        :param tag_name: name of the tag
        :return: None
        """
        return

    def get_tags(self):
        """
        Return a list of tags for this user
        :return: A list of tag names
        Uses: self._user_uuid: current user identity
        """
        return

    def get_resources_by_tag(self, tag=None):
        """
        Get a structured dictionary of tags and their contents
        :param tag: the name of a tag to use
        :return: A dict object of contents
        Uses: self._user_uuid: the current user.
        This returns a dictionary structure of the form
        { "tag": { resource_uuid : { title : "resource title", 'access' : "access code" }}}
        If tag argument is not None, report on only one tag.
        """
        return
