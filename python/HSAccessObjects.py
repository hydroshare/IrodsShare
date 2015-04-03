__author__ = 'Alva'

from HSAlib import HSAccess, HSAccessCore, HSAException, HSAccessException, HSAIntegrityException, HSAUsageException
from pprint import pprint

################################################
# a generic object that can kick off basic queries:
# - list users
# - list resources
# and the like.
################################################


class HSAccessObject(object):
    """
    Generic object interface: does not assume anything about user environment
    """

    def __init__(self, hsa):
        self.__hsa = hsa


class HSAccessUser(object):
    """
    Representation of an IrodsShare user, including all actions that apply to a user. 

        * Public methods are always available to the user. 

        * Private methods are made conditionally available through the :py:meth:`get_capabilities` method. 
    """
    def __init__(self, hsa, user_uuid=None):
        """
        Initialize a user object

        :type hsa: HSAccess
        :type user_uuid: str?
        :param hsa: A raw HSAccess object with non-object interface. 
        :param user_uuid: uuid of the user to represent with this object. 

        This stores a primitive HSAccess object as a sub-object and then stores context as to what
        specific user it represents. It reads and caches metadata in order to reduce database calls. 
        """
        self.__hsa = hsa
        if user_uuid is not None:
            self.__uuid = user_uuid
        else:
            self.__uuid = self.__hsa.get_uuid()
        # does an implicit check on uuid validity and raises exception if not valid
        self.__meta = self.__hsa.get_user_metadata(self.__uuid)

    def get_uuid(self):
        """ 
        Get the uuid of the user that this object represents. 

        :return: uuid of current user
        :rtype: str
        """
        return self.__uuid

    def get_login(self):
        """ 
        Get the login name in iRODS of the user that this object represents. 

        :return: login name of current user
        :rtype: str
        """
        return self.__meta['login']

    def get_name(self):
        """ 
        Get the print name of the user that this object represents. 

        :return: print name of current user
        :rtype: str
        """
        return self.__meta['name']

    def is_admin(self):
        """ 
        Return True if user is administrator

        :return: True if current user is an administrator
        :rtype: bool 
        """
        return self.__meta['admin']

    def is_active(self):
        """ 
        Return True if user is active now. 

        :return: True if current user is active. 
        :rtype: bool 
        """
        return self.__meta['active']

    def get_privilege_over_resource(self, resource_uuid):
        """ 
        Get the privilege code for the privilege that this user holds over a given resource

        :type resource_uuid: str
        :param resource_uuid: uuid of the resource to check. 
        :return: one of 'own', 'rw', 'ro', 'none'.
        :rtype: str

        This returns one of the following codes: 

            'own'

                User owns this resource

            'rw'

                User can read and change this resource

            'ro'

                User can read but not change this resource

            'none'

                No privilege over resource
        """
        return self.__hsa.get_user_privilege_over_resource(resource_uuid)

    def get_privilege_over_group(self, group_uuid):
        """ 
        Get the privilege code for the privilege that this user holds over a given group. 

        :type group_uuid: str
        :param group_uuid: uuid of the group to check. 
        :return: one of 'own', 'rw', 'ro', 'none'.
        :rtype: str

        This returns one of the following codes: 

            'own'

                User owns this group.

            'rw'

                User can read and change this group, e.g., by adding members.

            'ro'

                User can read but not change this group, e.g., by listing the users in the group. 

            'none'

                No privilege over group; user cannot see members of the group. 
        """
        return self.__hsa.get_user_privilege_over_group(group_uuid)

    # "__" routines require privilege that is determined by get_capabilities
    def __change_name(self, new_name):
        """ 
        PRIVATE: change the name of a user. 

        :type new_name: str
        :param new_name: new name to assign. 

        This function is exposed via :py:meth:`get_capabilities` as capability key 'change_name'. 
        """
        self.__meta['name'] = new_name
        self.__hsa.assert_user_metadata(self.__meta)

    def __make_active(self):
        """ 
        PRIVATE: make the user active. 

        This makes the user active if not, and does nothing if already active. 

        This function is exposed via :py:meth:`get_capabilities` as capability key 'make_active'. 

        Notes: 

            * Inactive users are prohibited from doing anything. 

            * Only an administrator can make a user active or inactive.
        """
        if self.__meta['active'] is False:
            self.__meta['active'] = True
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_not_active(self):
        """ 
        PRIVATE: make the user inactive. 

        This makes the user inactive if active, and does nothing if already inactive.

        This function is exposed via :py:meth:`get_capabilities` as capability key 'make_not_active'. 

        Notes: 

            * Inactive users are prohibited from doing anything. 

            * Only an administrator can make a user active or inactive.
        """
        if self.__meta['active'] is True:
            self.__meta['active'] = False
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_admin(self):
        """ 
        PRIVATE: make the user an administrator. 

        This makes the user an administrator if not, and does nothing if already an administrator. 

        This function is exposed via :py:meth:`get_capabilities` as capability key 'make_admin'. 

        Notes: 

            * Only an administrator can make a user an administrator.

        """
        if self.__meta['admin'] is False:
            self.__meta['admin'] = True
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_not_admin(self):
        """ 
        PRIVATE: make the user a non-administrator. 

        This makes the user a non-administrator if already an administrator, and does nothing otherwise. 

        This function is exposed via :py:meth:`get_capabilities` as capability key 'make_not_admin'. 

        Notes: 

            * Only an administrator can make a user a non-administrator.

            * **Administrators can do this to themselves, after which they are no longer administrators.**
        """
        if self.__meta['admin'] is True:
            self.__meta['admin'] = False
            self.__hsa.assert_user_metadata(self.__meta)

    # this will only work if the user in question has admin
    def __register_user(self, user_login, user_name, user_active=True, user_admin=False):
        """
        Register a new user; requires administrative privilege. 

        :type user_login: str
        :type user_name: str
        :type user_active: bool
        :type user_admin: bool 
        :param user_login: iRODS login for the user. 
        :param user_name: print name for the new user. 
        :param user_active: whether user is initially active: default is True.
        :param user_admin: whether user is initially an administrator: default is False. 

        This registers a new user, which must already exist in iRODS. 
       
        To modify an already registered user, see other methods, including :py:meth:`_HSAccessObject__change_name`, etc. 
        """
        uuid = self.__hsa.assert_user(user_login, user_name,  user_active, user_admin)
        return HSAccessUser(self.__hsa, uuid)

    # anyone can register a group
    def register_group(self, group_name, group_active=True, group_shareable=True,
                       group_discoverable=True, group_public=True):
        """ 
        Register a new group. 

        :type group_name: str
        :type group_active: bool
        :type group_shareable: bool
        :type group_discoverable: bool
        :type group_public: bool 
        :param group_name: print name of the group, need not be unique. 
        :param group_active: whether the group is active. 
        :param group_shareable: whether the group is shareable, which allows non-owners to invite members. 
        :param group_discoverable: whether the group is discoverable in group listings. 
        :param group_public: whether the group is public, which allows all users to see members. 
        :return: object representing the created group. 
        :rtype: HSAccessGroup 

        Some notes: 
            
            * Group names need not be unique. If one creates two groups in rapid succession with the same 
              name, they will be distinct. 
           
            * Anyone can create a group; this is not a privileged action. 
        """
        uuid = self.__hsa.assert_group(group_name, group_active, group_shareable,
                                       group_discoverable, group_public)
        return HSAccessGroup(self.__hsa, uuid)

    # anyone can register a new resource
    def register_resource(self, resource_path, resource_title,
                          resource_immutable=False, resource_published=False,
                          resource_discoverable=False, resource_public=False,
                          resource_shareable=True):
        """
        Register a new group. 

        :type resource_title: str
        :type resource_immutable: bool
        :type resource_published: bool
        :type resource_discoverable: bool
        :type resource_public: bool 
        :type resource_shareable: bool
        :param resource_title: print name of the group, need not be unique. 
        :param resource_immutable: whether the resource is immutable, which downgrades all privileges to read-only. 
        :param resource_published: whether the resource is published, which means a DOI has been issued. 
        :param resource_discoverable: whether the resource is discoverable in resource listings. 
        :param resource_public: whether the resource is public, which allows all users to read it. 
        :param resource_shareable: whether the resource is shareable, which allows non-owners to share with others. 
        :return: object representing the created resource. 
        :rtype: HSAccessResource

        Some notes: 
            
            * Resource titles need not be unique. If one creates two resources in rapid succession with the same 
              title, they will be distinct. 
           
            * Anyone can create a resource; this is not a privileged action. 
        """
        uuid = self.__hsa.assert_resource(resource_path, resource_title,
                                          resource_immutable=resource_immutable,
                                          resource_published=resource_published,
                                          resource_discoverable=resource_discoverable,
                                          resource_public=resource_public,
                                          resource_shareable=resource_shareable)
        return HSAccessResource(self.__hsa, uuid)

    # obey access control
    def get_groups(self):
        """
        Get groups accessible to a user, along with requisite action links

        :return: List of :py:class:`HSAccessGroup` instances. 
        :rtype: List<HSAccessGroup>

        This gets the list of groups accessible to the current user, as objects. 
        """
        group_uuids = self.__hsa.get_groups_for_user(self.__uuid)
        result = []
        for g in group_uuids:
            result += [HSAccessGroup(self.__hsa, g['uuid'])]
        return result

    # obey access control
    def get_resources(self):
        """
        Get a list of accessible resources, along wih requisite action links

        :return: List of :py:class:`HSAccessResource` instances. 
        :rtype: List<HSAccessResource>

        This gets the list of resources accessible to the current user, as objects. 
        """
        resource_uuids = self.__hsa.get_resources_held_by_user(self.__uuid)
        result = []
        for g in resource_uuids:
            result += [HSAccessResource(self.__hsa, g['uuid'])]
        return result

    # ## ERROR ### def get_group_invitations(self):
    # ## ERROR ###   """
    # ## ERROR ###   Get a list of invitations to join groups, with "accept" and "refuse" buttons
    # ## ERROR ###   """
    # ## ERROR ###   invites = self.__hsa.get_group_invitations_for_user(self.__uuid)
    # ## ERROR ###   results = []
    # ## ERROR ###   for i in invites:
    # ## ERROR ###       results += [HSAccessGroupInvitation(self.__hsa,
    # ## ERROR ###                                           self.__uuid,
    # ## ERROR ###                                           i['group_uuid'],
    # ## ERROR ###                                           i['inviting_user_uuid'])]

    # ## ERROR ### def get_resource_invitations(self):
    # ## ERROR ###     """
    # ## ERROR ###     Get a list of all invitations to own resources, with "accept" and "reject" buttons
    # ## ERROR ###     """
    # ## ERROR ###     pass

    def get_capabilities(self):
        """
        Get the capabilities of this particular user. 

        :return: Dict of capability pairs of form { 'capability_key': bound_method, ... } 
        :rtype: Dict

        This function exposes private methods of :py:class:`HSAccessUser` based upon the 
        capabilities of the represented user. The format of the return value
        is::

            {'capability_key': bound_method, ...}

        This is used via the following pattern::

            caps = Object.get_capabilities() 
            ...
            if 'capability_key' in caps.keys(): 
                caps['capability_key'](...arguments...)

        where arguments are documented below. 

        User capability keys include: 
        
            * 'register_user': register a new user. This requires administrative privilege
              and returns the :py:meth:`HSAccessUser` object corresponding to the new user. 

              See :py:meth:`_HSAccessUser__register_user` for details and calling conventions.

            * 'make_active' and 'make_not_active': control whether a user is active. This requires 
              administrative privilege. There are no arguments. 

            * 'change_name': change the name of a user. This requires either administrative 
              privilege or being that user. There is one parameter: the new name. 
              
              See :py:meth:`_HSAccessUser__change_name` for details. 

        Note: this is not all a user can do. These are simply the "protected" methods that are 
        enabled and disabled according to user privilege. Other methods are available to all users at 
        all times. In general, the private methods of :py:class:`HSAccessObjects.HSAccessUser` are 
        exposed in this fashion while the public methods are always available. 

        Note that violating privacy mechanisms and executing methods directly accomplishes nothing, as these 
        methods are also protected from being executed inappropriately. 
        """
        capabilities = {}
        if self.__hsa.user_is_admin():
            capabilities['register_user'] = self.__register_user
            if self.__meta['admin']:
                capabilities['make_not_admin'] = self.__make_not_admin
            else:
                capabilities['make_admin'] = self.__make_admin
            if self.__meta['active']:
                capabilities['make_not_active'] = self.__make_not_active
            else:
                capabilities['make_active'] = self.__make_active
            capabilities['change_name'] = self.__change_name

        if self.__hsa.get_uuid() == self.__uuid:
            capabilities['change_name'] = self.__change_name

        return capabilities

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
        """
        Pretty-print an HSAccessUser for debugging purposes. 

        :type indent: int
        :param indent: indentation for printout in two-space units. 

        Indentation allows hierarchical listings of sub-objects. 
        """ 
        print self.__spaces(indent), "==========="
        print self.__spaces(indent), "USER RECORD"
        print self.__spaces(indent), "  User uuid: ", self.__uuid
        print self.__spaces(indent), "  User login: ", self.__meta['login']
        print self.__spaces(indent), "  is_active(): ", self.is_active()
        print self.__spaces(indent), "  is_admin(): ", self.is_admin()
        print self.__spaces(indent), "  get_capabilities(): "
        for n in self.get_capabilities().keys():
            print self.__spaces(indent+3), n
        print self.__spaces(indent), "  get_groups(): "
        for n in self.get_groups():
            print self.__spaces(indent+3), "uuid: ", n.get_uuid(), \
                " priv: ", n.get_privilege(), \
                " name: ", n.get_name()
        print self.__spaces(indent), "  get_resources(): "
        for n in self.get_resources():
            print self.__spaces(indent+3), "uuid: ", n.get_uuid(), \
                " priv: ", n.get_privilege(), \
                " name: ", n.get_title()

# there is a basic question as to how to handle these objects.
# there really should be only one connection for all objects.
# but if that connection changes, havoc results.
# objects should be self-aware of their capabilities.
# perhaps we should deal with reflection separately
# and instantiate all methods as static?
# via get_capabilities?


class HSAccessGroup(object):
    """
    Represent a group as a python object

    This is a simple reflection interface that informs one as to whether group operations are possible
    """
    def __init__(self, hsa, uuid):
        """
        Initialize a group object

        :type hsa: HSAccess
        :type uuid: str
        :param hsa: raw access object: instance of HSAccess. 
        :param uuid: uuid of group to represent. 
        """
        self.__hsa = hsa
        self.__uuid = uuid
        self.__meta = self.__hsa.get_group_metadata(self.__uuid)
        self.__priv_cum = self.__hsa.get_cumulative_user_privilege_over_group(self.__uuid)
        self.__priv_prim = self.__hsa.get_user_privilege_over_group(self.__uuid)
        self.__member = self.__hsa.user_in_group(self.__uuid)

    def get_uuid(self):
        """ 
        Get the uuid of the group that this object represents. 

        :return: uuid of current group
        :rtype: str
        """
        return self.__uuid

    def get_privilege(self):
        """
        Get privilege of current user over group. 

        :return: one of 'own', 'rw', 'ro', 'none'.
        :rtype: str

        This returns one of the following codes: 

            'own'

                User owns this resource

            'rw'

                User can read and change this resource

            'ro'

                User can read but not change this resource

            'none'

                No privilege over resource
        """
        return self.__priv_cum

    def get_name(self):
        """ 
        Get the name of the group that this object represents. 

        :return: name of current group
        :rtype: str
        """
        return self.__meta['name']

    # human relationships
    def get_owners(self):
        """
        Get owners of the current group as HSAccessUser instances 

        :return: List of HSAccessUser instances. 
        :rtype: List<HSAccessUser> 
        """
        mems = self.__hsa.get_group_members(self.__uuid)
        results = []
        for m in mems:
            if m['code'] is 'own':
                results += [HSAccessUser(self.__hsa, m['uuid'])]
        return results

    def __get_members(self):  # users who hold resource
        """
        Get members of the current group as HSAccessUser instances 

        :return: List of HSAccessUser instances. 
        :rtype: List<HSAccessUser> 

        This is a privileged routine made accessible by :py:meth:`get_capabilities`. 
        """
        mems = self.__hsa.get_group_members(self.__uuid)
        results = []
        for m in mems:
            results += [HSAccessUser(self.__hsa, m['uuid'])]
        return results

    def __get_resources(self):  # resources held by group
        """
        Get resources held by group as HSAccessResource instances 

        :return: List of HSAccessResource instances. 
        :rtype: List<HSAccessResource> 

        This is a privileged routine made accessible by :py:meth:`get_capabilities`. 
        """
        res = self.__hsa.get_resources_held_by_group(self.__uuid)
        results = []
        for m in res:
            results += [HSAccessResource(self.__hsa, m['uuid'])]
        return results

    # privileges
    def is_readable(self):
        """
        Return True if group is readable (i.e., members are exposed). 

        :return: True if group is readable. 
        :rtype: bool
        """
        return self.__priv_cum == 'ro' or self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    def is_writeable(self):
        """
        Return True if group is writeable (i.e., user can add members). 

        :return: True if group is writeable.
        :rtype: bool
        """
        return self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    def is_owned(self):
        """
        Return True if group is owned by the current user.

        :return: True if group is owned by current user. 
        :rtype: bool
        """
        return self.__priv_cum == 'own'

    def is_discoverable(self):
        """
        Return True if group is discoverable by non-members. 

        :return: True if group is discoverable. 
        :rtype: bool
        """
        return self.__meta['discoverable']

    def is_public(self):
        """
        Return True if group members are exposed to non-members. 

        :return: True if group is public. 
        :rtype: bool
        """
        return self.__meta['public']

    def is_active(self):
        """
        Return True if group is active. 

        :return: True if group is active. 
        :rtype: bool

        Note: inactive groups do not affect privilege over resources. 
        """
        return self.__meta['active']

    def is_shareable(self):
        """
        Return True if group is shareable. 

        :return: True if group is shareable. 
        :rtype: bool

        If a group is shareable, non-owners can invite new members. 
        """
        return self.__meta['shareable']

    def is_member(self):
        """
        Return True if current user is a member of the group. 

        :return: True if current user is a member. 
        :rtype: bool
        """
        return self.__member

    def get_capabilities(self):
        """
        Get the capabilities of our user over this group. 

        :return: Dict of capability pairs of form { 'capability_key': bound_method, ... } 
        :rtype: Dict 

        This function exposes private methods of :py:class:`HSAccessUser` based upon the 
        capabilities of the represented user. The format of the return value
        is::

            {'capability_key': bound_method, ...}

        This is used via the following pattern::

            caps = Object.get_capabilities() 
            ...
            if 'capability_key' in caps.keys(): 
                caps['capability_key'](...arguments...)

        where arguments are documented below. 

        User capability keys include: 
        
            * 'make_shareable' and 'make_not_shareable' control whether group members can invite others. 
              User must be group owner or administrator. 

            * 'make_discoverable' and 'make_not_discoverable' control whether other users can see the
              group in public listings. User must be group owner or administrator. 

            * 'make_public' and 'make_not_public' control whether other users can see the members of the 
              group in public listings. User must be group owner or administrator. 

            * 'make_active' and 'make_not_active': control whether the group is active. This requires 
              administrative privilege. 

            * 'get_members' makes a listing of :py:class:`HSAccessUser` instances representing members of the group. 

              See :py:meth:`_HSAccessGroup__get_members` for details. 

            * 'get_resources' makes a listing of :py:class:`HSAccessResource` instances representing resources 
              shared with the group. 

              See :py:meth:`_HSAccessGroup__get_resources` for details. 

            * 'change_name': change the name of the group. User must be either group owner or an administrator. 
              There is one parameter: the new name. 
              
              See :py:meth:`_HSAccessGroup__change_name` for details. 

            * 'share_with_user': add a new user to the group, immediately. User must be group owner or administrator, 
              or group must be shareable. 

              There is one parameter: the :py:class:`HSAccessUser` with which to share the group. 
              
              See :py:meth:`_HSAccessGroup__share_with_user` for details. 

        Note: this is not all a user can do. These are simply the "protected" methods that are 
        enabled and disabled according to user privilege. Other methods are available to all users at 
        all times. In general, the private methods of :py:class:`HSAccessObjects.HSAccessGroup` are 
        exposed in this fashion while the public methods are always available. 

        Note that violating privacy mechanisms and executing methods directly accomplishes nothing, as these 
        methods are also protected from being executed inappropriately. 
        """
        capabilities = {}
        if not self.__hsa.user_is_active():
            return {}
        # if the user is administrator or owner, then can set flags
        if self.__hsa.user_is_admin() or self.is_owned():
            capabilities['change_name'] = self.__change_name
            if self.is_discoverable():
                capabilities['make_not_discoverable'] = self.__make_not_discoverable
            else:
                capabilities['make_discoverable'] = self.__make_discoverable
            if self.is_public():
                capabilities['make_not_public'] = self.__make_not_public
            else:
                capabilities['make_public'] = self.__make_public
            if self.is_shareable():
                capabilities['make_not_shareable'] = self.__make_not_shareable
            else:
                capabilities['make_shareable'] = self.__make_shareable

        if self.__hsa.user_is_admin() or self.is_owned() or self.is_shareable():
            capabilities['share_with_user'] = self.__share_with_user
            # capabilities['invite_user'] = self.__invite_user

        if self.__hsa.user_is_admin() or self.is_member() or self.is_public():
            capabilities['get_members'] = self.__get_members

        if self.__hsa.user_is_admin() or self.is_member():
            capabilities['get_resources'] = self.__get_resources

        return capabilities

    def __change_name(self, new_name):
        """
        Change the name of a group.

        :type new_name: str
        :param new_name: new name to use. 

        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__meta['name'] = new_name
        self.__hsa.assert_group_metadata(self.__meta)

    def __make_shareable(self):
        """
        Make a group shareable. 

        This means that non-owners can invite group members. 
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def __make_not_shareable(self):
        """
        Make a group not shareable. 

        This means that non-owners cannot invite group members. 
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def __make_public(self):
        """
        Make a group public. 

        This means that non-members can see group members.
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_public(self.__uuid)
        self.__meta['public'] = True

    def __make_not_public(self):
        """
        Make a group not public. 

        This means that non-members cannot see group members.
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_discoverable(self):
        """
        Make a group discoverable. 

        This means that non-members can discover the group in group listings. 
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_discoverable(self.__uuid)
        self.__meta['discoverable'] = True

    def __make_not_discoverable(self):
        """
        Make a group not discoverable. 

        This means that non-members cannot discover the group in group listings. 
        User must be owner or administrator. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.make_group_not_discoverable(self.__uuid)
        self.__meta['discoverable'] = False

    # need to store allowable privilege codes somewhere; otherwise this will throw exceptions
    def __share_with_user(self, user, privilege_code):
        """
        Share a group with a user immediately. 

        :type user: HSAccessUser
        :type privilege_code: str
        :param user: user to be added to the group. 
        :param privilege_code: one of 'own', 'rw', 'ro', 'none'. 

        This routine is exposed via :py:meth:`get_capabilities`.
        """
        self.__hsa.share_group_with_user(self.__uuid, user.get_uuid(), privilege_code)

    # ## ERROR ### def __invite_user(self, user, privilege_code):
    # ## ERROR ###     self.__hsa.invite_user_to_group(self.__uuid, user.get_uuid(), privilege_code)

    # ## ERROR ### def get_invited_users(self):
    # ## ERROR ###     # this returns ALL invitations sent by the user.
    # ## ERROR ###     # we want the ones for this group specifically
    # ## ERROR ###     # THIS IS DEFINITELY WRONG
    # ## ERROR ###     invites = self.__hsa.get_group_invitations_sent_by_user()
    # ## ERROR ###     pprint(invites)
    # ## ERROR ###     results = []
    # ## ERROR ###     for u in invites:
    # ## ERROR ###         # limit to this specific group
    # ## ERROR ###         if u['group_uuid'] is self.__uuid:
    # ## ERROR ###             results += [HSAccessGroupInvitation(self.__hsa,
    # ## ERROR ###                                                 u['user_uuid'],
    # ## ERROR ###                                                 u['group_uuid'],
    # ## ERROR ###                                                 u['inviting_user_uuid'])]
    # ## ERROR ###     return results

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
        """
        Pretty-print an HSAccessGroup for debugging purposes. 

        :type indent: int
        :param indent: indentation for printout in two-space units. 

        Indentation allows hierarchical listings of sub-objects. 
        """ 
        print self.__spaces(indent), "============"
        print self.__spaces(indent), "GROUP RECORD"
        print self.__spaces(indent), "  Group uuid: ", self.get_uuid()
        print self.__spaces(indent), "  Group name: ", self.get_name()
        print self.__spaces(indent), "  Granted privilege: ", self.__priv_prim
        print self.__spaces(indent), "  Cumulative privilege: ", self.__priv_cum
        print self.__spaces(indent), "  is_active(): ", self.is_active()
        print self.__spaces(indent), "  is_discoverable(): ", self.is_discoverable()
        print self.__spaces(indent), "  is_public(): ", self.is_public()
        print self.__spaces(indent), "  is_shareable(): ", self.is_shareable()
        print self.__spaces(indent), "  get_capabilities(): "
        for n in self.get_capabilities().keys():
            print self.__spaces(indent+3), n
        print self.__spaces(indent), "  get_members(): "
        for n in self.__get_members():
            print self.__spaces(indent+3), "uuid: ", n.get_uuid(), " priv: ", " name: ", n.get_name()
        print self.__spaces(indent), "  get_resources(): "
        for n in self.__get_resources():
            print self.__spaces(indent+3), "uuid: ", n.get_uuid(), " priv: ", n.get_privilege(), " name: ", n.get_title()


class HSAccessGroupInvitation(HSAccessGroup):
    """
    Represent an invitation to join a group in  a two-phase transaction. 
    """

    def __init__(self, hsa, user_uuid, group_uuid, inviting_user_uuid):
        HSAccessGroup.__init__(self, hsa, group_uuid)
        self.__inviting_user_uuid = inviting_user_uuid
        self.__target_user_uuid = user_uuid

    # all one can do with an invitation is to accept or refuse it.
    # after acceptance, other things become possible
    def get_capabilities(self):
        """
        Get the capabilities of our user over this invitation. 

        :return: Dict of capability pairs of form { 'capability_key': bound_method, ... } 
        :rtype: Dict 

        This function exposes private methods of :py:class:`HSAccessUser` based upon the 
        capabilities of the represented user. The format of the return value
        is::

            {'capability_key': bound_method, ...}

        This is used via the following pattern::

            caps = Object.get_capabilities() 
            ...
            if 'capability_key' in caps.keys(): 
                caps['capability_key'](...arguments...)

        where arguments are documented below. 

        User capability keys include: 
        
            * 'accept' and 'refuse' act on an invitation to accept or refuse it. There are no parameters. 

        Note that violating privacy mechanisms and executing methods directly accomplishes nothing, as these 
        methods are also protected from being executed inappropriately. 
        """
        return {'accept': self.__accept, 'refuse': self.__refuse}

    def __accept(self):
        """
        Accept an invitation to a group. 
        """
        self.__hsa.accept_invitation_to_group(self.__uuid, self.__inviting_user_uuid)

    def __refuse(self):
        """
        Refuse an invitation to a group. 
        """
        self.__hsa.refuse_invitation_to_group(self.__uuid, self.__inviting_user_uuid)


class HSAccessResource(object):
    """
    Represent a resource as a python object

    This is a simple reflection interface that informs one as to whether resource operations are possible
    """
    def __init__(self, hsa, uuid):
        """
        Initialize a resource object

        :type hsa: HSAccess
        :type uuid: str: 
        :param hsa: Object describing the current (primitive) session.
        :param uuid: uuid of resource. 

        This builds a resource object from a resource uuid, and caches the state of the 
        resource to save time during rendering. 
        """
        self.__hsa = hsa
        self.__uuid = uuid
        self.__meta = self.__hsa.get_resource_metadata(self.__uuid)
        self.__priv_cum = self.__hsa.get_cumulative_user_privilege_over_resource(self.__uuid)
        self.__priv_prim = self.__hsa.get_user_privilege_over_resource(self.__uuid)

    # these routines are available to all users
    def get_uuid(self):
        """
        Get uuid of the current resource. 
       
        :return: uuid of current resource. 
        :rtype: str
        """
        return self.__uuid

    def get_title(self):
        """
        Get title of the current resource. 
       
        :return: title of current resource. 
        :rtype: str
        """
        return self.__meta['title']

    def get_path(self):
        """
        Get file path of the current resource. 
       
        :return: file path of current resource. 
        :rtype: str
        """
        return self.__meta['path']

    def get_privilege(self):
        """
        Get privilege of current user over resource.
       
        :return: 'own', 'rw', 'ro', 'none' (for public resources) 
        :rtype: str
        """
        return self.__priv_cum

    def is_readable(self):
        """
        True if resource is readable.
       
        :return: True if resource is readable 
        :rtype: int
        """

        return self.__priv_cum == 'ro' or self.__priv_cum == 'rw' or self.__priv_cum == 'ro'

    def is_writeable(self):
        """
        True if resource is writeable.
       
        :return: True if resource is writeable 
        :rtype: int
        """
        return self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    # immutability can override cumulative ownership; must check separately.
    def is_owned(self):
        """
        True if resource is owned by the currently authenticated user. 
       
        :return: True if resource is owned by the currently authenticated user. 
        :rtype: int
        """
        return self.__priv_prim == 'own'

    def is_discoverable(self):
        """
        True if resource is discoverable by the currently authenticated user. 
       
        :return: True if resource is discoverable by the currently authenticated user. 
        :rtype: int
        """
        return self.__meta['discoverable']

    def is_public(self):
        """
        True if resource is public.
       
        :return: True if resource is public.
        :rtype: int
        """
        return self.__meta['public']

    def is_published(self):
        """
        True if resource is published and has a DOI. 
       
        :return: True if resource is published and has a DOI
        :rtype: int
        """
        return self.__meta['published']

    def is_shareable(self):
        """
        True if resource is shareable by non-owners. 
       
        :return: True if resource is shareable by non-owners. 
        :rtype: int
        """
        return self.__meta['shareable']

    def is_immutable(self):
        """
        True if resource is immutable. 
       
        :return: True if resource is immutable. This overrides normal ownership privileges. 
        :rtype: int
        """
        return self.__meta['immutable']

    def get_capabilities(self):
        """
        Get the capabilities of our user over this resource. 

        :return: Dict of capability pairs of form { 'capability_key': bound_method, ... } 
        :rtype: Dict 

        This function exposes private methods of :py:class:`HSAccessResource` based upon the 
        capabilities of the current user. The format of the return value
        is::

            {'capability_key': bound_method, ...}

        This is used via the following pattern::

            caps = Object.get_capabilities() 
            ...
            if 'capability_key' in caps.keys(): 
                caps['capability_key'](...arguments...)

        where arguments are documented below. 

        User capability keys include: 
        
            * 'make_shareable' and 'make_not_shareable' control whether users and group members with access 
              can share that access with others. User must be resource owner or administrator. 

            * 'make_discoverable' and 'make_not_discoverable' control whether other users can see the
              resource in public listings. User must be resource owner or administrator. 

            * 'make_public' and 'make_not_public' control whether other users can read the contents of the resource. 
              User must be group owner or administrator. 

            * 'make_published' and 'make_not_published' indicate whether a DOI has been generated for the 
              the resource.  User must be resource owner or administrator. 

            * 'make_immutable' and 'make_not_immutable' indicate whether the resource should be considered
              read-only to all users.  User must be resource owner or administrator. 

            * 'get_users' makes a listing of :py:class:`HSAccessUser` instances representing users with 
              access to the resource. 

              See :py:meth:`_HSAccessResource__get_users` for details. 

            * 'get_groups' makes a listing of :py:class:`HSAccessGroup` instances representing groups with 
              access to the resource::

                resource.get_capabilities['get_groups']()

              See :py:meth:`_HSAccessResource__get_groups` for details. 

            * 'change_name': change the name of the resource. User must be either resource owner or an administrator. 
              There is one parameter: the new name::

                resource.get_capabilities['change_name'](*new_name*)
              
              See :py:meth:`_HSAccessGroup__change_name` for details. 

            * 'share_with_user': share the resource with a new user, immediately. 
              User must be resource owner or administrator, or resource must be shareable. 
              There is one parameter: the :py:class:`HSAccessUser` with which to share the resource. Usage::

                resource.get_capabilities['share_with_user'](*user_object*, *privilege_word*) 
              
              where privilege_word is one of 'own', 'rw', 'ro', or 'none'. 

              See :py:meth:`_HSAccessResource__share_with_user` for details. 

            * 'share_with_group': share the resource with a new group, immediately. 
              User must be resource owner or administrator, or resource must be shareable. 
              There is one parameter: the :py:class:`HSAccessGroup` with which to share the resource. 

                resource.get_capabilities()['share_with_group'](*group_object*)
              
              See :py:meth:`_HSAccessResource__share_with_group` for details. 

        Note: this is not all a user can do. These are simply the "protected" methods that are 
        enabled and disabled according to user privilege. Other methods are available to all users at 
        all times. In general, the private methods of :py:class:`HSAccessObjects.HSAccessGroup` are 
        exposed in this fashion while the public methods are always available. 

        Note that violating privacy mechanisms and executing methods directly accomplishes nothing, as these 
        methods are also protected from being executed inappropriately. 
        """
        capabilities = {}
        if not self.__hsa.user_is_active():
            return {}
        # if the user is administrator or owner, then can set flags

        if self.__hsa.user_is_admin() or self.is_owned():
            capabilities['change_title'] = self.__change_title
            capabilities['get_users'] = self.__get_users
            capabilities['get_groups'] = self.__get_groups

            if self.is_discoverable():
                capabilities['make_not_discoverable'] = self.__make_not_discoverable
            else:
                capabilities['make_discoverable'] = self.__make_discoverable

            if self.is_public():
                capabilities['make_not_public'] = self.__make_not_public
            else:
                capabilities['make_public'] = self.__make_public

            if self.is_shareable():
                capabilities['make_not_shareable'] = self.__make_not_shareable
            else:
                capabilities['make_shareable'] = self.__make_shareable

            if not self.is_published():
                capabilities['make_published'] = self.__make_published

            if not self.is_immutable():
                capabilities['make_immutable'] = self.__make_immutable

        if self.is_owned() or self.is_shareable():
            capabilities['share_with_user'] = self.__share_with_user
            capabilities['share_with_group'] = self.__share_with_group

        return capabilities

    # "__" routines are limited via access control

    def __get_users(self):
        """
        Get the list of HSAccessUsers currently holding this resource. 

        :return: List of :py:class:`HSAccessUser`
        :rtype: List<HSAccessUser> 
        """
        users = self.__hsa.get_users_holding_resource(self.__uuid)
        result = []
        for u in users:
            result += [HSAccessUser(self.__hsa, u['uuid'])]
        return result

    def __get_groups(self):
        """
        Get the list of HSAccessGroups currently holding this resource. 

        :return: List of :py:class:`HSAccessGroup`
        :rtype: List<HSAccessGroup> 
        """
        groups = self.__hsa.get_groups_holding_resource(self.__uuid)
        result = []
        for u in groups:
            result += [HSAccessGroup(self.__hsa, u['uuid'])]
        return result

    def __change_title(self, new_name):
        """
        Change title of a resource.

        :param new_name: new name to use for title. 
        :type new_name: str
        """
        self.__meta['title'] = new_name
        self.__hsa.assert_resource_metadata(self.__meta)

    def __make_shareable(self):
        """
        Make the current resource shareable. 
        """
        self.__hsa.make_resource_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def __make_not_shareable(self):
        """
        Make the current resource not shareable. 
        """
        self.__hsa.make_resource_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def __make_public(self):
        """
        Make the current resource public. 
        """
        self.__hsa.make_resource_public(self.__uuid)
        self.__meta['public'] = True

    def __make_not_public(self):
        """
        Make the current resource not public. 
        """
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_published(self):
        """
        Make the current resource published. 
        """
        self.__hsa.make_resource_published(self.__uuid)
        self.__meta['published'] = True

    def make_not_published(self):
        """
        Make the current resource not published. 
        """
        self.__hsa.make_resource_not_published(self.__uuid)
        self.__meta['published'] = False

    def __make_discoverable(self):
        """
        Make the current resource discoverable. 
        """
        self.__hsa.make_resource_public(self.__uuid)
        self.__meta['public'] = True

    def __make_not_discoverable(self):
        """
        Make the current resource not discoverable. 
        """
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_immutable(self):
        """
        Make the current resource immutable. 
        """
        self.__hsa.make_resource_immutable(self.__uuid)
        self.__meta['immutable'] = True

    # need to store allowable privilege codes somewhere
    def __share_with_user(self, user, privilege_code):
        """
        Share this resource with a user.

        :param user: :py:class:`HSAccessUser` object describing the user 
        :param privilege_code: one of 'own', 'rw', 'ro', 'none'. 
        :type user: HSAccessUser
        :type privilege_code: str

        """
        self.__hsa.share_resource_with_user(self.__uuid, user.get_uuid(), privilege_code)

    def __share_with_group(self, group, privilege_code):
        """
        Share this resource with a group.

        :param group: :py:class:`HSAccessGroup` object describing the group 
        :param privilege_code: one of 'own', 'rw', 'ro', 'none'. 
        :type group: HSAccessGroup
        :type privilege_code: str

        """
        self.__hsa.share_resource_with_group(self.__uuid, group.get_uuid(), privilege_code)

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
        """
        Pretty-print an HSAccessResource for debugging purposes. 

        :type indent: int
        :param indent: indentation for printout in two-space units. 

        Indentation allows hierarchical listings of sub-objects. 
        """ 
        print self.__spaces(indent), "==============="
        print self.__spaces(indent), "RESOURCE RECORD"
        print self.__spaces(indent), "  Resource uuid: ", self.get_uuid()
        print self.__spaces(indent), "  Resource title: ", self.get_title()
        print self.__spaces(indent), "  Resource path: ", self.get_path()
        print self.__spaces(indent), "  Granted privilege: ", self.__priv_prim
        print self.__spaces(indent), "  Cumulative privilege: ", self.__priv_cum
        print self.__spaces(indent), "  is_public(): ", self.is_public()
        print self.__spaces(indent), "  is_immutable(): ", self.is_immutable()
        print self.__spaces(indent), "  is_shareable(): ", self.is_shareable()
        print self.__spaces(indent), "  get_capabilities():"
        for n in self.get_capabilities().keys():
            print self.__spaces(indent+3), n

        print self.__spaces(indent), "  get_users(): "
        for n in self.__get_users():
            print self.__spaces(indent+3), \
                "uuid: ", n.get_uuid(), \
                " priv: ", n.get_privilege_over_resource(self.__uuid), \
                " name: ", n.get_name()

        print self.__spaces(indent), "  get_groups(): "
        for n in self.__get_groups():
            print self.__spaces(indent+3), \
                "uuid: ", n.get_uuid(), \
                " priv: ", n.get_privilege_over_group(self.__uuid, n.get_uuid()), \
                " name: ", n.get_name()

