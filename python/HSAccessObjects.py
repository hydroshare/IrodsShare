__author__ = 'Alva'

from HSAlib import HSAccess, HSAccessCore, HSAException, HSAccessException, HSAIntegrityException, HSAUsageException
from pprint import pprint

def __spaces(self, indent=0):
    s = ""
    for i in [n for n in range(1, indent)]:
        s += ' '
    return s

################################################
# a generic object that can kick off basic queries:
# - list users
# - list resources
# and the like.
################################################


class HSAccessObject(object):
    def __init__(self, hsa):
        self.__hsa = hsa


class HSAccessUser(object):
    def __init__(self, hsa, user_uuid=None):
        """
        Initialize a user object

        :type hsa: HSAccess
        :type user_uuid: str?
        :return: None
        """
        self.__hsa = hsa
        if user_uuid is not None:
            self.__uuid = user_uuid
        else:
            self.__uuid = self.__hsa.get_uuid()
        # does an implicit check on uuid validity and raises exception if not valid
        self.__meta = self.__hsa.get_user_metadata(self.__uuid)

    def get_uuid(self):
        return self.__uuid

    def get_login(self):
        return self.__meta['login']

    def get_name(self):
        return self.__meta['name']

    def is_admin(self):
        return self.__meta['admin']

    def is_active(self):
        return self.__meta['active']

    def get_privilege_over_resource(self, resource_uuid):
        return self.__hsa.get_user_privilege_over_resource(resource_uuid)

    def get_privilege_over_group(self, group_uuid):
        return self.__hsa.get_user_privilege_over_group(group_uuid)

    # "__" routines require privilege that is determined by get_capabilities
    def __change_name(self, new_name):
        self.__meta['name'] = new_name
        self.__hsa.assert_user_metadata(self.__meta)

    def __make_active(self):
        if self.__meta['active'] is False:
            self.__meta['active'] = True
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_not_active(self):
        if self.__meta['active'] is True:
            self.__meta['active'] = False
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_admin(self):
        if self.__meta['admin'] is False:
            self.__meta['admin'] = True
            self.__hsa.assert_user_metadata(self.__meta)

    def __make_not_admin(self):
        if self.__meta['admin'] is True:
            self.__meta['admin'] = False
            self.__hsa.assert_user_metadata(self.__meta)

    # this will only work if the user in question has admin
    def __register_user(self, user_login, user_name, user_active=True, user_admin=False):
        uuid = self.__hsa.assert_user(user_login, user_name,  user_active, user_admin)
        return HSAccessUser(self.__hsa, uuid)

    # anyone can register a group
    def register_group(self, group_name, group_active=True, group_shareable=True,
                       group_discoverable=True, group_public=True):
        uuid = self.__hsa.assert_group(group_name, group_active, group_shareable,
                                       group_discoverable, group_public)
        return HSAccessGroup(self.__hsa, uuid)

    # anyone can register a new resource
    def register_resource(self, resource_path, resource_title,
                          resource_immutable=False, resource_published=False,
                          resource_discoverable=False, resource_public=False,
                          resource_shareable=True):
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

        There is a fundamental difference between HSAccessUser.get_* and
        HSAccessObject.get_*. The former sees what a user sees, while the latter
        sees only what the user would see in this situation.
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

        This gets the list of resources accessible to a specific user.
        """
        resource_uuids = self.__hsa.get_resources_held_by_user(self.__uuid)
        result = []
        for g in resource_uuids:
            result += [HSAccessResource(self.__hsa, g['uuid'])]
        return result

    ### ERROR ### def get_group_invitations(self):
    ### ERROR ###   """
    ### ERROR ###   Get a list of invitations to join groups, with "accept" and "refuse" buttons
    ### ERROR ###   """
    ### ERROR ###   invites = self.__hsa.get_group_invitations_for_user(self.__uuid)
    ### ERROR ###   results = []
    ### ERROR ###   for i in invites:
    ### ERROR ###       results += [HSAccessGroupInvitation(self.__hsa,
    ### ERROR ###                                           self.__uuid,
    ### ERROR ###                                           i['group_uuid'],
    ### ERROR ###                                           i['inviting_user_uuid'])]

    ### ERROR ### def get_resource_invitations(self):
    ### ERROR ###     """
    ### ERROR ###     Get a list of all invitations to own resources, with "accept" and "reject" buttons
    ### ERROR ###     """
    ### ERROR ###     pass

    def get_capabilities(self):
        caps = {}
        if self.__hsa.user_is_admin():
            caps['register_user'] = self.__register_user
            if self.__meta['admin']:
                caps['make_not_admin'] = self.__make_not_admin
            else:
                caps['make_admin'] = self.__make_admin
            if self.__meta['active']:
                caps['make_not_active'] = self.__make_not_active
            else:
                caps['make_active'] = self.__make_active
            caps['change_name'] = self.__change_name

        if self.__hsa.get_uuid() == self.__uuid:
            caps['change_name'] = self.__change_name

        return caps

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
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
        :returns: None
        """
        self.__hsa = hsa
        self.__uuid = uuid
        self.__meta = self.__hsa.get_group_metadata(self.__uuid)
        self.__priv_cum = self.__hsa.get_cumulative_user_privilege_over_group(self.__uuid)
        self.__priv_prim = self.__hsa.get_user_privilege_over_group(self.__uuid)
        self.__member = self.__hsa.user_in_group(self.__uuid)

    def get_uuid(self):
        return self.__uuid

    def get_privilege(self):
        return self.__priv_cum

    def get_name(self):
        return self.__meta['name']

    # human relationships
    def get_owners(self):
        mems = self.__hsa.get_group_members(self.__uuid)
        results = []
        for m in mems:
            if m['code'] is 'own':
                results += [HSAccessUser(self.__hsa, m['uuid'])]
        return results

    def __get_members(self):  # users who hold resource
        mems = self.__hsa.get_group_members(self.__uuid)
        results = []
        for m in mems:
            results += [HSAccessUser(self.__hsa, m['uuid'])]
        return results

    def __get_resources(self):  # resources held by group
        res = self.__hsa.get_resources_held_by_group(self.__uuid)
        results = []
        for m in res:
            results += [HSAccessResource(self.__hsa, m['uuid'])]
        return results

    # privileges
    def is_readable(self):
        return self.__priv_cum == 'ro' or self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    def is_writeable(self):
        return self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    def is_owned(self):
        return self.__priv_cum == 'own'

    def is_discoverable(self):
        return self.__meta['discoverable']

    def is_public(self):
        return self.__meta['public']

    def is_active(self):
        return self.__meta['active']

    def is_shareable(self):
        return self.__meta['shareable']

    def is_member(self):
        return self.__member

    def get_capabilities(self):
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
        self.__meta['name'] = new_name
        self.__hsa.assert_group_metadata(self.__meta)

    def __make_shareable(self):
        self.__hsa.make_group_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def __make_not_shareable(self):
        self.__hsa.make_group_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def __make_public(self):
            self.__hsa.make_group_public(self.__uuid)
            self.__meta['public'] = True

    def __make_not_public(self):
        self.__hsa.make_group_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_discoverable(self):
            self.__hsa.make_group_discoverable(self.__uuid)
            self.__meta['discoverable'] = True

    def __make_not_discoverable(self):
        self.__hsa.make_group_not_discoverable(self.__uuid)
        self.__meta['discoverable'] = False

    # need to store allowable privilege codes somewhere; otherwise this will throw exceptions
    def __share_with_user(self, user, privilege_code):
        self.__hsa.share_group_with_user(self.__uuid, user.get_uuid(), privilege_code)

    ### ERROR ### def __invite_user(self, user, privilege_code):
    ### ERROR ###     self.__hsa.invite_user_to_group(self.__uuid, user.get_uuid(), privilege_code)

    ### ERROR ### def get_invited_users(self):
    ### ERROR ###     # this returns ALL invitations sent by the user.
    ### ERROR ###     # we want the ones for this group specifically
    ### ERROR ###     # THIS IS DEFINITELY WRONG
    ### ERROR ###     invites = self.__hsa.get_group_invitations_sent_by_user()
    ### ERROR ###     pprint(invites)
    ### ERROR ###     results = []
    ### ERROR ###     for u in invites:
    ### ERROR ###         # limit to this specific group
    ### ERROR ###         if u['group_uuid'] is self.__uuid:
    ### ERROR ###             results += [HSAccessGroupInvitation(self.__hsa,
    ### ERROR ###                                                 u['user_uuid'],
    ### ERROR ###                                                 u['group_uuid'],
    ### ERROR ###                                                 u['inviting_user_uuid'])]
    ### ERROR ###     return results

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
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

    def __init__(self, hsa, user_uuid, group_uuid, inviting_user_uuid):
        HSAccessGroup.__init__(self, hsa, group_uuid)
        self.__inviting_user_uuid = inviting_user_uuid
        self.__target_user_uuid = user_uuid

    # all one can do with an invitation is to accept or refuse it.
    # after acceptance, other things become possible
    def get_capabilities(self):
        return {'accept': self.__accept, 'refuse': self.refuse}

    def __accept(self):
        self.__hsa.accept_invitation_to_group(self.__uuid, self.__inviting_user_uuid)

    def refuse(self):
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
        :type uuid: str
        :returns: None
        """
        self.__hsa = hsa
        self.__uuid = uuid
        self.__meta = self.__hsa.get_resource_metadata(self.__uuid)
        self.__priv_cum = self.__hsa.get_cumulative_user_privilege_over_resource(self.__uuid)
        self.__priv_prim = self.__hsa.get_user_privilege_over_resource(self.__uuid)

    # these routines are available to all users
    def get_uuid(self):
        return self.__uuid

    def get_title(self):
        return self.__meta['title']

    def get_path(self):
        return self.__meta['path']

    def get_privilege(self):
        return self.__priv_cum

    def is_readable(self):
        return self.__priv_cum == 'ro' or self.__priv_cum == 'rw' or self.__priv_cum == 'ro'

    def is_writeable(self):
        return self.__priv_cum == 'rw' or self.__priv_cum == 'own'

    # immutability can override cumulative ownership; must check separately.
    def is_owned(self):
        return self.__priv_prim == 'own'

    def is_discoverable(self):
        return self.__meta['discoverable']

    def is_public(self):
        return self.__meta['public']

    def is_published(self):
        return self.__meta['published']

    def is_shareable(self):
        return self.__meta['shareable']

    def is_immutable(self):
        return self.__meta['immutable']

    def get_capabilities(self):
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
        users = self.__hsa.get_users_holding_resource(self.__uuid)
        result = []
        for u in users:
            result += [HSAccessUser(self.__hsa, u['uuid'])]
        return result

    def __get_groups(self):
        groups = self.__hsa.get_groups_holding_resource(self.__uuid)
        result = []
        for u in groups:
            result += [HSAccessGroup(self.__hsa, u['uuid'])]
        return result

    def __change_title(self, new_name):
        self.__meta['title'] = new_name
        self.__hsa.assert_resource_metadata(self.__meta)

    def __make_shareable(self):
        self.__hsa.make_resource_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def __make_not_shareable(self):
        self.__hsa.make_resource_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def __make_public(self):
            self.__hsa.make_resource_public(self.__uuid)
            self.__meta['public'] = True

    def __make_not_public(self):
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_published(self):
            self.__hsa.make_resource_published(self.__uuid)
            self.__meta['published'] = True

    def make_not_published(self):
        self.__hsa.make_resource_not_published(self.__uuid)
        self.__meta['published'] = False

    def __make_discoverable(self):
            self.__hsa.make_resource_public(self.__uuid)
            self.__meta['public'] = True

    def __make_not_discoverable(self):
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def __make_immutable(self):
            self.__hsa.make_resource_immutable(self.__uuid)
            self.__meta['immutable'] = True

    # need to store allowable privilege codes somewhere
    def __share_with_user(self, user_uuid, privilege_code):
        self.__hsa.share_resource_with_user(self.__uuid, user_uuid, privilege_code)

    def __share_with_group(self, group_uuid, privilege_code):
        self.__hsa.share_resource_with_group(self.__uuid, group_uuid, privilege_code)

    def __spaces(self, indent=0):
        s = ""
        for i in [n for n in range(1, indent)]:
            s += '  '
        return s

    def pprint(self, indent=0):
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

