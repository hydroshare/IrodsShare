__author__ = 'Alva'

import HSAlib

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
    def __init__(self, hsa, user_uuid):
        """
        Initialize a user object

        :type hsa: HSAccess

        """
        self.__hsa = hsa
        self.__uuid = user_uuid
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

    # this will only work if logged in as an admin
    def register_user(self, user_login, user_name, user_active=True, user_admin=False):
        uuid = self.__hsa.assert_user(user_login, user_name,  user_active=True, user_admin=False, user_uuid=None)
        return HSAccessUser(self.__hsa, uuid)

    # anyone can register a group
    def register_group(self, group_name, group_active=True, group_shareable=True,
                     group_discoverable=True, group_public=True):
        uuid = self.__hsa.assert_group(group_name, group_active=True, group_shareable=True,
                                       group_discoverable=True, group_public=True)
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
        pass

    # obey access control
    def get_resources(self):
        """
        Get a list of accessible resources, along wih requisite action links

        This gets the list of resources accessible to a specific user.
        """
        pass

    def get_group_invitations(self):
        """
        Get a list of invitations to join groups, with "accept" and "reject" buttons
        """
        pass

    def get_resource_invitations(self):
        """
        Get a list of all invitations to own resources, with "accept" and "reject" buttons
        """
        pass

    # i think we need an invitation object for this

    def accept_group_invitation(self, hsa_grp):
        """
        Accept a prior invitation to join a group
        """
        pass

    def refuse_group_invitation(self, hsa_grp):
        """
        Refuse an invitation to join a group
        """
        pass



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
        self.__uuid = uuid;
        self.__meta = self.__hsa.get_group_metadata(self.__uuid)
        self.__priv_cum = self.__hsa.get_cumulative_user_privilege_over_group(self.__uuid)
        # self.__priv_prim = self.__hsa.get_user_privilege_over_group(self.__uuid, self.__hsa.get_uuid())

    def get_privilege(self):
        return self.__priv_cum

    def get_name(self):
        return self.__meta['name']

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

    def get_capabilities(self):
        capabilities = {}
        if not self.__hsa.user_is_active():
            return {}
        # if the user is administrator or owner, then can set flags
        if self.__hsa.user_is_admin() or self.is_owned():
            capabilities['change_title'] = self.change_name
            if self.is_discoverable():
                capabilities['make_not_discoverable'] = self.make_not_discoverable
            else:
                capabilities['make_discoverable'] = self.make_discoverable
            if self.is_public():
                capabilities['make_not_public'] = self.make_not_public
            else:
                capabilities['make_public'] = self.make_public
            if self.is_shareable():
                capabilities['make_not_shareable'] = self.make_not_shareable
            else:
                capabilities['make_shareable'] = self.make_shareable
        if self.__hsa.user_is_admin() or self.is_owned() or self.is_shareable():
            capabilities['share_with_user'] = self.share_with_user
        return capabilities

    def change_name(self, new_name):
        self.__meta['name'] = new_name
        self.__hsa.assert_group_metadata(self.__meta)

    def make_shareable(self):
        self.__hsa.make_group_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def make_not_shareable(self):
        self.__hsa.make_group_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def make_public(self):
            self.__hsa.make_group_public(self.__uuid)
            self.__meta['public'] = True

    def make_not_public(self):
        self.__hsa.make_group_not_public(self.__uuid)
        self.__meta['public'] = False

    def make_discoverable(self):
            self.__hsa.make_group_discoverable(self.__uuid)
            self.__meta['discoverable'] = True

    def make_not_discoverable(self):
        self.__hsa.make_group_not_discoverable(self.__uuid)
        self.__meta['discoverable'] = False

    # need to store allowable privilege codes somewhere
    def share_with_user(self, user_uuid, privilege_code):
        self.__hsa.share_group_with_user(self.__uuid, user_uuid, privilege_code)

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

    def is_active(self):
        return self.__meta['active']

    def is_shareable(self):
        return self.__meta['shareable']

    def is_immutable(self):
        return self.__meta['immutable']

    def get_title(self):
        return self.__meta['title']

    def get_capabilities(self):
        capabilities = {}
        if not self.__hsa.user_is_active():
            return {}
        # if the user is administrator or owner, then can set flags
        if self.__hsa.user_is_admin() or self.is_owned():
            capabilities = {'change_title': self.change_title}

            if self.is_discoverable():
                capabilities['make_not_discoverable'] = self.make_not_discoverable
            else:
                capabilities['make_discoverable'] = self.make_discoverable

            if self.is_public():
                capabilities['make_not_public'] = self.make_not_public
            else:
                capabilities['make_public'] = self.make_public

            if self.is_shareable():
                capabilities['make_not_shareable'] = self.make_not_shareable
            else:
                capabilities['make_shareable'] = self.make_shareable

            if not self.is_published():
                capabilities['make_published'] = self.make_published

            if not self.is_immutable():
                capabilities['make_immutable'] = self.make_immutable

            if self.is_shareable():
                capabilities['make_not_shareable'] = self.make_not_shareable
            else:
                capabilities['make_shareable'] = self.make_shareable

        if self.is_owned() or self.is_shareable():
            capabilities['share_with_user'] = self.share_with_user
            capabilities['share_with_group'] = self.share_with_group

        return capabilities

    def change_title(self, new_name):
        self.__meta['title'] = new_name
        self.__hsa.assert_resource_metadata(self.__meta)

    def make_shareable(self):
        self.__hsa.make_resource_shareable(self.__uuid)
        self.__meta['shareable'] = True

    def make_not_shareable(self):
        self.__hsa.make_resource_not_shareable(self.__uuid)
        self.__meta['shareable'] = False

    def make_public(self):
            self.__hsa.make_resource_public(self.__uuid)
            self.__meta['public'] = True

    def make_not_public(self):
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def make_published(self):
            self.__hsa.make_resource_published(self.__uuid)
            self.__meta['published'] = True

    def make_not_published(self):
        self.__hsa.make_resource_not_published(self.__uuid)
        self.__meta['published'] = False

    def make_discoverable(self):
            self.__hsa.make_resource_public(self.__uuid)
            self.__meta['public'] = True

    def make_not_discoverable(self):
        self.__hsa.make_resource_not_public(self.__uuid)
        self.__meta['public'] = False

    def make_immutable(self):
            self.__hsa.make_resource_immutable(self.__uuid)
            self.__meta['immutable'] = True

    # need to store allowable privilege codes somewhere
    def share_with_user(self, user_uuid, privilege_code):
        self.__hsa.share_resource_with_user(self.__uuid, user_uuid, privilege_code)

    def share_with_group(self, group_uuid, privilege_code):
        self.__hsa.share_resource_with_group(self.__uuid, group_uuid, privilege_code)