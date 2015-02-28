__author__ = 'Alva'
import HSAlib
import unittest
from pprint import pprint

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

# storage for test context; users, groups, and resources created durign testing

context = { 'groups': {}, 'users': {}, 'resources': {} }

class T01Reset(unittest.TestCase):
    def test(self):
        ha = startup('admin')
        ha._global_reset(("yes, I'm sure"))

class T02CreateUser(unittest.TestCase):
    def test(self):
        global context
        # start as privileged user
        ha = startup('admin')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        user_cat = ha.assert_user('cat', 'not a dog', True, False, user_uuid="user_cat")
        # store this context for later tests
        context['users']['cat']=user_cat

        # check that user was created correctly
        self.assertTrue(user_cat is "user_cat")
        meta = ha.get_user_metadata(user_cat)
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a dog')
        self.assertTrue(meta['active'] is True)
        self.assertTrue(meta['admin'] is False)

        # change user metadata
        ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=user_cat)
        meta = ha.get_user_metadata(user_cat)
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'] is True)
        self.assertTrue(meta['admin'] is False)

        # now try to do something as cat
        ha = startup('cat')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)
        ha.get_user_metadata(user_cat)
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'] is True)
        self.assertTrue(meta['admin'] is False)

        # now start up as admin again
        ha = startup('admin')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)
        user_dog = ha.assert_user('dog', 'Meow', True, False)

        # store for later use
        context['users']['dog'] = user_dog

        self.assertTrue(len(user_dog) == 32)
        meta=ha.get_user_metadata(user_dog)
        self.assertTrue(meta['login'] == 'dog')
        self.assertTrue(meta['name'] == 'Meow')
        self.assertTrue(meta['active'] is True)
        self.assertTrue(meta['admin'] is False)
        self.assertTrue(len(user_dog) == 32)

        # this should fail
        ha = startup('cat')

        # this should fail; non-administrators cannot create users
        try:
            user_gerbil = ha.assert_user('gerbil', 'Woof', True, False)
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "User uuid 'user_cat' is not an administrator; operation requires privilege")
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)


class T03CreateResource(unittest.TestCase):
    def test(self):
        global context
        ha = startup('cat') # regular user
        # print "cat uuid is",ha._user_uuid
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)

        # create a resource
        resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')

        # store uuid for later tests
        context['resources']['dog'] = resource_dog

        # check that resource was created
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 1)
        self.assertTrue(resource_dog == 'resource_dog')
        meta = ha.get_resource_metadata(resource_dog)
        self.assertTrue(meta['title'] == 'all about dogs')
        self.assertTrue(meta['path'] == '/cat/foo')
        self.assertTrue(meta['immutable'] is False)
        self.assertTrue(ha.resource_exists(resource_dog))
        self.assertTrue(not ha.resource_is_immutable(resource_dog))
        self.assertTrue(ha.resource_is_owned(resource_dog))
        self.assertTrue(ha.resource_is_readwrite(resource_dog))
        self.assertTrue(ha.resource_is_readable(resource_dog))
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog))

        # this allows pathnames to be changed; perhaps it should not
        ha.assert_resource('/cat/bar', 'no more about dogs', False, resource_uuid=resource_dog)
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 1)
        meta = ha.get_resource_metadata(resource_dog)
        self.assertTrue(meta['title'] == 'no more about dogs')
        self.assertTrue(meta['path'] == '/cat/bar')
        self.assertTrue(meta['immutable'] is False)


class T04CreateGroup(unittest.TestCase):
    def test(self):
        global context

        ha = startup('dog')
        user_dog = ha.get_uuid()

        # a new group to check
        group_arfers = 'group_arfers'

        # check that the user has no groups yet
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        # try to read the metadata of a non-existent group
        try:
            meta = ha.get_group_metadata(group_arfers)
            self.assertTrue("unreachable line reached" == "")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "no such group " + group_arfers)

        # creates a new group
        group_arfers = ha.assert_group('arfers', group_uuid='group_arfers')

        # check that user statistics are correct
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_groups_of_user() == 1)

        # check that return value is correct
        self.assertTrue(group_arfers == 'group_arfers')
        meta = ha.get_group_metadata(group_arfers)

        # check that returned metadata matches creation script
        self.assertTrue(len(meta) == 6)
        self.assertTrue(meta['name'] == 'arfers')
        self.assertTrue(meta['uuid'] == group_arfers)
        self.assertTrue(meta['asserting_login'] == 'dog')

        # check that various group checking procedures work properly
        self.assertTrue(ha.group_exists(group_arfers))
        self.assertTrue(ha.group_is_owned(group_arfers))
        self.assertTrue(ha.group_is_readwrite(group_arfers))
        self.assertTrue(ha.group_is_readable(group_arfers))
        # self.assertTrue(ha.group_is_readable_without_sharing(group_arfers))

        # change the group metadata without creating a new group
        ha.assert_group('all about dogs', group_uuid=group_arfers)

        # check that a new group was not created
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_groups_of_user() == 1)

        # check that metadata has been changed
        meta = ha.get_group_metadata(group_arfers)
        self.assertTrue(len(meta) == 6)
        self.assertTrue(meta['name'] == 'all about dogs')
        self.assertTrue(meta['uuid'] == group_arfers)
        self.assertTrue(meta['asserting_login'] == 'dog')

        # destroy a group
        ha.retract_group(group_arfers)

        # check that it got destroyed according to statistics
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        # try to read the metadata of a retracted group: should fail
        try:
            meta = ha.get_group_metadata(group_arfers)
            self.fail("should not be able to access retracted group")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "no such group " + group_arfers)


class T05ProtectResource(unittest.TestCase):
    def test(self):
        global context
        ha = startup('cat')
        user_dog = context['users']['dog']
        resource_dog = context['resources']['dog']

        # dog should not have sharing privileges
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==100)
        self.assertTrue(ha.resource_is_owned(resource_dog) is False)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is False)
        self.assertTrue(ha.resource_is_readable(resource_dog) is False)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is False)
        # this should fail.
        try:
            resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')
            self.fail("non-owners should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # now share something with dog
        ha = startup('cat')
        ha.share_resource_with_user(resource_dog, user_dog, 'own')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==1)
        self.assertTrue(ha.resource_is_owned(resource_dog) is True)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is True)
        resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')

        # downgrade permission to rw
        ha = startup('cat')
        ha.share_resource_with_user(resource_dog, user_dog, 'rw')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==2)
        self.assertTrue(ha.resource_is_owned(resource_dog) is False)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is True)
        try:
            resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')
            self.fail("non-owners should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # downgrade permission to 'ro'
        ha = startup('cat')
        ha.share_resource_with_user(resource_dog, user_dog, 'ro')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==3)
        self.assertTrue(ha.resource_is_owned(resource_dog) is False)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is False)
        self.assertTrue(ha.resource_is_readable( resource_dog) is True)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is True)
        try:
            resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')
            self.fail("non-owners should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        ha= startup('cat')
        # take out user sharing
        ha.unshare_resource_with_user(resource_dog, user_dog)
        meowers = ha.assert_group('some random meowers', group_uuid='guid02')
        ha.share_group_with_user(meowers, user_dog, "rw")
        try:
            ha.share_resource_with_group(resource_dog, meowers, 'own')
            self.fail("groups should not be able to 'own' resources")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value=="Cannot assert 'ownership' privilege for a group")
        ha.share_resource_with_group(resource_dog, meowers, 'rw')
        # ha.unshare_resource_with_group(resource_dog, meowers)

        # second phase: check group membership privilege
        ha = startup('dog')
        # print ha.get_user_privilege_over_resource(ha._user_uuid, resource_dog)
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==2)
        self.assertTrue(ha.resource_is_owned(resource_dog) is False)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable(resource_dog) is True)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is True)
        try:
            resource_dog = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='resource_dog')
            self.fail("non-owners should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # turn off group sharing
        ha = startup('cat')
        ha.unshare_resource_with_group(resource_dog, meowers)
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(resource_dog)==100)
        self.assertTrue(ha.resource_is_owned(resource_dog) is False)
        self.assertTrue(ha.resource_is_readwrite(resource_dog) is False)
        self.assertTrue(ha.resource_is_readable(resource_dog) is False)
        self.assertTrue(ha.resource_is_readable_without_sharing(resource_dog) is False)

def match_lists(l1, l2):
    return len(set(l1)&set(l2))==len(set(l1))

class T06ProtectGroup(unittest.TestCase):
    def test(self):
        global context
        ha = startup('cat')
        cat = context['users']['cat']
        dog = context['users']['dog']
        poly = ha.assert_group('polyamory')

        # store for later tests
        context['groups']['polyamory'] = poly

        # ensure that this group was created and current user is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['polyamory','some random meowers'],names), "error in group listing")

        # make sure group is exclusively accessible to cat so far
        ha = startup('dog')

        # dog should not have access to the group
        self.assertTrue(ha.group_is_owned(poly) is False)
        self.assertTrue(ha.group_is_readwrite(poly) is False)
        self.assertTrue(ha.group_is_readable(poly) is False)
        # self.assertTrue(ha.group_is_readable_without_sharing(poly) is False)

        # dog's groups should be unchanged
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['all about dogs','some random meowers'], names), "error in group listing")

        # should not be able to modify group members
        # ha.share_group_with_user(poly, dog, "rw")
        try:
            ha.share_group_with_user(poly, dog, "rw")
            self.fail("non-members should not be able to add users to a group")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "user lacks read/write privilege necessary to share this group")

        # now share with dog and let's compare the states
        ha = startup('cat')
        ha.share_group_with_user(poly, dog,"rw")

        # now check the state of 'dog'
        ha = startup('dog')
        # dog should have read/write permission to poly
        self.assertTrue(ha.group_is_owned(poly) is False)
        self.assertTrue(ha.group_is_readwrite(poly) is True)
        self.assertTrue(ha.group_is_readable(poly) is True)
        # self.assertTrue(ha.group_is_readable_without_sharing(poly) is True)
        # check total group membership as well
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['polyamory', 'all about dogs','some random meowers'],names),
                        "error in group listing")

        # now let's have dog make a group
        wolves = ha.assert_group("wolves")
        # check that the dog is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['wolves', 'polyamory', 'all about dogs','some random meowers'],names),
                        "error in group listing")

        # put 'cat' into the 'wolves' group
        ha.share_group_with_user(wolves, cat, "rw")

        # make sure 'cat' is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user(cat))
        self.assertTrue(match_lists(['wolves', 'polyamory','some random meowers'], names),
                        "error in group listing")

class T07InviteToGroup(unittest.TestCase):
    def test(self):
        global context
        dog = context['users']['dog']
        cat = context['users']['cat']

        ha = startup('dog')
        group_operas = ha.assert_group('operas')
        context['groups']['operas'] = group_operas

        user_cat = context['users']['cat']
        ha.invite_user_to_group(group_operas, user_cat, 'ro') # dog invites cat to operas
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('cat')
        invites = ha.get_group_invitations_for_user()

        # check that invitation itself is valid
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['group']['uuid'] == group_operas)
        self.assertTrue(invites[0]['host']['uuid'] == ha._get_user_uuid_from_login('dog'))
        self.assertTrue(invites[0]['group']['privilege'] == 'ro')

        # check that invitation has not been acted upon
        self.assertFalse(ha.user_in_group(group_operas))
        self.assertFalse(ha.group_is_owned(group_operas))
        self.assertFalse(ha.group_is_readwrite(group_operas))
        self.assertFalse(ha.group_is_readable(group_operas))

        # accept invitation
        ha.accept_invitation_to_group(invites[0]['group']['uuid'], invites[0]['host']['uuid'])

        # invitation is no longer present
        self.assertTrue(len(ha.get_group_invitations_for_user()) == 0)

        # check that invitation powers are granted
        self.assertTrue(ha.user_in_group(group_operas))
        self.assertFalse(ha.group_is_owned(group_operas))
        self.assertFalse(ha.group_is_readwrite(group_operas))
        self.assertTrue(ha.group_is_readable(group_operas))

        # now try a reject operation
        group_carnivores = ha.assert_group('carnivores')
        context['groups']['carnivores'] = group_carnivores
        ha.invite_user_to_group(group_carnivores, dog, 'own')

        # check that there is no invite crosstalk
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('dog')
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['group']['uuid'] == group_carnivores)
        self.assertTrue(invites[0]['host']['uuid'] == cat)
        self.assertTrue(invites[0]['group']['privilege' ]== 'own')

        # test that invitation has not taken hold
        self.assertFalse(ha.user_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertFalse(ha.group_is_readable(group_carnivores))

        # reject invitation
        ha.refuse_invitation_to_group(invites[0]['group']['uuid'], invites[0]['host']['uuid'])

        # check that invitation has been deleted
        self.assertTrue(len(ha.get_group_invitations_for_user()) == 0)

        # test that invitation has not taken hold
        self.assertFalse(ha.user_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertFalse(ha.group_is_readable(group_carnivores))

if __name__== '__main__':
    unittest.main()

