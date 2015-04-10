__author__ = 'Alva'
import HSAlib
import unittest
from pprint import pprint


def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

# storage for test test_context; users, groups, and resources created durign testing

context = {'groups': {}, 'users': {}, 'resources': {}}


class T01Reset(unittest.TestCase):
    def test(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")


class T02CreateUser(unittest.TestCase):
    def test(self):
        global context
        # start as privileged user
        ha = startup('admin')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        context['users']['cat'] = ha.assert_user('cat', 'not a dog', True, False, user_uuid="user_cat")
        # store this test_context for later tests

        # check that user was created correctly
        self.assertTrue(context['users']['cat'] == 'user_cat')
        meta = ha.get_user_metadata(context['users']['cat'])
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a dog')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

        # change user metadata
        ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=context['users']['cat'])
        meta = ha.get_user_metadata(context['users']['cat'])
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

        # now try to do something to user cat as cat
        ha = startup('cat')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        ha.get_user_metadata(context['users']['cat'])
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

        # now start up as admin again
        ha = startup('admin')
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        # make a user 'dog'
        context['users']['dog'] = ha.assert_user('dog', 'Meow', True, False)
        self.assertTrue(len(context['users']['dog']) == 32)

        meta = ha.get_user_metadata(context['users']['dog'])
        self.assertTrue(meta['login'] == 'dog')
        self.assertTrue(meta['name'] == 'Meow')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

        ha = startup('cat')

        # this should fail; non-administrators cannot create users
        try:
            ha.assert_user('gerbil', 'Woof', True, False)
            self.fail("a non-administrator should not be able to create a user")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == "User is not an administrator")
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)

        # check on user logins
        logins = ha._HSAccessCore__get_user_logins() # private function: used for testing only
        self.assertTrue(match_lists(logins, ['admin', 'cat', 'dog']))
        # pprint(logins)


class T03CreateResource(unittest.TestCase):
    def test(self):
        global context
        ha = startup('cat')  # regular user
        # print "cat uuid is",ha.__user_uuid
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)

        # create a resource
        context['resources']['dog'] = ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')

        # check that resource was created
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 1)
        self.assertTrue(context['resources']['dog'] == context['resources']['dog'])
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertTrue(meta['title'] == 'all about dogs')
        self.assertTrue(meta['path'] == '/cat/foo')
        self.assertFalse(meta['immutable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['public'])
        self.assertTrue(meta['shareable'])
        self.assertTrue(ha.resource_exists(context['resources']['dog']))
        self.assertTrue(not ha.resource_is_immutable(context['resources']['dog']))
        self.assertTrue(not ha.resource_is_public(context['resources']['dog']))
        self.assertTrue(ha.resource_is_owned(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readable(context['resources']['dog']))
        # self.assertTrue(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))

        # should not allow pathnames to be changed by a non-administrator
        try:
            ha.assert_resource('/cat/horse', 'no more about dogs', resource_uuid=context['resources']['dog'])
            self.fail("should not be able to change resource pathname as a regular user")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == "User must be an administrator")

        # should allow title to be changed by a non-administrator
        ha.assert_resource('/cat/foo', 'no more about dogs', resource_uuid=context['resources']['dog'])
        self.assertTrue(ha.get_number_of_resources_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_resources_held_by_user() == 1)
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertTrue(meta['title'] == 'no more about dogs')
        self.assertTrue(meta['path'] == '/cat/foo')
        self.assertFalse(meta['immutable'])

        # check for reflexive behavior
        meta = ha.get_resource_metadata(context['resources']['dog'])
        ha.assert_resource_metadata(meta)

        # ha.make_resource_immutable(test_context['resources']['dog'])
        # self.assertTrue(ha.resource_is_immutable(test_context['resources']['dog'])==True)
        # self.assertTrue(ha.resource_is_public(test_context['resources']['dog'])==False)


class T04CreateGroup(unittest.TestCase):
    def test(self):
        global context

        ha = startup('dog')

        # a new group to check
        context['groups']['arfers'] = 'group_arfers'

        # check that the user has no groups yet
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        # try to read the metadata of a non-existent group
        try:
            ha.get_group_metadata(context['groups']['arfers'])  # will not be accessed.
            self.fail("one should not be able to get group metadata of a non-existent group")
        except HSAlib.HSAUsageException as e:
            # print e.value
            self.assertTrue(e.value == "Group uuid does not exist")

        # creates a new group
        ha.assert_group('arfers', group_uuid=context['groups']['arfers'])

        # check that user statistics are correct
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_groups_of_user() == 1)

        # check that return value is correct
        self.assertTrue(context['groups']['arfers'] == 'group_arfers')
        meta = ha.get_group_metadata(context['groups']['arfers'])

        # check that returned metadata matches creation script
        self.assertTrue(len(meta) == 9)
        self.assertTrue(meta['name'] == 'arfers')
        self.assertTrue(meta['uuid'] == context['groups']['arfers'])
        self.assertTrue(meta['asserting_login'] == 'dog')

        # check that various group checking procedures work properly
        self.assertTrue(ha.group_exists(context['groups']['arfers']))
        self.assertTrue(ha.group_is_owned(context['groups']['arfers']))
        self.assertTrue(ha.group_is_readwrite(context['groups']['arfers']))
        self.assertTrue(ha.group_is_readable(context['groups']['arfers']))
        # self.assertTrue(ha.group_is_readable_without_sharing(test_context['groups']['arfers']))

        # change the group metadata without creating a new group
        ha.assert_group('all about dogs', group_uuid=context['groups']['arfers'])

        # check that a new group was not created
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 1)
        self.assertTrue(ha.get_number_of_groups_of_user() == 1)

        # check that metadata has been changed
        meta = ha.get_group_metadata(context['groups']['arfers'])
        self.assertTrue(len(meta) == 9)
        self.assertTrue(meta['name'] == 'all about dogs')
        self.assertTrue(meta['uuid'] == context['groups']['arfers'])
        self.assertTrue(meta['asserting_login'] == 'dog')

        # destroy a group
        ha.retract_group(context['groups']['arfers'])

        # check that it got destroyed according to statistics
        self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(ha.get_number_of_groups_of_user() == 0)

        # try to read the metadata of a retracted group: should fail
        try:
            ha.get_group_metadata(context['groups']['arfers'])
            self.fail("should not be able to access a retracted group")
        except HSAlib.HSAUsageException as e:
            self.assertTrue("Group uuid does not exist" == e.value)


class T05ProtectResource(unittest.TestCase):
    def test(self):
        global context

        # dog should not have sharing privileges
        ha = startup('dog')
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 100)
        self.assertFalse(ha.resource_is_owned(context['resources']['dog']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertFalse(ha.resource_is_readable(context['resources']['dog']))
        # self.assertFalse(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))
        # this should fail.
        try:
            ha.assert_resource('/cat/foo', 'all about dogs', resource_uuid=context['resources']['dog'])
            self.fail("non-owners should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            # print e.value
            self.assertTrue(e.value == 'Resource must be writeable')

        # now share something with dog
        ha = startup('cat')
        ha.share_resource_with_user(context['resources']['dog'], context['users']['dog'], 'own')
        ha = startup('dog')
        # print "user privilege over resource dog is ",
        #       ha.__get_user_privilege_over_resource(test_context['resources']['dog'])
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 1)
        self.assertTrue(ha.resource_is_owned(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readable(context['resources']['dog']))
        # self.assertTrue(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))
        ha.assert_resource('/cat/foo', 'all about dogs', resource_uuid=context['resources']['dog'])

        # downgrade permission to rw
        ha = startup('cat')
        ha.share_resource_with_user(context['resources']['dog'], context['users']['dog'], 'rw')
        ha = startup('dog')
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 2)
        self.assertFalse(ha.resource_is_owned(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readable(context['resources']['dog']))
        # self.assertTrue(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))

        # readwrite users should be able to change title.
        ha.assert_resource('/cat/foo', 'all about dogs', resource_uuid=context['resources']['dog'])
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertEqual(meta['title'], 'all about dogs')
        ha.assert_resource('/cat/foo', 'no more about dogs', resource_uuid = context['resources']['dog'])
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertEqual(meta['title'], 'no more about dogs')

        # downgrade permission to 'ro'
        ha = startup('cat')
        ha.share_resource_with_user(context['resources']['dog'], context['users']['dog'], 'ro')
        ha = startup('dog')
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 3)
        self.assertFalse(ha.resource_is_owned(context['resources']['dog']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readable(context['resources']['dog']))
        # self.assertTrue(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))
        try:
            ha.assert_resource('/cat/foo', 'all about dogs', resource_uuid=context['resources']['dog'])
            self.fail("read-only users should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            # print e.value
            self.assertTrue(e.value == 'Resource must be writeable')

        ha = startup('cat')
        # take out user sharing
        ha.unshare_resource_with_user(context['resources']['dog'], context['users']['dog'])
        context['groups']['meowers'] = ha.assert_group('some random meowers', group_uuid='guid02')
        ha.share_group_with_user(context['groups']['meowers'], context['users']['dog'], "rw")
        try:
            ha.share_resource_with_group(context['resources']['dog'], context['groups']['meowers'], 'own')
            self.fail("groups should not be able to own resources")
        except HSAlib.HSAException as e:
            # print e.value
            self.assertTrue(e.value == "A group cannot own a resource")
        ha.share_resource_with_group(context['resources']['dog'], context['groups']['meowers'], 'rw')
        # ha.unshare_resource_with_group(test_context['resources']['dog'], test_context['groups']['meowers'])

        # second phase: check group membership privilege
        ha = startup('dog')
        # print ha.__get_user_privilege_over_resource(ha.__user_uuid, test_context['resources']['dog'])
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 2)
        self.assertFalse(ha.resource_is_owned(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertTrue(ha.resource_is_readable(context['resources']['dog']))
        # self.assertTrue(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))

        # readwrite users should be able to change title.
        ha.assert_resource('/cat/foo', 'all about dogs', resource_uuid=context['resources']['dog'])
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertEqual(meta['title'], 'all about dogs')
        ha.assert_resource('/cat/foo', 'no more about dogs', resource_uuid = context['resources']['dog'])
        meta = ha.get_resource_metadata(context['resources']['dog'])
        self.assertEqual(meta['title'], 'no more about dogs')


        # turn off group sharing
        ha = startup('cat')
        ha.unshare_resource_with_group(context['resources']['dog'], context['groups']['meowers'])
        ha = startup('dog')
        # self.assertTrue(ha._HSAccessCore__get_user_privilege_over_resource(test_context['resources']['dog']) == 100)
        self.assertFalse(ha.resource_is_owned(context['resources']['dog']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['dog']))
        self.assertFalse(ha.resource_is_readable(context['resources']['dog']))
        # self.assertFalse(ha.resource_is_readable_without_sharing(test_context['resources']['dog']))


def match_lists(l1, l2):
    return len(set(l1) & set(l2)) == len(set(l1))


class T06ProtectGroup(unittest.TestCase):
    def test(self):
        global context
        ha = startup('cat')

        context['groups']['polyamory'] = ha.assert_group('polyamory')  # owned by 'cat'
        self.assertTrue(ha.group_is_owned(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_active(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_public(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_shareable(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['polyamory']))

        # ensure that this group was created and current user is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        # print "get groups for user is:"
        # pprint(ha.get_groups_for_user())
        self.assertTrue(match_lists(['polyamory', 'some random meowers'], names), "error in group listing")

        # make sure group is exclusively accessible to cat so far
        ha = startup('dog')

        # dog should not have access to the group
        self.assertFalse(ha.group_is_owned(context['groups']['polyamory']))
        self.assertFalse(ha.group_is_readwrite(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_readable(context['groups']['polyamory']))  # readable because public

        # dog's groups should be unchanged
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        # pprint(names)
        self.assertTrue(match_lists(['some random meowers'], names), "error in group listing")

        # should not be able to modify group members
        # ha.share_group_with_user(test_context['groups']['polyamory'], test_context['users']['dog'], "rw")
        try:
            ha.share_group_with_user(context['groups']['polyamory'], context['users']['dog'], "rw")
            self.fail("non-members should not be able to add users to a group")
        except HSAlib.HSAException as e:
            # print e.value
            self.assertTrue(e.value == "User has insufficient privilege for group")

        # now share with dog and let's compare the states
        ha = startup('cat')
        ha.share_group_with_user(context['groups']['polyamory'], context['users']['dog'], "rw")

        # now check the state of 'dog'
        ha = startup('dog')
        # dog should have read/write permission to group polyamory
        self.assertFalse(ha.group_is_owned(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_readwrite(context['groups']['polyamory']))
        self.assertTrue(ha.group_is_readable(context['groups']['polyamory']))

        # check total group membership as well
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['polyamory', 'some random meowers'], names),
                        "error in group listing")

        # now let's have dog make a group
        wolves = ha.assert_group("wolves")
        # check that the dog is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['wolves', 'polyamory', 'some random meowers'], names),
                        "error in group listing")

        # put 'test_context['users']['cat']' into the 'wolves' group
        ha.share_group_with_user(wolves, context['users']['cat'], "rw")

        # make sure 'cat' is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user(context['users']['cat']))
        self.assertTrue(match_lists(['wolves', 'polyamory', 'some random meowers'], names),
                        "error in group listing")

        names = map((lambda x: x['name']), ha.get_groups())
        self.assertTrue(match_lists(names, ['polyamory', 'some random meowers', 'wolves']))


class T07InviteToGroup(unittest.TestCase):
    def test(self):
        global context

        ha = startup('dog')
        context['groups']['operas'] = ha.assert_group('operas')  # groups are public by default

        ha.invite_user_to_group(context['groups']['operas'], context['users']['cat'], 'ro')  # dog invites cat to operas
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('cat')
        invites = ha.get_group_invitations_for_user()

        # check that invitation itself is valid
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['group_uuid'] == context['groups']['operas'])
        self.assertTrue(invites[0]['inviting_user_uuid'] == context['users']['dog'])
        self.assertTrue(invites[0]['group_privilege'] == 'ro')

        # check that invitation has not been acted upon
        self.assertFalse(ha.user_in_group(context['groups']['operas']))
        self.assertFalse(ha.group_is_owned(context['groups']['operas']))
        self.assertFalse(ha.group_is_readwrite(context['groups']['operas']))
        self.assertTrue(ha.group_is_readable(context['groups']['operas']))  # group is public

        # accept invitation
        ha.accept_invitation_to_group(invites[0]['group_uuid'], invites[0]['inviting_user_uuid'])

        # invitation is no longer present
        self.assertTrue(len(ha.get_group_invitations_for_user()) == 0)

        # check that invitation powers are granted
        self.assertTrue(ha.user_in_group(context['groups']['operas']))
        self.assertFalse(ha.group_is_owned(context['groups']['operas']))
        self.assertFalse(ha.group_is_readwrite(context['groups']['operas']))
        self.assertTrue(ha.group_is_readable(context['groups']['operas']))

        # now try a reject operation
        group_carnivores = ha.assert_group('carnivores')
        context['groups']['carnivores'] = group_carnivores
        ha.invite_user_to_group(group_carnivores, context['users']['dog'], 'own')

        # check that there is no invite crosstalk
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('dog')
        invites = ha.get_group_invitations_for_user()
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['group_uuid'] == group_carnivores)
        self.assertTrue(invites[0]['inviting_user_uuid'] == context['users']['cat'])
        self.assertTrue(invites[0]['group_privilege'] == 'own')

        # test that invitation has not taken hold
        self.assertFalse(ha.user_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertTrue(ha.group_is_readable(group_carnivores))

        # reject invitation
        ha.refuse_invitation_to_group(invites[0]['group_uuid'], invites[0]['inviting_user_uuid'])

        # check that invitation has been deleted
        self.assertTrue(len(ha.get_group_invitations_for_user()) == 0)

        # test that invitation has not taken hold
        self.assertFalse(ha.user_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertTrue(ha.group_is_readable(group_carnivores))


class T07InviteToResource(unittest.TestCase):
    def test(self):
        global context

        ha = startup('dog')
        context['resources']['weber'] = ha.assert_resource('/dog/weber', 'Andrew Lloyd Weber')
        # resources are public by default

        ha.invite_user_to_resource(context['resources']['weber'], context['users']['cat'], 'ro')
        # dog invites cat to weber
        invites = ha.get_resource_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('cat')
        invites = ha.get_resource_invitations_for_user()

        # check that invitation itself is valid
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['resource_uuid'] == context['resources']['weber'])
        self.assertTrue(invites[0]['inviting_user_uuid'] == context['users']['dog'])
        self.assertTrue(invites[0]['resource_privilege'] == 'ro')

        # check that invitation has not been acted upon
        self.assertFalse(ha.resource_is_owned(context['resources']['weber']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['weber']))
        self.assertFalse(ha.resource_is_readable(context['resources']['weber']))  # resource is not public

        # accept invitation
        ha.accept_invitation_to_resource(invites[0]['resource_uuid'], invites[0]['inviting_user_uuid'])

        # invitation is no longer present
        self.assertTrue(len(ha.get_resource_invitations_for_user()) == 0)

        # check that invitation powers are granted
        self.assertFalse(ha.resource_is_owned(context['resources']['weber']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['weber']))
        self.assertTrue(ha.resource_is_readable(context['resources']['weber']))

        # now try a reject operation
        resource_familiars = ha.assert_resource('/cat/familiars', 'familiars')
        context['resources']['familiars'] = resource_familiars
        ha.invite_user_to_resource(resource_familiars, context['users']['dog'], 'own')

        # check that there is no invite crosstalk
        invites = ha.get_resource_invitations_for_user()
        self.assertTrue(len(invites) == 0)

        ha = startup('dog')
        invites = ha.get_resource_invitations_for_user()
        self.assertTrue(len(invites) == 1)
        self.assertTrue(invites[0]['resource_uuid'] == resource_familiars)
        self.assertTrue(invites[0]['inviting_user_uuid'] == context['users']['cat'])
        self.assertTrue(invites[0]['resource_privilege'] == 'own')

        # test that invitation has not taken hold
        self.assertFalse(ha.resource_is_owned(resource_familiars))
        self.assertFalse(ha.resource_is_readwrite(resource_familiars))
        self.assertFalse(ha.resource_is_readable(resource_familiars))

        # reject invitation
        ha.refuse_invitation_to_resource(invites[0]['resource_uuid'], invites[0]['inviting_user_uuid'])

        # check that invitation has been deleted
        self.assertTrue(len(ha.get_resource_invitations_for_user()) == 0)

        # test that invitation has not taken hold
        self.assertFalse(ha.resource_is_owned(resource_familiars))
        self.assertFalse(ha.resource_is_readwrite(resource_familiars))
        self.assertFalse(ha.resource_is_readable(resource_familiars))


class T08ResourceFlags(unittest.TestCase):
    def test(self):
        global context
        ha = startup('admin')
        # a user with no privilege over anything
        context['users']['nobody'] = ha.assert_user('nobody', 'no one in particular')

        ha = startup('dog')

        # do resource flags work properly?
        context['resources']['bones'] = ha.assert_resource('/dog/bones', 'all about dog bones',
                                                           resource_uuid='resource_bones')
        # are resources created with correct defaults?
        self.assertTrue(context['resources']['bones'] == 'resource_bones')
        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        # can I change shareable?
        ha.make_resource_not_shareable(context['resources']['bones'])
        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_shareable(context['resources']['bones']))

        # dog is an owner, should be able to share even if shareable is False
        ha.share_resource_with_user(context['resources']['bones'], context['users']['cat'], 'ro')

        ha = startup('admin')
        context['users']['bat'] = ha.assert_user('bat', 'not a man', True, False)

        # not an owner of test_context['resources']['bones']
        ha = startup('cat')
        self.assertTrue(ha.resource_is_readable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['bones']))
        self.assertFalse(ha.resource_is_owned(context['resources']['bones']))
        try:
            ha.share_resource_with_user(context['resources']['bones'], context['users']['bat'], "ro")
            self.fail("should not be able to share an unshareable resource")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == "Resource is not shareable by non-owners")

        ha = startup('dog')
        ha.make_resource_shareable(context['resources']['bones'])
        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        # can I change discoverable?
        ha.make_resource_discoverable(context['resources']['bones'])
        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertTrue(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        names = map((lambda x: x['title']), ha.get_discoverable_resources())
        self.assertTrue(match_lists(['all about dog bones'], names), "error in discoverable resource listing")

        ha = startup('nobody')
        self.assertEqual(ha.get_cumulative_user_privilege_over_resource(context['resources']['bones']), 'none')
        ha = startup('dog')

        ha.make_resource_not_discoverable(context['resources']['bones'])
        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        ha.make_resource_immutable(context['resources']['bones'])
        self.assertTrue(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        # ownership should survive downgrading to immutable; otherwise one cuts out ownership privilege completely
        self.assertTrue(ha.resource_is_readable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['bones']))
        self.assertTrue(ha.resource_is_owned(context['resources']['bones']))

        # another user shouldn't be able to read it unless it's also public
        ha = startup('nobody')
        self.assertFalse(ha.resource_is_readable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['bones']))
        self.assertFalse(ha.resource_is_owned(context['resources']['bones']))

        ha = startup('dog')
        ha.make_resource_not_immutable(context['resources']['bones'])

        self.assertFalse(ha.resource_is_immutable(context['resources']['bones']))
        self.assertFalse(ha.resource_is_public(context['resources']['bones']))
        self.assertFalse(ha.resource_is_published(context['resources']['bones']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['bones']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['bones']))

        # test making a resource public
        ha = startup('dog')

        context['resources']['chewies'] = ha.assert_resource('/dog/chewies', 'all about dog chewies')
        self.assertFalse(ha.resource_is_immutable(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_public(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_published(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['chewies']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['chewies']))

        ha.make_resource_public(context['resources']['chewies'])
        self.assertFalse(ha.resource_is_immutable(context['resources']['chewies']))
        self.assertTrue(ha.resource_is_public(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_published(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_discoverable(context['resources']['chewies']))
        self.assertTrue(ha.resource_is_shareable(context['resources']['chewies']))

        names = map((lambda x: x['title']), ha.get_public_resources())
        self.assertTrue(match_lists(['all about dog chewies'], names), "error in public resource listing")
        names = map((lambda x: x['title']), ha.get_discoverable_resources())
        self.assertTrue(match_lists(['all about dog chewies'], names), "error in public resource listing")

        ha = startup('bat')
        # check protection for otherwise unconnected user
        protection = [i['privilege'] for i in ha.get_discoverable_resources() if i['title'] == 'all about dog chewies' ]
        self.assertEqual(len(protection), 1, "wrong number of title matches in get_discoverable_resources")
        self.assertEqual(protection[0], 'ro', 'public resource protection incorrect')

        # can 'cat' see the public resource owned by 'dog' but not explicitly owned by 'cat'.
        self.assertTrue(ha.resource_is_readable(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_readwrite(context['resources']['chewies']))
        self.assertFalse(ha.resource_is_owned(context['resources']['chewies']))
        self.assertEqual(ha.get_cumulative_user_privilege_over_resource(context['resources']['chewies']), 'ro')

        # test whether we can retract a resource
        ha = startup('dog')
        ha.retract_resource(context['resources']['chewies'])
        self.assertFalse(ha.resource_exists(context['resources']['chewies']),
                         "resource still exists after being retracted")

class T09GroupSharing(unittest.TestCase):
    def test(self):
        global context
        ha = startup('dog')

        context['resources']['scratching'] = ha.assert_resource('/cat/scratching',
                                                                'all about sofas as scratching posts')

        self.assertFalse(ha.resource_is_public(context['resources']['scratching']))
        self.assertFalse(ha.resource_is_immutable(context['resources']['scratching']))

        # test primitive group sharing of a resource
        context['groups']['felines'] = ha.assert_group('felines')
        ha.group_is_owned(context['groups']['felines'])

        ha.share_group_with_user(context['groups']['felines'], context['users']['cat'], 'ro')

        try:
            ha.share_resource_with_group(context['resources']['scratching'], context['groups']['felines'], 'own')
            self.fail("A group should not be able to own a resource")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == "A group cannot own a resource")

        ha.share_resource_with_group(context['resources']['scratching'], context['groups']['felines'], 'rw')

        # is the resource just shared with this group?
        uuids = map((lambda x: x['uuid']), ha.get_resources_held_by_group(context['groups']['felines']))
        self.assertTrue(match_lists(uuids, [context['resources']['scratching']]))

        # check that group access works
        ha = startup('cat')

        self.assertTrue(ha.group_exists(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_readable(context['groups']['felines']))
        self.assertFalse(ha.group_is_readwrite(context['groups']['felines']))
        self.assertFalse(ha.group_is_owned(context['groups']['felines']))

        self.assertTrue(ha.resource_is_readable(context['resources']['scratching']))
        self.assertTrue(ha.resource_is_readwrite(context['resources']['scratching']))
        self.assertFalse(ha.resource_is_owned(context['resources']['scratching']))
        try:
            ha.unshare_resource_with_group(context['resources']['scratching'], context['groups']['felines'])
            self.fail("Non-owner of group was allowed to unshare resource with group")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == 'Regular user must own group')

        ha = startup('dog')
        ha.unshare_resource_with_group(context['resources']['scratching'], context['groups']['felines'])
        self.assertTrue(len(ha.get_resources_held_by_group(context['groups']['felines'])) == 0)


class T10GroupFlags(unittest.TestCase):
    def test(self):
        global context
        # test whether protection on flags is appropriate
        ha = startup('cat')
        self.assertFalse(ha.group_is_owned(context['groups']['felines']))

        try:
            ha.make_group_not_shareable(context['groups']['felines'])
            self.fail("non-owner should not be able to change sharing")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == "Regular user must own group")
        try:
            ha.make_group_not_discoverable(context['groups']['felines'])
            self.fail("non-owner should not be able to change discoverability")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == "Regular user must own group")

        ha = startup('dog')
        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)

        ha.make_group_not_discoverable(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertFalse(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)

        ha.make_group_discoverable(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)

        # check public flag
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)

        # become another user and check that the resource is readable


        ha.make_group_not_public(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertFalse(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))

        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' not in names)

        ha.make_group_public(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))

        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)

        # check shareable flag
        ha.make_group_not_shareable(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertFalse(ha.group_is_shareable(context['groups']['felines']))

        ha.make_group_shareable(context['groups']['felines'])

        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.group_is_public(context['groups']['felines']))
        self.assertTrue(ha.group_is_discoverable(context['groups']['felines']))
        self.assertTrue(ha.group_is_active(context['groups']['felines']))
        self.assertTrue(ha.group_is_shareable(context['groups']['felines']))


class T11PreserveOwnership(unittest.TestCase):
    def test(self):
        global context
        ha = startup('dog')
        self.assertTrue(ha.group_is_owned(context['groups']['felines']))
        self.assertTrue(ha.get_number_of_group_owners(context['groups']['felines']) == 1)
        # meta = ha.get_group_metadata(test_context['groups']['felines'])
        try:
            # try to downgrade your own privilege
            ha.share_group_with_user(context['groups']['felines'], context['users']['dog'], 'ro')
            self.fail("should not be able to remove sole owner")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == 'Cannot remove last owner of group')

        self.assertTrue(ha.resource_is_owned(context['resources']['bones']))
        self.assertTrue(ha.get_number_of_resource_owners(context['resources']['bones']) == 1)
        # meta = ha.get_resource_metadata(test_context['resources']['bones'])
        try:
            # try to downgrade your own privilege
            ha.share_resource_with_user(context['resources']['bones'], context['users']['dog'], 'ro')
            self.fail("should not be able to remove sole owner")
        except HSAlib.HSAccessException as e:
            self.assertTrue(e.value == 'Cannot remove last owner of resource')

class T12ProgrammingErrors(unittest.TestCase):
    def test(self):
        global context

        ha = startup('dog')

        # this test checks whether the private routines are functioning properly, by
        # using their private names. This is not a pattern to use in practice.
        try:
            ha._HSAccessCore__get_user_id_from_login('nonsense')
            self.fail("managed to get non-existent login 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'User login does not exist')

        try:
            ha.get_user_uuid_from_login('nonsense')
            self.fail("managed to get non-existent login 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'User login does not exist')

        try:
            ha._HSAccessCore__get_user_id_from_uuid('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'User uuid does not exist')

        try:
            ha.get_user_metadata('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'User uuid does not exist')

        try:
            ha._HSAccessCore__get_user_login_from_uuid('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'User uuid does not exist')

        try:
            ha._HSAccessCore__get_group_id_from_uuid('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'Group uuid does not exist')

        try:
            ha._HSAccessCore__get_group_name_from_uuid('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value == 'Group uuid does not exist')

        try:
            ha.get_group_metadata('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value=='Group uuid does not exist')

        try:
            ha._HSAccessCore__get_resource_id_from_uuid('nonsense')
            self.fail("managed to get non-existent resource uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value=='Resource uuid does not exist')

        try:
            ha._HSAccessCore__get_resource_uuid_from_path('nonsense')
            self.fail("managed to get non-existent resource path 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value=='Resource path does not exist')

        try:
            ha.get_resource_metadata('nonsense')
            self.fail("managed to get non-existent resource path 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertTrue(e.value=='Resource uuid does not exist')


class T13CascadeDelete(unittest.TestCase):
    def test(self):
        global context
        ha = startup('admin')
        context['users']['wombat'] = ha.assert_user('wombat', 'some random wombat')

        ha = startup('dog')
        context['resources']['verdi'] = ha.assert_resource('/dog/verdi', 'Guiseppe Verdi')
        ha.share_resource_with_user(context['resources']['verdi'], context['users']['cat'])
        ha.share_resource_with_group(context['resources']['verdi'], context['groups']['operas'])
        ha.invite_user_to_resource(context['resources']['verdi'], context['users']['wombat'])

        self.assertTrue(ha.resource_exists(context['resources']['verdi']))
        ha.retract_resource(context['resources']['verdi'])
        self.assertFalse(ha.resource_exists(context['resources']['verdi']))

        context['groups']['singers'] = ha.assert_group('singers')
        ha.share_group_with_user(context['groups']['singers'], context['users']['cat'])
        ha.invite_user_to_group(context['groups']['singers'], context['users']['wombat'])

        self.assertTrue(ha.group_exists(context['groups']['singers']))
        ha.retract_group(context['groups']['singers'])
        self.assertFalse(ha.group_exists(context['groups']['singers']))


if __name__ == '__main__':
    unittest.main()
