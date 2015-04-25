__author__ = 'Alva'
import HSAlib
import unittest
from pprint import pprint


def startup(login):
    """ log into the access control system (without password)
    :type login: basestring
    :param login: login name to use for user
    :return:
    """
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')


def match_lists(l1, l2):
    """ return true if two lists contain the same content
    :param l1: first list
    :param l2: second list
    :return: whether lists match
    """
    return len(set(l1) & set(l2)) == len(set(l1))


class T01CreateUser(unittest.TestCase):

    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")

    def test_01_create(self):
        "Can create a user"
        # start as privileged user
        ha = startup('admin')
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        cat = ha.assert_user('cat', 'not a dog', True, False, user_uuid="user_cat")

        # check that user was created correctly
        self.assertEqual(cat, 'user_cat')
        meta = ha.get_user_metadata(cat)
        self.assertEqual(meta['login'], 'cat')
        self.assertEqual(meta['name'], 'not a dog')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

        # check that user owns and holds nothing 
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_of_user(), 0)

    def test_02_change_name_as_admin(self):
        "Administrator can change user name"
        # start as privileged user
        ha = startup('admin')
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        cat = ha.assert_user('cat', 'not a dog', True, False, user_uuid="user_cat")
        # change user name 
        ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=cat)
        meta = ha.get_user_metadata(cat)
        self.assertEqual(meta['login'], 'cat')
        self.assertEqual(meta['name'], 'not a gerbil')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])
        self.assertFalse(ha.user_is_admin(cat)) 
        self.assertTrue(ha.user_is_active(cat)) 

    def test_03_change_admin_as_admin(self):
        "Administrators can delegate admin privilege"
        # start as privileged user
        ha = startup('admin')
        cat = ha.assert_user('cat', 'not a dog')
        cat = ha.assert_user('cat', 'not a dog', True, True, user_uuid=cat)

        meta = ha.get_user_metadata(cat)
        self.assertEqual(meta['login'], 'cat')
        self.assertEqual(meta['name'], 'not a dog')
        self.assertTrue(meta['active'])
        self.assertTrue(meta['admin'])
        self.assertTrue(ha.user_is_admin(cat)) 
        self.assertTrue(ha.user_is_active(cat)) 

        ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=cat)

    def test_03_change_active_as_admin(self):
        "Administrators can set users as active or inactive"
        # start as privileged user
        ha = startup('admin')
        cat = ha.assert_user('cat', 'not a dog')
        ha.assert_user('cat', 'not a dog', False, False, user_uuid=cat)

        meta = ha.get_user_metadata(cat)
        self.assertEqual(meta['login'], 'cat')
        self.assertEqual(meta['name'], 'not a dog')
        self.assertFalse(meta['active'])
        self.assertFalse(meta['admin'])
        self.assertFalse(ha.user_is_admin(cat)) 
        self.assertFalse(ha.user_is_active(cat)) 

    def test_04_check_view_of_created_user(self):
        "Non-admin users can discover users"
        # start as privileged user
        ha = startup('admin')
        cat = ha.assert_user('cat', 'not a dog', True, False)

        # now check the view as user cat
        ha = startup('cat')
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_of_user(), 0)

        meta = ha.get_user_metadata(cat)
        self.assertEqual(meta['login'], 'cat')
        self.assertEqual(meta['name'], 'not a dog')
        self.assertTrue(meta['active'])
        self.assertFalse(meta['admin'])

    def test_05_prevent_unprivileged_create(self):
        "Non-admin users cannot create users"
        ha = startup('admin')
        cat = ha.assert_user('cat', 'not a dog', True, False)

        ha = startup('cat')
        try:
            ha.assert_user('gerbil', 'Woof', True, False)
            self.fail("a non-administrator should not be able to create a user")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "Regular users cannot create users",
                             "Invalid exception was '"+e.value+"'")

    def test_05_check_logins(self):
        "After user creation, list of logins is correct"
        ha = startup('admin')
        cat = ha.assert_user('cat', 'not a dog', True, False)
        dog = ha.assert_user('dog', 'arrf', True, False)

        # todo: should test get_users instead.
        logins = ha._HSAccessCore__get_user_logins() # private function: used for testing only
        self.assertTrue(match_lists(logins, ['admin', 'cat', 'dog']))


class T03CreateResource(unittest.TestCase):

    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a little arfer', True, False)

    def test_01_create(self):
        "Resource creator has appropriate access"

        ha = startup('cat')  # regular user

        # check that there are no resources already 
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 0)

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # check that resource was created
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 1)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 1)

        # basic existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['immutable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['public'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # protection state
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))


    def test_02_isolate(self):
        "A user who didn't create a resource cannot access it"

        ha = startup('cat')  # regular user
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # check that resource was created
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 1)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 1)

        ha = startup('dog')  # not owner 

        # check that resource is not accessible 
        self.assertEqual(ha.get_number_of_resources_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_resources_held_by_user(), 0)

        # resource should exist for user
        self.assertTrue(ha.resource_exists(holes))

        # metadata should be the same as before
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['immutable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['public'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))  # shareable in principle 

        # a different user should not be able to access the resource
        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertFalse(ha.resource_is_readable(holes))

        # composite django state: should not be able to do anything
        self.assertFalse(ha.can_change_resource(holes))
        self.assertFalse(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertFalse(ha.can_share_resource(holes))

    def test_03_change_path(self):
        "An unprivileged user cannot change the iRODS path of a resource"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # should not allow pathnames to be changed by a non-administrator
        try:
            ha.assert_resource('/cat/horse', 'all about dog holes', resource_uuid=holes)
            self.fail("should not be able to change resource pathname as a regular user")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "User must be an administrator", 
                             "Invalid exception was '"+e.value+"'")

    def test_04_change_title(self):
        "An owner can change the title of a resource"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # should allow title to be changed by a non-administrator
        ha.assert_resource('/cat/holes', 'no more about dog holes', resource_uuid=holes)

        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'no more about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')

    def test_05_check_reflex(self):
        "Asserting the resource metadata just read leaves it unchanged"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # check for reflexive behavior: write what you read, then read again 
        meta = ha.get_resource_metadata(holes)
        ha.assert_resource_metadata(meta)

        # basic existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # protection state
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

    def test_06_check_flag_immutable(self):
        "Resource owner can set and reset immutable flag"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # basic existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # ownership
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_immutable=True, resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertTrue(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertTrue(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # access control
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_immutable=False, resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # access control
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

    def test_07_check_flag_discoverable(self):
        "Resource owner can set and reset discoverable flag"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # access control state
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_discoverable=True, resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertTrue(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertTrue(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # protection state
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_discoverable=False, resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # access control
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

    def test_08_check_flag_published(self):
        "Resource owner can set and reset published flag"
        ha = startup('cat')  # regular user

        # create a resource 
        holes = ha.assert_resource('/cat/holes', 'all about dog holes')

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_published=True, resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertTrue(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertTrue(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # access control
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha.assert_resource('/cat/holes', 'all about dog holes', 
                           resource_published=False, resource_uuid=holes)
        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

class T04CreateGroup(unittest.TestCase):

    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)

    def test_01_non_exists(self):
        "Cannot access non-existent groups"
        ha = startup('dog')

        # check that the user has no groups yet
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_of_user(), 0)

        # try to read the metadata of a non-existent group
        try:
            ha.get_group_metadata('nothing')  # will not be accessed.
            self.fail("one should not be able to get group metadata of a non-existent group")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, "Group uuid does not exist", 
                             "Invalid exception was '"+e.value+"'")

    def test_02_create(self):
        "Can create a group"
        ha = startup('dog')

        # creates a new group
        arfers = ha.assert_group('arfers', group_uuid='group_arfers')

        # check that user statistics are correct
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 1)
        self.assertEqual(ha.get_number_of_groups_of_user(), 1)

        # check that return value is correct
        self.assertEqual(arfers, 'group_arfers')

        # check that returned metadata matches creation command

        # existence
        self.assertTrue(ha.group_exists(arfers))

        # metadata state
        meta = ha.get_group_metadata(arfers)
        self.assertEqual(len(meta), 9)
        self.assertEqual(meta['name'], 'arfers')
        self.assertEqual(meta['uuid'], arfers)
        self.assertEqual(meta['asserting_login'], 'dog')
        self.assertTrue(meta['public'])
        self.assertTrue(meta['discoverable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertTrue(ha.group_is_public(arfers))
        self.assertTrue(ha.group_is_discoverable(arfers))
        self.assertTrue(ha.group_is_shareable(arfers))

        # privileges
        self.assertTrue(ha.group_is_owned(arfers))
        self.assertTrue(ha.group_is_readwrite(arfers))
        self.assertTrue(ha.group_is_readable(arfers))

        # composite django state
        self.assertTrue(ha.can_change_group(arfers))
        self.assertTrue(ha.can_view_group(arfers))
        self.assertTrue(ha.can_change_group_flags(arfers))
        self.assertTrue(ha.can_delete_group(arfers))
        self.assertTrue(ha.can_share_group(arfers))

    def test_02_change_name(self):
        "Owner can change the name of a group"
        ha = startup('dog')

        arfers = ha.assert_group('arfers')
        ha.assert_group('all about dogs', group_uuid=arfers)

        # check that a new group was not created
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 1)
        self.assertEqual(ha.get_number_of_groups_of_user(), 1)

        # check that metadata has been changed
        meta = ha.get_group_metadata(arfers)
        self.assertEqual(len(meta), 9)
        self.assertEqual(meta['name'], 'all about dogs')
        self.assertEqual(meta['uuid'], arfers)
        self.assertEqual(meta['asserting_login'], 'dog')
        self.assertTrue(meta['public'])
        self.assertTrue(meta['discoverable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertTrue(ha.group_is_public(arfers))
        self.assertTrue(ha.group_is_discoverable(arfers))
        self.assertTrue(ha.group_is_shareable(arfers))

        # privileges
        self.assertTrue(ha.group_is_owned(arfers))
        self.assertTrue(ha.group_is_readwrite(arfers))
        self.assertTrue(ha.group_is_readable(arfers))

        # composite django state
        self.assertTrue(ha.can_change_group(arfers))
        self.assertTrue(ha.can_view_group(arfers))
        self.assertTrue(ha.can_change_group_flags(arfers))
        self.assertTrue(ha.can_delete_group(arfers))
        self.assertTrue(ha.can_share_group(arfers))

    def test_04_retract_group(self):
        "Owner can retract a group"
        ha = startup('dog')
        arfers = ha.assert_group('arfers')

        # check that it got created 
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 1)
        self.assertEqual(ha.get_number_of_groups_of_user(), 1)
        ha.retract_group(arfers)

        # existence
        self.assertFalse(ha.group_exists(arfers))

        # check that it got destroyed according to statistics
        self.assertEqual(ha.get_number_of_groups_owned_by_user(), 0)
        self.assertEqual(ha.get_number_of_groups_of_user(), 0)

        # try to read the metadata of a retracted group: should fail
        try:
            ha.get_group_metadata(arfers)
            self.fail("should not be able to access a retracted group")
        except HSAlib.HSAUsageException as e:
            self.assertEqual("Group uuid does not exist", e.value, 
                             "Invalid exception was '"+e.value+"'")


class T05ShareResource(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        ha = startup('cat')
        self.holes = ha.assert_resource('/cat/holes', 'all about dog holes')

    def test_01_unshared(self):
        "Resources cannot be accessed by users with no access"
        # dog should not have sharing privileges
        holes = self.holes 
        ha = startup('dog')

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # privilege
        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertFalse(ha.resource_is_readable(holes))

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertFalse(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertFalse(ha.can_share_resource(holes))

        # this should fail.
        try:
            ha.assert_resource('/cat/holes', 'all about dogs', resource_uuid=holes)
            self.fail("non-writers should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertEqual(e.value, 'Resource must be writeable',
                             "Invalid exception was '"+e.value+"'")

    def test_02_share_ownership(self):
        "Resources can be shared as 'own' by owner"
        holes = self.holes 
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        ha.share_resource_with_user(holes, dog, 'own')
        ha = startup('dog')

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dog holes')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))

        # privilege
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        # try to use owner privilege to change title
        ha.assert_resource('/cat/holes', 'all about dogs', resource_uuid=holes)

        # existence
        self.assertTrue(ha.resource_exists(holes))

        # metadata state
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dogs')
        self.assertEqual(meta['path'], '/cat/holes')
        self.assertFalse(meta['public'])
        self.assertFalse(meta['discoverable'])
        self.assertFalse(meta['published'])
        self.assertFalse(meta['immutable'])
        self.assertTrue(meta['shareable'])

        # flag state
        self.assertFalse(ha.resource_is_public(holes))
        self.assertFalse(ha.resource_is_discoverable(holes))
        self.assertFalse(ha.resource_is_published(holes))
        self.assertFalse(ha.resource_is_immutable(holes))
        self.assertTrue(ha.resource_is_shareable(holes))
        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

    def test_03_share_rw(self):
        "Resources can be shared as 'rw' by owner"
        holes = self.holes
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        ha.share_resource_with_user(holes, dog, 'rw')
        ha = startup('dog')

        # privilege
        self.assertFalse(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        # readwrite users should be able to change title.
        ha.assert_resource('/cat/holes', 'all about whole dogs', resource_uuid=holes)
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about whole dogs')

    def test_04_share_ro(self):
        "Resources can be shared as 'ro' by owner"
        holes = self.holes
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        ha.share_resource_with_user(holes, dog, 'ro')
        ha = startup('dog')

        # privilege
        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        # try to change the name of a resource: should fail
        try:
            ha.assert_resource('/cat/holes', 'all about whole dogs', resource_uuid=holes)
            self.fail("read-only users should not be able to modify resource metadata")
        except HSAlib.HSAException as e:
            self.assertEqual(e.value, 'Resource must be writeable',
                             "Invalid exception was '"+e.value+"'")

    def test_04_downgrade_privilege(self):
        "Resource sharing privileges can be downgraded by owner"
        holes = self.holes
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        ha.share_resource_with_user(holes, dog, 'own')
        ha = startup('dog')

        self.assertTrue(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))
        self.assertEqual(len(ha.get_resources_held_by_user()), 1)

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertTrue(ha.can_change_resource_flags(holes))
        self.assertTrue(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha = startup('cat')
        ha.share_resource_with_user(holes, dog, 'rw')
        ha = startup('dog')

        self.assertFalse(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))
        self.assertEqual(len(ha.get_resources_held_by_user()), 1)

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha = startup('cat')
        ha.share_resource_with_user(holes, dog, 'ro')
        ha = startup('dog')

        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))
        self.assertEqual(len(ha.get_resources_held_by_user()), 1)

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        ha = startup('cat')
        ha.unshare_resource_with_user(holes, dog)
        ha = startup('dog')

        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertFalse(ha.resource_is_readable(holes))
        self.assertEqual(len(ha.get_resources_held_by_user()), 0)

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertFalse(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertFalse(ha.can_share_resource(holes))

    def test_05_resource_sharing_with_group(self):
        "Group cannot own a resource"
        # now share something with dog
        holes = self.holes 
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        meowers = ha.assert_group('some random meowers')
        ha.share_group_with_user(meowers, dog, "rw")
        try:
            ha.share_resource_with_group(holes, meowers, 'own')
            self.fail("groups should not be able to own resources")
        except HSAlib.HSAException as e:
            self.assertEqual(e.value, "A group cannot own a resource", 
                             "Invalid exception was '"+e.value+"'")

    def test_06_resource_sharing_rw_with_group(self):
        "Resource can be shared 'rw' with a group"
        # now share something with dog
        holes = self.holes
        ha = startup('cat')
        dog = ha.get_user_uuid_from_login('dog')
        meowers = ha.assert_group('some random meowers')
        ha.share_group_with_user(meowers, dog, "rw")
        ha.share_resource_with_group(holes, meowers, 'rw')

        # second phase: check group membership privilege
        ha = startup('dog')

        self.assertFalse(ha.resource_is_owned(holes))
        self.assertTrue(ha.resource_is_readwrite(holes))
        self.assertTrue(ha.resource_is_readable(holes))

        # composite django state
        self.assertTrue(ha.can_change_resource(holes))
        self.assertTrue(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertTrue(ha.can_share_resource(holes))

        # readwrite group users should be able to change title.
        ha.assert_resource('/cat/holes', 'all about dogs', resource_uuid=holes)
        meta = ha.get_resource_metadata(holes)
        self.assertEqual(meta['title'], 'all about dogs')

        # turn off group sharing
        ha = startup('cat')
        ha.unshare_resource_with_group(holes, meowers)
        ha = startup('dog')

        self.assertFalse(ha.resource_is_owned(holes))
        self.assertFalse(ha.resource_is_readwrite(holes))
        self.assertFalse(ha.resource_is_readable(holes))

        # composite django state
        self.assertFalse(ha.can_change_resource(holes))
        self.assertFalse(ha.can_view_resource(holes))
        self.assertFalse(ha.can_change_resource_flags(holes))
        self.assertFalse(ha.can_delete_resource(holes))
        self.assertFalse(ha.can_share_resource(holes))


class T06ProtectGroup(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)

    def test_01_create(self):
        "Initial group state is correct"

        cat = self.cat
        dog = self.dog
        ha = startup('cat')
        polyamory = ha.assert_group('polyamory')  # owned by 'cat'

        # flag state
        self.assertTrue(ha.group_is_active(polyamory))
        self.assertTrue(ha.group_is_public(polyamory))
        self.assertTrue(ha.group_is_shareable(polyamory))
        self.assertTrue(ha.group_is_discoverable(polyamory))

        # privilege
        self.assertTrue(ha.group_is_owned(polyamory))
        self.assertTrue(ha.group_is_readable(polyamory))
        self.assertTrue(ha.group_is_readwrite(polyamory))

        # composite django state
        self.assertTrue(ha.can_change_group(polyamory))
        self.assertTrue(ha.can_view_group(polyamory))
        self.assertTrue(ha.can_change_group_flags(polyamory))
        self.assertTrue(ha.can_delete_group(polyamory))
        self.assertTrue(ha.can_share_group(polyamory))

        # membership
        self.assertTrue(ha.user_is_in_group(polyamory, cat))

        # ensure that this group was created and current user is a member
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        self.assertTrue(match_lists(['polyamory'], names), "error in group listing")

    def test_02_isolate(self):
        "Groups cannot be changed by non-members"
        cat = self.cat
        dog = self.dog
        ha = startup('cat')
        polyamory = ha.assert_group('polyamory')  # owned by 'cat'
        # make sure group is exclusively accessible to cat so far
        ha = startup('dog')

        # dog should not have access to the group
        self.assertFalse(ha.group_is_owned(polyamory))
        self.assertFalse(ha.group_is_readwrite(polyamory))
        self.assertTrue(ha.group_is_readable(polyamory))  # readable because public

        # composite django state
        self.assertFalse(ha.can_change_group(polyamory))
        self.assertTrue(ha.can_view_group(polyamory))
        self.assertFalse(ha.can_change_group_flags(polyamory))
        self.assertFalse(ha.can_delete_group(polyamory))
        self.assertTrue(ha.can_share_group(polyamory))

        # dog's groups should be unchanged
        names = map((lambda x: x['name']), ha.get_groups_for_user())
        # pprint(names)
        self.assertTrue(match_lists([], names), "error in group listing")

        # should not be able to modify group members
        try:
            ha.share_group_with_user(polyamory, dog, "rw")
            self.fail("non-members should not be able to add users to a group")
        except HSAlib.HSAException as e:
            self.assertEqual(e.value, "User has insufficient privilege for group",
                             "Invalid exception was '"+e.value+"'")

    def test_03_share_rw(self):
        "Sharing with 'rw' privilege allows group changes "
        cat = self.cat
        dog = self.dog
        ha = startup('cat')
        polyamory = ha.assert_group('polyamory')  # owned by 'cat'
        ha.share_group_with_user(polyamory, dog, "rw")

        # now check the state of 'dog'
        ha = startup('dog')
        # dog should have read/write permission to group polyamory
        self.assertFalse(ha.group_is_owned(polyamory))
        self.assertTrue(ha.group_is_readwrite(polyamory))
        self.assertTrue(ha.group_is_readable(polyamory))

        # composite django state
        self.assertTrue(ha.can_change_group(polyamory))
        self.assertTrue(ha.can_view_group(polyamory))
        self.assertFalse(ha.can_change_group_flags(polyamory))
        self.assertFalse(ha.can_delete_group(polyamory))
        self.assertTrue(ha.can_share_group(polyamory))

    def test_04_share_ro(self):
        "Sharing with 'ro' privilege disallows group changes "
        cat = self.cat
        dog = self.dog
        ha = startup('cat')
        polyamory = ha.assert_group('polyamory')  # owned by 'cat'
        ha.share_group_with_user(polyamory, dog, "ro")

        # now check the state of 'dog'
        ha = startup('dog')
        # dog should have read/write permission to group polyamory
        self.assertFalse(ha.group_is_owned(polyamory))
        self.assertFalse(ha.group_is_readwrite(polyamory))
        self.assertTrue(ha.group_is_readable(polyamory))

        # composite django state
        self.assertFalse(ha.can_change_group(polyamory))
        self.assertTrue(ha.can_view_group(polyamory))
        self.assertFalse(ha.can_change_group_flags(polyamory))
        self.assertFalse(ha.can_delete_group(polyamory))
        self.assertTrue(ha.can_share_group(polyamory))

        # :todo add test for whether group can be changed via share and unshare

        ### the following code is extraneous and needs to be deleted.
        # # check total group membership as well
        # names = map((lambda x: x['name']), ha.get_groups_for_user())
        # self.assertTrue(match_lists(['polyamory'], names),
        #                 "error in group listing")
        #
        # # now let's have dog make a group
        # wolves = ha.assert_group("wolves")
        # # check that the dog is a member
        # names = map((lambda x: x['name']), ha.get_groups_for_user())
        # self.assertTrue(match_lists(['wolves', 'polyamory'], names),
        #                 "error in group listing")
        #
        # # put 'cat' into the 'wolves' group
        # ha.share_group_with_user(wolves, cat, "rw")
        #
        # # make sure 'cat' is a member
        # names = map((lambda x: x['name']), ha.get_groups_for_user(cat))
        # self.assertTrue(match_lists(['wolves', 'polyamory'], names),
        #                 "error in group listing")
        #
        # names = map((lambda x: x['name']), ha.get_groups())
        # self.assertTrue(match_lists(names, ['polyamory', 'wolves']))


class T07InviteToGroup(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)

    def test(self):
        "Can invite a user to a group"
        cat = self.cat
        dog = self.dog

        ha = startup('dog')
        operas = ha.assert_group('operas')  # groups are public by default

        ha.invite_user_to_group(operas, cat, 'ro')  # dog invites cat to operas
        invites = ha.get_group_invitations_for_user()
        self.assertEqual(len(invites), 0)

        ha = startup('cat')
        invites = ha.get_group_invitations_for_user()

        # check that invitation itself is valid
        self.assertEqual(len(invites), 1)
        self.assertEqual(invites[0]['group_uuid'], operas)
        self.assertEqual(invites[0]['inviting_user_uuid'], dog)
        self.assertEqual(invites[0]['group_privilege'], 'ro')

        # check that invitation has not been acted upon
        self.assertFalse(ha.user_is_in_group(operas))
        self.assertFalse(ha.group_is_owned(operas))
        self.assertFalse(ha.group_is_readwrite(operas))
        self.assertTrue(ha.group_is_readable(operas))  # group is public

        # accept invitation
        ha.accept_invitation_to_group(invites[0]['group_uuid'], invites[0]['inviting_user_uuid'])

        # invitation is no longer present
        self.assertEqual(len(ha.get_group_invitations_for_user()), 0)

        # check that invitation powers are granted
        self.assertTrue(ha.user_is_in_group(operas))

        self.assertFalse(ha.group_is_owned(operas))
        self.assertFalse(ha.group_is_readwrite(operas))
        self.assertTrue(ha.group_is_readable(operas))

        # now try a reject operation
        group_carnivores = ha.assert_group('carnivores')
        carnivores = group_carnivores
        ha.invite_user_to_group(group_carnivores, dog, 'own')

        # check that there is no invite crosstalk
        invites = ha.get_group_invitations_for_user()
        self.assertEqual(len(invites), 0)

        ha = startup('dog')
        invites = ha.get_group_invitations_for_user()
        self.assertEqual(len(invites), 1)
        self.assertEqual(invites[0]['group_uuid'], group_carnivores)
        self.assertEqual(invites[0]['inviting_user_uuid'], cat)
        self.assertEqual(invites[0]['group_privilege'], 'own')

        # test that invitation has not taken hold
        self.assertFalse(ha.user_is_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertTrue(ha.group_is_readable(group_carnivores))

        # reject invitation
        ha.refuse_invitation_to_group(invites[0]['group_uuid'], invites[0]['inviting_user_uuid'])

        # check that invitation has been deleted
        self.assertEqual(len(ha.get_group_invitations_for_user()), 0)

        # test that invitation has not taken hold
        self.assertFalse(ha.user_is_in_group(group_carnivores))
        self.assertFalse(ha.group_is_owned(group_carnivores))
        self.assertFalse(ha.group_is_readwrite(group_carnivores))
        self.assertTrue(ha.group_is_readable(group_carnivores))


class T07InviteToResource(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)

    def test(self):
        "Can invite a user to a resource"
        cat = self.cat
        dog = self.dog

        ha = startup('dog')
        weber = ha.assert_resource('/dog/weber', 'Andrew Lloyd Weber')
        # resources are public by default

        ha.invite_user_to_resource(weber, cat, 'ro')
        # dog invites cat to weber
        invites = ha.get_resource_invitations_for_user()
        self.assertEqual(len(invites), 0)

        ha = startup('cat')
        invites = ha.get_resource_invitations_for_user()

        # check that invitation itself is valid
        self.assertEqual(len(invites), 1)
        self.assertEqual(invites[0]['resource_uuid'], weber)
        self.assertEqual(invites[0]['inviting_user_uuid'], dog)
        self.assertEqual(invites[0]['resource_privilege'], 'ro')

        # check that invitation has not been acted upon
        self.assertFalse(ha.resource_is_owned(weber))
        self.assertFalse(ha.resource_is_readwrite(weber))
        self.assertFalse(ha.resource_is_readable(weber))  # resource is not public

        # accept invitation
        ha.accept_invitation_to_resource(invites[0]['resource_uuid'], invites[0]['inviting_user_uuid'])

        # invitation is no longer present
        self.assertEqual(len(ha.get_resource_invitations_for_user()), 0)

        # check that invitation powers are granted
        self.assertFalse(ha.resource_is_owned(weber))
        self.assertFalse(ha.resource_is_readwrite(weber))
        self.assertTrue(ha.resource_is_readable(weber))

        # now try a reject operation
        resource_familiars = ha.assert_resource('/cat/familiars', 'familiars')
        familiars = resource_familiars
        ha.invite_user_to_resource(resource_familiars, dog, 'own')

        # check that there is no invite crosstalk
        invites = ha.get_resource_invitations_for_user()
        self.assertEqual(len(invites), 0)

        ha = startup('dog')
        invites = ha.get_resource_invitations_for_user()
        self.assertEqual(len(invites), 1)
        self.assertEqual(invites[0]['resource_uuid'], resource_familiars)
        self.assertEqual(invites[0]['inviting_user_uuid'], cat)
        self.assertEqual(invites[0]['resource_privilege'], 'own')

        # test that invitation has not taken hold
        self.assertFalse(ha.resource_is_owned(resource_familiars))
        self.assertFalse(ha.resource_is_readwrite(resource_familiars))
        self.assertFalse(ha.resource_is_readable(resource_familiars))

        # reject invitation
        ha.refuse_invitation_to_resource(invites[0]['resource_uuid'], invites[0]['inviting_user_uuid'])

        # check that invitation has been deleted
        self.assertEqual(len(ha.get_resource_invitations_for_user()), 0)

        # test that invitation has not taken hold
        self.assertFalse(ha.resource_is_owned(resource_familiars))
        self.assertFalse(ha.resource_is_readwrite(resource_familiars))
        self.assertFalse(ha.resource_is_readable(resource_familiars))


class T08ResourceFlags(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        self.bat = ha.assert_user('bat', 'not a man', True, False)
        ha = startup('dog')
        self.bones = ha.assert_resource('/dog/bones', 'all about dog bones', resource_uuid='resource_bones')
        self.chewies = ha.assert_resource('/dog/chewies', 'all about dog chewies')

    def test_01_default_flags(self):
        "Flag defaults are correct when resource is created"
        bones = self.bones
        ha = startup('dog')

        # are resources created with correct defaults?
        self.assertEqual(bones, 'resource_bones')
        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))

    def test_02_shareable(self):
        "Resource shareable flag enables resource sharing"
        cat = self.cat
        bones = self.bones
        ha = startup('dog')

        # can I change shareable?
        ha.make_resource_not_shareable(bones)
        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertFalse(ha.resource_is_shareable(bones))

        # dog is an owner, should be able to share even if shareable is False
        ha.share_resource_with_user(bones, cat, 'ro')

        # should get some privilege, but not an owner of bones
        ha = startup('cat')
        self.assertTrue(ha.resource_is_readable(bones))
        self.assertFalse(ha.resource_is_readwrite(bones))
        self.assertFalse(ha.resource_is_owned(bones))

    def test_03_not_shareable(self):
        "Resource that is not shareable cannot be shared by non-owner"
        cat = self.cat
        bones = self.bones
        bat = self.bat
        ha = startup('dog')
        ha.make_resource_not_shareable(bones)
        ha.share_resource_with_user(bones, cat, 'ro')

        # cat should not be able to reshare
        ha = startup('cat')
        try:
            ha.share_resource_with_user(bones, bat, "ro")
            self.fail("should not be able to share an unshareable resource")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "Resource is not shareable by non-owners", 
                             "Invalid exception was '"+e.value+"'")

    def test_04_transitive_sharing(self):
        "Resource shared with one user can be shared with another"
        cat = self.cat
        bones = self.bones
        bat = self.bat
        ha = startup('dog')

        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))
        ha.share_resource_with_user(bones, cat, 'ro')

        # now cat should be able to share with bat
        ha = startup('cat')
        ha.share_resource_with_user(bones, bat, "ro")
        ha = startup('bat')
        self.assertFalse(ha.resource_is_owned(bones))
        self.assertFalse(ha.resource_is_readwrite(bones))
        self.assertTrue(ha.resource_is_readable(bones))

    def test_05_discoverable(self):
        "Resource can be made discoverable"
        bones = self.bones
        ha = startup('dog')

        # can I change discoverable?
        ha.make_resource_discoverable(bones)
        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertTrue(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))

        ha = startup('nobody')
        names = map((lambda x: x['title']), ha.get_discoverable_resources())
        self.assertTrue(match_lists(['all about dog bones'], names), "error in discoverable resource listing")
        self.assertEqual(ha.get_cumulative_user_privilege_over_resource(bones), 'none')

    def test_06_not_discoverable(self):
        "Resource can be made not discoverable"
        bones = self.bones
        ha = startup('dog')

        ha.make_resource_not_discoverable(bones)
        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))

        ha = startup('nobody')
        names = ha.get_discoverable_resources()
        self.assertEqual(len(ha.get_discoverable_resources()), 0)

    def test_07_immutable(self):
        "An immutable resource cannot be changed"
        bones = self.bones
        ha = startup('dog')
        ha.make_resource_immutable(bones)
        self.assertTrue(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))
        # ownership should survive downgrading to immutable; otherwise one cuts out ownership privilege completely
        self.assertTrue(ha.resource_is_owned(bones))
        self.assertFalse(ha.resource_is_readwrite(bones))
        self.assertTrue(ha.resource_is_readable(bones))

        # another user shouldn't be able to read it unless it's also public
        ha = startup('nobody')
        self.assertFalse(ha.resource_is_readable(bones))
        self.assertFalse(ha.resource_is_readwrite(bones))
        self.assertFalse(ha.resource_is_owned(bones))

        # undo immutable
        ha = startup('dog')
        ha.make_resource_not_immutable(bones)

        self.assertFalse(ha.resource_is_immutable(bones))
        self.assertFalse(ha.resource_is_public(bones))
        self.assertFalse(ha.resource_is_published(bones))
        self.assertFalse(ha.resource_is_discoverable(bones))
        self.assertTrue(ha.resource_is_shareable(bones))
        # should restore readwrite to owner
        self.assertTrue(ha.resource_is_owned(bones))
        self.assertTrue(ha.resource_is_readwrite(bones))
        self.assertTrue(ha.resource_is_readable(bones))

    def test_08_public(self):
        "Public resources show up in public listings"
        chewies = self.chewies
        ha = startup('dog')
        # test making a resource public

        self.assertFalse(ha.resource_is_immutable(chewies))
        self.assertFalse(ha.resource_is_public(chewies))
        self.assertFalse(ha.resource_is_published(chewies))
        self.assertFalse(ha.resource_is_discoverable(chewies))
        self.assertTrue(ha.resource_is_shareable(chewies))

        ha.make_resource_public(chewies)
        self.assertFalse(ha.resource_is_immutable(chewies))
        self.assertTrue(ha.resource_is_public(chewies))
        self.assertFalse(ha.resource_is_published(chewies))
        self.assertFalse(ha.resource_is_discoverable(chewies))
        self.assertTrue(ha.resource_is_shareable(chewies))

        names = map((lambda x: x['title']), ha.get_public_resources())
        self.assertTrue(match_lists(['all about dog chewies'], names), "error in public resource listing")
        names = map((lambda x: x['title']), ha.get_discoverable_resources())
        self.assertTrue(match_lists(['all about dog chewies'], names), "error in public resource listing")

        ha = startup('nobody')
        # check protection for otherwise unconnected user
        protection = [i['privilege'] for i in ha.get_public_resources() if i['title'] == 'all about dog chewies' ]
        self.assertEqual(len(protection), 1, "wrong number of title matches in get_discoverable_resources")
        self.assertEqual(protection[0], 'ro', 'public resource protection incorrect')

        # check protection for otherwise unconnected user
        protection = [i['privilege'] for i in ha.get_discoverable_resources() if i['title'] == 'all about dog chewies' ]
        self.assertEqual(len(protection), 1, "wrong number of title matches in get_discoverable_resources")
        self.assertEqual(protection[0], 'ro', 'public resource protection incorrect')

        # can 'nobody' see the public resource owned by 'dog' but not explicitly shared with 'nobody'.
        self.assertTrue(ha.resource_is_readable(chewies))
        self.assertFalse(ha.resource_is_readwrite(chewies))
        self.assertFalse(ha.resource_is_owned(chewies))
        self.assertEqual(ha.get_cumulative_user_privilege_over_resource(chewies), 'ro')

    def test_08_discoverable(self):
        "Discoverable resources show up in discoverable resource listings"
        chewies = self.chewies
        ha = startup('dog')
        # test making a resource public

        self.assertFalse(ha.resource_is_immutable(chewies))
        self.assertFalse(ha.resource_is_public(chewies))
        self.assertFalse(ha.resource_is_published(chewies))
        self.assertFalse(ha.resource_is_discoverable(chewies))
        self.assertTrue(ha.resource_is_shareable(chewies))

        ha.make_resource_discoverable(chewies)
        self.assertFalse(ha.resource_is_immutable(chewies))
        self.assertFalse(ha.resource_is_public(chewies))
        self.assertFalse(ha.resource_is_published(chewies))
        self.assertTrue(ha.resource_is_discoverable(chewies))
        self.assertTrue(ha.resource_is_shareable(chewies))

        # discoverable doesn't mean public
        names = map((lambda x: x['title']), ha.get_public_resources())
        self.assertTrue(match_lists([], names), "error in public resource listing")
        names = map((lambda x: x['title']), ha.get_discoverable_resources())
        self.assertTrue(match_lists(['all about dog chewies'], names), "error in discoverable resource listing")

        ha = startup('nobody')

        # check protection for otherwise unconnected user
        protection = [i['privilege'] for i in ha.get_discoverable_resources() if i['title'] == 'all about dog chewies' ]
        self.assertEqual(len(protection), 1, "wrong number of title matches in get_discoverable_resources")
        self.assertEqual(protection[0], 'none', 'public resource protection incorrect')

        # can 'nobody' see the public resource owned by 'dog' but not explicitly shared with 'nobody'.
        self.assertFalse(ha.resource_is_readable(chewies))
        self.assertFalse(ha.resource_is_readwrite(chewies))
        self.assertFalse(ha.resource_is_owned(chewies))
        self.assertEqual(ha.get_cumulative_user_privilege_over_resource(chewies), 'none')

    def test_09_retract(self):
        "Retracted resources cannot be accessed"
        chewies = self.chewies
        ha = startup('dog')
        # test whether we can retract a resource
        ha.retract_resource(chewies)
        self.assertFalse(ha.resource_exists(chewies), "resource still exists after being retracted")

class T09GroupSharing(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        ha = startup('dog')
        self.scratching = ha.assert_resource('/dog/scratching', 'all about sofas as scratching posts')
        self.felines = ha.assert_group('felines')  # dog owns felines group
        ha.share_group_with_user(self.felines, self.cat, 'ro')  # poetic justice

    def test_00_defaults(self):
        "Defaults are correct when creating groups"
        scratching = self.scratching
        felines = self.felines

        ha = startup('dog')  # the owner

        self.assertTrue(ha.group_exists(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_readable(felines))
        self.assertTrue(ha.group_is_readwrite(felines))
        self.assertTrue(ha.group_is_owned(felines))

        self.assertTrue(ha.resource_is_readable(scratching))
        self.assertTrue(ha.resource_is_readwrite(scratching))
        self.assertTrue(ha.resource_is_owned(scratching))

        ha = startup('cat')  # a group member with 'ro' privilege

        self.assertTrue(ha.group_exists(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_readable(felines))
        self.assertFalse(ha.group_is_readwrite(felines))
        self.assertFalse(ha.group_is_owned(felines))

        self.assertFalse(ha.resource_is_readable(scratching))
        self.assertFalse(ha.resource_is_readwrite(scratching))
        self.assertFalse(ha.resource_is_owned(scratching))

    def test_01_cannot_share_own(self):
        "Groups cannot 'own' resources"
        scratching = self.scratching
        felines = self.felines
        ha = startup('dog')
        try:
            ha.share_resource_with_group(scratching, felines, 'own')
            self.fail("A group should not be able to own a resource")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, "A group cannot own a resource", 
                             "Invalid exception was '"+e.value+"'")

    def test_02_share_rw(self):
        "An owner can share with 'rw' privileges"
        scratching = self.scratching
        felines = self.felines
        ha = startup('dog')
        ha.share_resource_with_group(scratching, felines, 'rw')

        # is the resource just shared with this group?
        uuids = map((lambda x: x['uuid']), ha.get_resources_held_by_group(felines))
        self.assertTrue(match_lists(uuids, [scratching]))

        # check that group access works
        ha = startup('cat')

        self.assertTrue(ha.group_exists(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_readable(felines))
        self.assertFalse(ha.group_is_readwrite(felines))
        self.assertFalse(ha.group_is_owned(felines))

        self.assertTrue(ha.resource_is_readable(scratching))
        self.assertTrue(ha.resource_is_readwrite(scratching))
        self.assertFalse(ha.resource_is_owned(scratching))

        # todo: check advanced sharing semantics: can initiating user unshare without group ownership
        try:
            ha.unshare_resource_with_group(scratching, felines)
            self.fail("Unrelated user was able to unshare resource with group")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, 'Regular user must own group',
                             "Invalid exception was '"+e.value+"'")

        ha = startup('dog')
        ha.unshare_resource_with_group(scratching, felines)
        self.assertEqual(len(ha.get_resources_held_by_group(felines)), 0)

class T10GroupFlags(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        ha = startup('dog')
        self.scratching = ha.assert_resource('/dog/scratching', 'all about sofas as scratching posts')
        self.felines = ha.assert_group('felines')  # dog owns felines group
        ha.share_group_with_user(self.felines, self.cat, 'ro')  # poetic justice

    def test_00_defaults(self):
        "Defaults for created groups are correct"
        felines = self.felines
        ha = startup('cat')
        self.assertFalse(ha.group_is_owned(felines))

    def test_01_not_shareable(self):
        "Non-owner cannot set a group to 'not shareable'"
        felines = self.felines
        ha = startup('cat')

        try:
            ha.make_group_not_shareable(felines)
            self.fail("non-owner should not be able to change sharing")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "Regular user must own group",
                             "Invalid exception was '"+e.value+"'")

    def test_02_not_discoverable(self):
        "Non-owner cannot set a group to 'not discoverable'"
        felines = self.felines
        ha = startup('cat')

        try:
            ha.make_group_not_discoverable(felines)
            self.fail("non-owner should not be able to change discoverability")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "Regular user must own group",
                             "Invalid exception was '"+e.value+"'")

    def test_03_not_public(self):
        "Non-owner cannot set a group to 'not public'"
        felines = self.felines
        ha = startup('cat')

        try:
            ha.make_group_not_public(felines)
            self.fail("non-owner should not be able to change public attribute")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, "Regular user must own group",
                             "Invalid exception was '"+e.value+"'")

    def test_05_get_discoverable(self):
        "Getting discoverable groups works properly"
        felines = self.felines
        ha = startup('dog')
        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)

    def test_06_make_not_discoverable(self):
        "Can make a group undiscoverable"
        felines = self.felines
        ha = startup('dog')
        ha.make_group_not_discoverable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertFalse(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)  # still public!
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)  # still public!

        ha.make_group_discoverable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)  # still public!

    def test_07_make_not_public(self):
        "Can make a group not public"
        felines = self.felines
        ha = startup('dog')
        ha.make_group_not_public(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertFalse(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)  # still discoverable!
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' not in names)

        ha.make_group_public(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)

        # check public flag
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)

    def test_07_make_private(self):
        "Making a group not public and not discoverable hides it"
        felines = self.felines
        ha = startup('dog')
        ha.make_group_not_public(felines)
        ha.make_group_not_discoverable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertFalse(ha.group_is_public(felines))
        self.assertFalse(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        # can an unrelated user do anything with the group?
        ha = startup('nobody')
        self.assertEqual(len(ha.get_discoverable_groups()), 0)
        self.assertEqual(len(ha.get_public_groups()), 0)

        self.assertFalse(ha.group_is_owned(felines))
        self.assertFalse(ha.group_is_readwrite(felines))
        self.assertFalse(ha.group_is_readable(felines))
        self.assertFalse(ha.group_is_public(felines))
        self.assertFalse(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        # try to do something that is not allowed now
        try:
            mems = ha.get_group_members(felines)
            self.fail("was allowed to get members of private group")
        except HSAlib.HSAccessException as e:
            # todo: this error message is incorrect; should be "Insufficient privilege"
            self.assertEqual(e.value, "User must be owner or administrator",
                             "Invalid exception was '"+e.value+"'")

        ha = startup('dog')
        ha.make_group_public(felines)
        ha.make_group_discoverable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))

        names = map((lambda x: x['name']), ha.get_discoverable_groups())
        self.assertTrue('felines' in names)
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)

        # check public flag
        names = map((lambda x: x['name']), ha.get_public_groups())
        self.assertTrue('felines' in names)
        # become another user and check that the resource is readable

    def test_08_make_not_shareable(self):
        "Can removing sharing privilege from a group"
        felines = self.felines
        ha = startup('dog')
        # check shareable flag
        ha.make_group_not_shareable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertFalse(ha.group_is_shareable(felines))

        ha.make_group_shareable(felines)

        self.assertTrue(ha.group_is_owned(felines))
        self.assertTrue(ha.group_is_public(felines))
        self.assertTrue(ha.group_is_discoverable(felines))
        self.assertTrue(ha.group_is_active(felines))
        self.assertTrue(ha.group_is_shareable(felines))


class T11PreserveOwnership(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        ha = startup('dog')
        self.scratching = ha.assert_resource('/dog/scratching', 'all about sofas as scratching posts')
        self.felines = ha.assert_group('felines')  # dog owns felines group
        ha.share_group_with_user(self.felines, self.cat, 'ro')  # poetic justice

    def test_01_remove_last_owner_of_group(self):
        "Cannot remove last owner of a group"
        ha = startup('dog')
        felines = self.felines
        dog = self.dog
        self.assertTrue(ha.group_is_owned(felines))
        self.assertEqual(ha.get_number_of_group_owners(felines), 1)
        # meta = ha.get_group_metadata(felines)
        try:
            # try to downgrade your own privilege
            ha.share_group_with_user(felines, dog, 'ro')
            self.fail("should not be able to remove sole owner")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, 'Cannot remove last owner of group', 
                             "Invalid exception was '"+e.value+"'")

    def test_01_remove_last_owner_of_resource(self):
        "Cannot remove last owner of a resource"
        ha = startup('dog')
        scratching = self.scratching
        dog = self.dog
        self.assertTrue(ha.resource_is_owned(scratching))
        self.assertEqual(ha.get_number_of_resource_owners(scratching), 1)
        # meta = ha.get_resource_metadata(bones)
        try:
            # try to downgrade your own privilege
            ha.share_resource_with_user(scratching, dog, 'ro')
            self.fail("should not be able to remove sole owner")
        except HSAlib.HSAccessException as e:
            self.assertEqual(e.value, 'Cannot remove last owner of resource', 
                             "Invalid exception was '"+e.value+"'")

class T12ProgrammingErrors(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        ha = startup('dog')
        self.scratching = ha.assert_resource('/dog/scratching', 'all about sofas as scratching posts')
        self.felines = ha.assert_group('felines')  # dog owns felines group
        ha.share_group_with_user(self.felines, self.cat, 'ro')  # poetic justice

    def test(self):
        "Programming errors are caught by type-checking system"
        ha = startup('dog')

        # this test checks whether the private routines are functioning properly, by
        # using their private names. This is not a pattern to use in practice.
        try:
            ha._HSAccessCore__get_user_id_from_login('nonsense')
            self.fail("managed to get non-existent login 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'User login does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha.get_user_uuid_from_login('nonsense')
            self.fail("managed to get non-existent login 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'User login does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha._HSAccessCore__get_user_id_from_uuid('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'User uuid does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha.get_user_metadata('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'User uuid does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha._HSAccessCore__get_user_login_from_uuid('nonsense')
            self.fail("managed to get non-existent user uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'User uuid does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha._HSAccessCore__get_group_id_from_uuid('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Group uuid does not exist',
                             "Invalid exception was '"+e.value+"'")

        try:
            ha._HSAccessCore__get_group_name_from_uuid('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Group uuid does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha.get_group_metadata('nonsense')
            self.fail("managed to get non-existent group uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Group uuid does not exist', 
                             "Invalid exception was '"+e.value+"'")

        try:
            ha._HSAccessCore__get_resource_id_from_uuid('nonsense')
            self.fail("managed to get non-existent resource uuid 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Resource uuid does not exist')

        try:
            ha._HSAccessCore__get_resource_uuid_from_path('nonsense')
            self.fail("managed to get non-existent resource path 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Resource path does not exist',
                             "Invalid exception was '"+e.value+"'")

        try:
            ha.get_resource_metadata('nonsense')
            self.fail("managed to get non-existent resource path 'nonsense'")
        except HSAlib.HSAUsageException as e:
            self.assertEqual(e.value, 'Resource uuid does not exist',
                             "Invalid exception was '"+e.value+"'")


class T13CascadeDelete(unittest.TestCase):
    def setUp(self):
        ha = startup('admin')
        ha._HSAccessCore__global_reset("yes, I'm sure")
        self.cat = ha.assert_user('cat', 'not a dog', True, False)
        self.dog = ha.assert_user('dog', 'a random arfer', True, False)
        self.nobody = ha.assert_user('nobody', 'no one in particular')
        self.wombat = ha.assert_user('wombat', 'some random wombat')
        ha = startup('dog')
        self.verdi = ha.assert_resource('/dog/verdi', 'Guiseppe Verdi')
        self.operas = ha.assert_group("operas")
        ha.share_resource_with_user(self.verdi, self.cat)
        ha.share_resource_with_group(self.verdi, self.operas)
        ha.invite_user_to_resource(self.verdi, self.wombat)
        self.singers = ha.assert_group('singers')
        ha.share_group_with_user(self.singers, self.cat)
        ha.invite_user_to_group(self.singers, self.wombat)

    def test_01_resource_cascade(self):
        "Cascade delete works for resources"
        ha = startup('dog')
        verdi = self.verdi

        self.assertTrue(ha.resource_exists(verdi))
        ha.retract_resource(verdi)
        self.assertFalse(ha.resource_exists(verdi))

    def test_02_group_cascade(self):
        "Cascade delete works for groups"
        ha = startup('dog')
        singers = self.singers

        self.assertTrue(ha.group_exists(singers))
        ha.retract_group(singers)
        self.assertFalse(ha.group_exists(singers))

class T15CreateGroup(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha = startup('cat')
        self.meowers = self.ha.assert_group('meowers')

    def test_01_default_group_ownership(self):
        "Defaults for group ownership are correct"
        self.ha = startup('cat')
        self.assertTrue(self.ha.group_exists(self.meowers))
        self.assertTrue(self.ha.group_is_owned(self.meowers))
        self.assertTrue(self.ha.group_is_readwrite(self.meowers))
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertTrue(self.ha.group_is_active(self.meowers))
        self.assertTrue(self.ha.group_is_public(self.meowers))
        self.assertTrue(self.ha.group_is_discoverable(self.meowers))
        self.assertTrue(self.ha.group_is_shareable(self.meowers))

    def test_02_default_group_isolation(self):
        "Users with no contact with the group have appropriate permissions"
        # start up as an unprivileged user with no access to the group
        self.ha = startup('dog')
        self.assertFalse(self.ha.group_is_owned(self.meowers))
        self.assertFalse(self.ha.group_is_readwrite(self.meowers))
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        # can an unprivileged user read group flags?
        self.assertTrue(self.ha.group_exists(self.meowers))
        self.assertTrue(self.ha.group_is_active(self.meowers))
        self.assertTrue(self.ha.group_is_public(self.meowers))
        self.assertTrue(self.ha.group_is_discoverable(self.meowers))
        self.assertTrue(self.ha.group_is_shareable(self.meowers))

    def test_03_change_group_not_public(self):
        "Can make a group not public"
        self.ha = startup('dog')
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertFalse(self.ha.group_is_readwrite(self.meowers))
        self.assertFalse(self.ha.group_is_owned(self.meowers))
        # now set it to non-public
        self.ha = startup('cat')
        self.ha.make_group_not_public(self.meowers)
        self.assertTrue(self.ha.group_is_owned(self.meowers))
        self.assertTrue(self.ha.group_is_readwrite(self.meowers))
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertTrue(self.ha.group_exists(self.meowers))
        self.assertTrue(self.ha.group_is_active(self.meowers))
        self.assertFalse(self.ha.group_is_public(self.meowers))
        self.assertTrue(self.ha.group_is_discoverable(self.meowers))
        self.assertTrue(self.ha.group_is_shareable(self.meowers))

        # test that an unprivileged user cannot read the group now
        self.ha = startup('dog')
        self.assertFalse(self.ha.group_is_readable(self.meowers))
        self.assertFalse(self.ha.group_is_readwrite(self.meowers))
        self.assertFalse(self.ha.group_is_owned(self.meowers))
        self.assertTrue(self.ha.group_exists(self.meowers))
        self.assertTrue(self.ha.group_is_active(self.meowers))
        self.assertFalse(self.ha.group_is_public(self.meowers))
        self.assertTrue(self.ha.group_is_discoverable(self.meowers))
        self.assertTrue(self.ha.group_is_shareable(self.meowers))

    def test_03_change_group_not_discoverable(self):
        "Can make a group not discoverable"
        self.ha = startup('dog')
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertFalse(self.ha.group_is_readwrite(self.meowers))
        self.assertFalse(self.ha.group_is_owned(self.meowers))
        # now set it to non-discoverable
        self.ha = startup('cat')
        self.ha.make_group_not_discoverable(self.meowers)
        self.assertTrue(self.ha.group_is_owned(self.meowers))
        self.assertTrue(self.ha.group_is_readwrite(self.meowers))
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertTrue(self.ha.group_exists(self.meowers))
        self.assertTrue(self.ha.group_is_public(self.meowers))
        self.assertFalse(self.ha.group_is_discoverable(self.meowers))
        self.assertTrue(self.ha.group_is_owned(self.meowers))
        self.assertTrue(self.ha.group_is_active(self.meowers))
        self.assertTrue(self.ha.group_is_shareable(self.meowers))
        # public -> discoverable; test that an unprivileged user can read the group now
        self.ha = startup('dog')
        self.assertTrue(self.ha.group_is_readable(self.meowers))
        self.assertFalse(self.ha.group_is_readwrite(self.meowers))
        self.assertFalse(self.ha.group_is_owned(self.meowers))

class T16AssertFolder(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        
    def tearDown(self):
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_assert_folder_fails_without_a_folder_name(self):
        try:
            self.ha_dog.assert_folder(None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_assert_folder_fails_if_folder_already_exists(self):
        self.ha_dog.assert_folder('dog_food')

        try:
            self.ha_dog.assert_folder('dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_assert_folder_succeeds_with_valid_folder_name(self):
        self.ha_dog.assert_folder('dog_food')
        self.ha_dog.assert_folder('dog_toys')
        self.ha_cat.assert_folder('cat_food')

        self.assertTrue(self.ha_dog.folder_exists('dog_food'))
        self.assertTrue(self.ha_dog.folder_exists('dog_toys'))
        self.assertTrue(self.ha_cat.folder_exists('cat_food'))

class T17RetractFolder(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        
    def tearDown(self):
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_retract_folder_fails_without_a_folder_name(self):
        try:
            self.ha_dog.retract_folder(None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_retract_folder_fails_if_folder_does_not_exist(self):
        try:
            self.ha_dog.retract_folder("this_folder_does_not_exist")
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_retract_folder_succeeds_if_folder_exists(self):
        self.ha_cat.assert_folder('cat_food')
        self.ha_cat.retract_folder('cat_food')

        self.assertFalse(self.ha_cat.folder_exists('cat_food'))

class T18AssertResourceInFolder(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_folder('dog_food')
        
    def tearDown(self):
        self.ha_dog.retract_folder('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_assert_resource_in_folder_fails_without_a_resource_uuid(self):
        try:
            self.ha_dog.assert_resource_in_folder(None, 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_assert_resource_in_folder_fails_without_a_folder_name(self):
        try:
            self.ha_dog.assert_resource_in_folder(self.resource_dog, None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")
        
    def test_03_assert_resource_in_folder_fails_if_resource_does_not_exist(self):
        try:
            self.ha_dog.assert_resource_in_folder('this_resource_does_not_exist', 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_assert_resource_in_folder_fails_if_folder_does_not_exist(self):
        try:
            self.ha_dog.assert_resource_in_folder(self.resource_dog, 'this_folder_does_not_exist')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_assert_resource_in_folder_succeeds_if_both_resource_and_folder_exists(self):
        self.ha_dog.assert_resource_in_folder(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_in_folders('dog_food'), {'dog_food': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}} )

class T19RetractResourceInFolder(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_folder('dog_food')
        self.ha_dog.assert_resource_in_folder(self.resource_dog, 'dog_food')

    def tearDown(self):
        self.ha_dog.retract_resource_in_folder(self.resource_dog, 'dog_food')
        self.ha_dog.retract_folder('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_retract_resource_in_folder_fails_without_a_resource_uuid(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_in_folder(None, 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_retract_resource_in_folder_fails_without_a_folder_name(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_in_folder(self.resource_dog, None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")
        
    def test_03_retract_resource_in_folder_fails_if_resource_does_not_exist(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_in_folder('this_resource_does_not_exist', 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_retract_resource_in_folder_fails_if_folder_does_not_exist(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_in_folder(self.resource_dog, 'this_folder_does_not_exist')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_retract_resource_in_folder_succeeds_if_both_resource_and_folder_exists(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        self.ha_dog.retract_resource_in_folder(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_in_folders('dog_food'), {'dog_food': {}} )

class T20GetFolders(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_folder('dog_food')
        self.ha_dog.assert_folder('dog_toys')

    def tearDown(self):
        self.ha_dog.retract_folder('dog_toys')
        self.ha_dog.retract_folder('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_get_folders_returns_folders_for_the_current_user_only(self):
        self.ha_cat.assert_folder('cat_food')

        self.dog_folders = self.ha_dog.get_folders()

        self.assertEqual(set(self.dog_folders), set(['dog_food', 'dog_toys']))

        self.ha_cat.retract_folder('cat_food')

    def test_02_get_folders_returns_no_folders_if_the_current_user_has_no_folders(self):
        self.cat_folders = self.ha_cat.get_folders()

        self.assertEqual(self.cat_folders, [])

class T21GetResourcesInFolders(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_folder('dog_food')
        self.ha_dog.assert_folder('dog_toys')
        self.ha_dog.assert_folder('cat_food')

    def tearDown(self):
        self.ha_dog.retract_folder('cat_food')
        self.ha_dog.retract_folder('dog_toys')
        self.ha_dog.retract_folder('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_get_resources_in_folders_returns_empty_dictionary_for_folder_with_no_resources(self):
        self.assertEqual(self.ha_dog.get_resources_in_folders('dog_food'), {'dog_food': {}} )

    def test_02_get_resources_in_folders_returns_none_for_access_code_with_no_privileges(self):
        self.ha_dog.assert_resource_in_folder(self.resource_dog, 'dog_toys')

        self.assertEqual(self.ha_dog.get_resources_in_folders('dog_toys'), {'dog_toys': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}} )

        self.ha_dog.retract_resource_in_folder(self.resource_dog, 'dog_toys')

    def test_03_get_resources_in_folders_returns_correct_access_code_with_privileges(self):
        self.ha_dog.assert_resource_in_folder(self.resource_dog, 'dog_food')
        self.ha.share_resource_with_user('resource_dog', self.users['dog'], 'own')

        self.assertEqual(self.ha_dog.get_resources_in_folders('dog_food'), {'dog_food': {'resource_dog': {'access': 'own', 'title': 'all about dogs'}}} )

    def test_04_get_resources_in_folders_returns_resources_for_all_folders_without_folder_name(self):
        self.ha_dog.assert_resource_in_folder(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_in_folders(), {'dog_food': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}, 'dog_toys': {}, 'cat_food': {}} )

        self.ha_dog.retract_resource_in_folder(self.resource_dog, 'dog_food')

class T22AssertTag(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        
    def tearDown(self):
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_assert_tag_fails_without_a_tag_name(self):
        try:
            self.ha_dog.assert_tag(None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_assert_tag_fails_if_tag_already_exists(self):
        self.ha_dog.assert_tag('dog_food')

        try:
            self.ha_dog.assert_tag('dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_assert_tag_succeeds_with_valid_tag_name(self):
        self.ha_dog.assert_tag('dog_food')
        self.ha_dog.assert_tag('dog_toys')
        self.ha_cat.assert_tag('cat_food')

        self.assertTrue(self.ha_dog.tag_exists('dog_food'))
        self.assertTrue(self.ha_dog.tag_exists('dog_toys'))
        self.assertTrue(self.ha_cat.tag_exists('cat_food'))

class T23RetractTag(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        
    def tearDown(self):
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_retract_tag_fails_without_a_tag_name(self):
        try:
            self.ha_dog.retract_tag(None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_retract_tag_fails_if_tag_does_not_exist(self):
        try:
            self.ha_dog.retract_tag("this_tag_does_not_exist")
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_retract_tag_succeeds_if_tag_exists(self):
        self.ha_cat.assert_tag('cat_food')
        self.ha_cat.retract_tag('cat_food')

        self.assertFalse(self.ha_cat.tag_exists('cat_food'))

class T24AssertResourceHasTag(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_tag('dog_food')
        
    def tearDown(self):
        self.ha_dog.retract_tag('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_assert_resource_has_tag_fails_without_a_resource_uuid(self):
        try:
            self.ha_dog.assert_resource_has_tag(None, 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_assert_resource_has_tag_fails_without_a_tag_name(self):
        try:
            self.ha_dog.assert_resource_has_tag(self.resource_dog, None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")
        
    def test_03_assert_resource_has_tag_fails_if_resource_does_not_exist(self):
        try:
            self.ha_dog.assert_resource_has_tag('this_resource_does_not_exist', 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_assert_resource_has_tag_fails_if_tag_does_not_exist(self):
        try:
            self.ha_dog.assert_resource_has_tag(self.resource_dog, 'this_tag_does_not_exist')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_assert_resource_has_tag_succeeds_if_both_resource_and_tag_exists(self):
        self.ha_dog.assert_resource_has_tag(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_by_tag('dog_food'), {'dog_food': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}} )

class T25RetractResourceHasTag(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_tag('dog_food')
        self.ha_dog.assert_resource_has_tag(self.resource_dog, 'dog_food')

    def tearDown(self):
        self.ha_dog.retract_resource_has_tag(self.resource_dog, 'dog_food')
        self.ha_dog.retract_tag('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_retract_resource_has_tag_fails_without_a_resource_uuid(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_has_tag(None, 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_retract_resource_has_tag_fails_without_a_tag_name(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_has_tag(self.resource_dog, None)
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")
        
    def test_03_retract_resource_has_tag_fails_if_resource_does_not_exist(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_has_tag('this_resource_does_not_exist', 'dog_food')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_retract_resource_has_tag_fails_if_tag_does_not_exist(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        try:
            self.ha_dog.retract_resource_has_tag(self.resource_dog, 'this_tag_does_not_exist')
            self.fail("expected an exception")
        except HSAlib.HSAException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_retract_resource_has_tag_succeeds_if_both_resource_and_tag_exists(self):
        self.ha.assert_user('cat', 'not a dog', True, False)
        self.ha.assert_user('dog', 'a little arfer', True, False)

        self.ha_dog.retract_resource_has_tag(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_by_tag('dog_food'), {'dog_food': {}} )

class T26GetTags(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_tag('dog_food')
        self.ha_dog.assert_tag('dog_toys')

    def tearDown(self):
        self.ha_dog.retract_tag('dog_toys')
        self.ha_dog.retract_tag('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_get_tags_returns_tags_for_the_current_user_only(self):
        self.ha_cat.assert_tag('cat_food')

        self.dog_tags = self.ha_dog.get_tags()

        self.assertEqual(set(self.dog_tags), set(['dog_food', 'dog_toys']))

        self.ha_cat.retract_tag('cat_food')

    def test_02_get_tags_returns_no_tags_if_the_current_user_has_no_tags(self):
        self.cat_tags = self.ha_cat.get_tags()

        self.assertEqual(self.cat_tags, [])

class T27GetResourcesByTag(unittest.TestCase):
    def setUp(self):
        self.ha = startup('admin')
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.users = {}
        self.users['cat'] = self.ha.assert_user('cat', 'not a dog', True, False)
        self.users['dog'] = self.ha.assert_user('dog', 'a little arfer', True, False)
        self.ha_dog = startup('dog')
        self.ha_cat = startup('cat')
        self.resource_dog = self.ha.assert_resource('/cat/foo', 'all about dogs',
                                                         resource_uuid='resource_dog')
        self.ha_dog.assert_tag('dog_food')
        self.ha_dog.assert_tag('dog_toys')
        self.ha_dog.assert_tag('cat_food')

    def tearDown(self):
        self.ha_dog.retract_tag('cat_food')
        self.ha_dog.retract_tag('dog_toys')
        self.ha_dog.retract_tag('dog_food')
        self.ha.retract_resource('resource_dog')
        # self.ha.retract_user('dog')
        # self.ha.retract_user('cat')
        self.ha_cat = None
        self.ha_dog = None
        self.users = None
        self.ha._HSAccessCore__global_reset("yes, I'm sure")
        self.ha = None

    def test_01_get_resources_by_tag_returns_empty_dictionary_for_tag_with_no_resources(self):
        self.assertEqual(self.ha_dog.get_resources_by_tag('dog_food'), {'dog_food': {}} )

    def test_02_get_resources_by_tag_returns_none_for_access_code_with_no_privileges(self):
        self.ha_dog.assert_resource_has_tag(self.resource_dog, 'dog_toys')

        self.assertEqual(self.ha_dog.get_resources_by_tag('dog_toys'), {'dog_toys': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}} )

        self.ha_dog.retract_resource_has_tag(self.resource_dog, 'dog_toys')

    def test_03_get_resources_by_tag_returns_correct_access_code_with_privileges(self):
        self.ha_dog.assert_resource_has_tag(self.resource_dog, 'dog_food')
        self.ha.share_resource_with_user('resource_dog', self.users['dog'], 'own')

        self.assertEqual(self.ha_dog.get_resources_by_tag('dog_food'), {'dog_food': {'resource_dog': {'access': 'own', 'title': 'all about dogs'}}} )

    def test_04_get_resources_by_tag_returns_resources_for_all_tags_without_tag_name(self):
        self.ha_dog.assert_resource_has_tag(self.resource_dog, 'dog_food')

        self.assertEqual(self.ha_dog.get_resources_by_tag(), {'dog_food': {'resource_dog': {'access': 'none', 'title': 'all about dogs'}}, 'dog_toys': {}, 'cat_food': {}} )

        self.ha_dog.retract_resource_has_tag(self.resource_dog, 'dog_food')

if __name__ == '__main__':
    unittest.main()
