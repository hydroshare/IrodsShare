__author__ = 'Alva'
from HSAlib import HSAccess, HSAccessException, HSAUsageException, HSAIntegrityException
from HSAccessObjects import HSAccessUser, HSAccessGroup, HSAccessResource, HSAccessFolder, HSAccessTag

import unittest
from pprint import pprint

# class Stasher(object):
#     """
#     This allows recovery of object details for objects that have been created before,
#     but refreshes metadata as needed. This allows complex state transition tests.
#     """
#
#     def __init__(self):
#         self.users = {}
#         self.groups = {}
#         self.resources = {}
#
#         self.hsaccess_instance = None
#         self.login_name = None
#         self.user_object = None
#
#     def login(self, login):
#         self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
#         self.login_name = login
#         self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
#         self.stash_user(self.user_object, login)
#         # pprint(stasher)
#         return self.user_object
#
#     def reset(self):
#         self.hsaccess_instance._HSAccessCore__global_reset("yes, I'm sure")
#
#     def stash_user(self, user, name):
#         if type(user) is not HSAccessUser:
#             raise HSAUsageException("cannot stash non-user")
#         if name in self.users.keys()\
#                 and self.users[name] != user.get_uuid():
#             raise HSAIntegrityException("attempt to change user id for name not allowed")
#         self.users[name] = user.get_uuid()
#
#     def get_user(self, name):
#         if type(name) is not str:
#             raise HSAUsageException("name is not a string")
#         return HSAccessUser(self.hsaccess_instance, self.users[name])
#
#     def stash_group(self, group, name):
#         if type(group) is not HSAccessGroup:
#             raise HSAUsageException("cannot stash non-group")
#         if name in self.groups.keys():
#             raise HSAIntegrityException("attempt to reuse group name is not allowed")
#         self.groups[name] = group.get_uuid()
#         # pprint(self.context)
#
#     def get_group(self, name):
#         if type(name) is not str:
#             raise HSAUsageException("name is not a string")
#         return HSAccessGroup(self.hsaccess_instance, self.groups[name])
#
#     def stash_resource(self, resource, name):
#         if type(resource) is not HSAccessResource:
#             raise HSAUsageException("cannot stash non-resource")
#         if name in self.resources.keys():
#             raise HSAIntegrityException("attempt to reuse resource name not allowed")
#         self.resources[name] = resource.get_uuid()
#
#     def get_resource(self, name):
#         if type(name) is not str:
#             raise HSAUsageException("name is not a string")
#         return HSAccessResource(self.hsaccess_instance, self.resources[name])

def check_homogeneity(tester, object):
    """
    Check that basic attributes of objects are synchronized between implementations

    :type tester: unittest.TestCase
    :type object: HSAccessObject
    :param tester: Instance of TestCase
    :param object: object to test: can be HSAccessUser. HSAccessGroup, HSAccessResource
    """
    if isinstance(object, HSAccessUser):
        tester.assertEqual(object.is_admin(), tester.hsaccess_instance.user_is_admin(object.get_uuid()),
            'homogeneity failure (admin)')
        tester.assertEqual(object.is_active(), tester.hsaccess_instance.user_is_admin(object.get_uuid()),
            'homogeneity failure (active)')
        if tester.hsaccess_instance.user_is_admin() and tester.hsaccess_instance.user_is_active():
            tester.assertTrue(match_lists(object.get_capabilities().keys(),
                        ['create_user', 'change_name' ]), "capabilities don't match")
        else:
            if object.get_uuid() == tester.hsaccess_instance.get_uuid():
                tester.assertTrue(match_lists(object.get_capabilities.keys(), ['change_name']),
                    "capabilities don't match")
            else:
                tester.assertTrue(match_lists(object.get_capabilities.keys(), ['change_name']),
                    "capabilities don't match")
        return

    if isinstance(object, HSAccessGroup):
        tester.assertEqual(object.is_active(), tester.hsaccess_instance.group_is_active(object.get_uuid()),
            'homogeneity failure (active)')
        tester.assertEqual(object.is_shareable(), tester.hsaccess_instance.group_is_shareable(object.get_uuid()),
            'homogeneity failure (shareable)')
        tester.assertEqual(object.is_discoverable(), tester.hsaccess_instance.group_is_discoverable(object.get_uuid()),
            'homogeneity failure (discoverable)')
        tester.assertEqual(object.is_public(), tester.hsaccess_instance.group_is_public(object.get_uuid()),
            'homogeneity failure (public)')

        return

    if isinstance(object, HSAccessResource):
        tester.assertEqual(object.is_shareable(), tester.hsaccess_instance.resource_is_shareable(object.get_uuid),
            'homogeneity failure (shareable)')
        tester.assertEqual(object.is_discoverable(), tester.hsaccess_instance.resource_is_discoverable(object.get_uuid),
            'homogeneity failure (discoverable)')
        tester.assertEqual(object.is_public(), tester.hsaccess_instance.resource_is_public(object.get_uuid),
            'homogeneity failure (public)')
        tester.assertEqual(object.is_published(), tester.hsaccess_instance.resource_is_published(object.get_uuid),
            'homogeneity failure (published)')
        tester.assertEqual(object.is_immutable(), tester.hsaccess_instance.resource_is_immutable(object.get_uuid),
            'homogeneity failure (immutable)')
        return

    tester.fail("unknown object passed to check_homogeneity")


def match_lists(l1, l2):
    return len(set(l1) & set(l2)) == len(set(l1))


# stasher = Stasher()


# class T01Reset(unittest.TestCase):
#     def test(self):
#         global stasher
#         current = stasher.login('admin')
#         stasher.reset()


class T01CreateUser(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_create(self):

        admin = self.user_object
        # check_homogeneity(self, admin)
        self.assertTrue(admin.get_access().get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_resources_held_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_groups_of_user() == 0)
        admin_caps = admin.get_capabilities()
        self.assertTrue('register_user' in admin_caps.keys())

        cat = admin_caps['register_user']('cat', 'not a dog', True, False)

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'not a dog')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        cat_caps = cat.get_capabilities()

        # user capabilities are relative to admin user
        self.assertTrue('change_name' in cat_caps.keys())
        cat_caps['change_name']('one mean meower')

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

    def test_02_make_admin(self):

        admin = self.login('admin')
        admin_caps = admin.get_capabilities()
        cat = admin_caps['register_user']('cat', 'one mean meower', True, False)

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        cat_caps = cat.get_capabilities()
        self.assertTrue('make_admin' in cat_caps.keys())
        self.assertTrue('make_not_admin' not in cat_caps.keys())

        cat_caps['make_admin']()

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertTrue(cat.is_admin())

        cat_caps = cat.get_capabilities()  # refresh not automatic
        self.assertTrue('make_admin' not in cat_caps.keys())
        self.assertTrue('make_not_admin' in cat_caps.keys())
        cat_caps['make_not_admin']()

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        cat_caps = cat.get_capabilities()
        self.assertTrue('make_admin' in cat_caps.keys())
        self.assertTrue('make_not_admin' not in cat_caps.keys())

    def test_03_make_inactive(self):

        admin = self.login('admin')
        admin_caps = admin.get_capabilities()
        cat = admin_caps['register_user']('cat', 'one mean meower', True, False)

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        # make user inactive, and back
        cat_caps = cat.get_capabilities()
        self.assertTrue('make_active' not in cat_caps.keys())
        self.assertTrue('make_not_active' in cat_caps.keys())

        cat_caps['make_not_active']()

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertFalse(cat.is_active())
        self.assertFalse(cat.is_admin())

        cat_caps = cat.get_capabilities()  # refresh not automatic
        self.assertTrue('make_active' in cat_caps.keys())
        self.assertTrue('make_not_active' not in cat_caps.keys())
        cat_caps['make_active']()

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        cat_caps = cat.get_capabilities()
        self.assertTrue('make_active' not in cat_caps.keys())
        self.assertTrue('make_not_active' in cat_caps.keys())


class T02RegularUser(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        self.cat = admin_caps['register_user']('cat', 'one mean meower')
        # self.dog = admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_change_name(self):
        # become an unprivileged user
        cat = self.login('cat')
        cat_caps = cat.get_capabilities()
        self.assertTrue('register_user' not in cat_caps.keys())
        self.assertTrue('change_name' in cat_caps.keys())
        cat_caps['change_name']('another mean meower')
        self.assertTrue('another mean meower', cat.get_name())

    def test_02_make_admin(self):
        # become an unprivileged user
        cat = self.login('cat')
        cat_caps = cat.get_capabilities()
        self.assertTrue('make_admin' not in cat_caps.keys())
        self.assertTrue('make_not_admin' not in cat_caps.keys())

        # try prohibited acts to make sure they're really prohibited!
        try:
            cat._HSAccessUser__make_admin()
            self.fail("Regular user allowed to make self administrator")
        except HSAccessException as e:
            self.assertTrue(e.value == "Regular users cannot make themselves administrators",
                            "Different exception: '" + e.value + "'")
            cat.refresh()

    def test_02_make_not_active(self):
        # become an unprivileged user
        cat = self.login('cat')
        cat_caps = cat.get_capabilities()
        self.assertTrue('make_not_active' not in cat_caps.keys())
        self.assertTrue('make_active' not in cat_caps.keys())

#         cat._HSAccessUser__make_not_active()
        try:
            cat._HSAccessUser__make_not_active()
            self.fail("Regular user allowed to make self not active")
        except HSAccessException as e:
            self.assertTrue(e.value == "Regular users cannot deactivate themselves",
                            "Different exception: '" + e.value + "'")
            cat.refresh()

class T03RegisterResource(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        self.cat = admin_caps['register_user']('cat', 'one mean meower')
        # self.dog = admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_register(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        self.assertTrue(posts.get_path() == '/cat/posts')
        self.assertTrue(posts.get_title() == 'all about scratching posts')
        self.assertFalse(posts.is_discoverable())
        self.assertFalse(posts.is_public())
        self.assertFalse(posts.is_published())
        self.assertFalse(posts.is_immutable())
        self.assertTrue(posts.is_shareable())
        self.assertTrue(posts.is_owned())
        self.assertTrue(posts.is_writeable())
        self.assertTrue(posts.is_readable())
        self.assertTrue(posts.get_privilege() == 'own')

    #####################
    # test shareability
    #####################

    def test_02_shareable_flag(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        posts_caps = posts.get_capabilities()
        self.assertTrue('make_shareable' not in posts_caps.keys())
        self.assertTrue('make_not_shareable' in posts_caps.keys())

        posts_caps['make_not_shareable']()
        self.assertFalse(posts.is_shareable())

        # must re-read capabilities; not refreshed
        posts_caps = posts.get_capabilities()
        self.assertTrue('make_shareable' in posts_caps.keys())
        self.assertTrue('make_not_shareable' not in posts_caps.keys())

        posts_caps['make_shareable']()
        self.assertTrue(posts.is_shareable())

        posts_caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_shareable' not in posts_caps.keys())
        self.assertTrue('make_not_shareable' in posts_caps.keys())

    #####################
    # test discoverability
    #####################

    def test_03_discoverable_flag(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        posts_caps = posts.get_capabilities()
        self.assertTrue('make_discoverable' in posts_caps.keys())
        self.assertTrue('make_not_discoverable' not in posts_caps.keys())

        posts_caps['make_discoverable']()
        self.assertTrue(posts.is_discoverable())

        # must re-read capabilities; not refreshed
        posts_caps = posts.get_capabilities()
        self.assertTrue('make_discoverable' not in posts_caps.keys())
        self.assertTrue('make_not_discoverable' in posts_caps.keys())

        posts_caps['make_not_discoverable']()
        self.assertFalse(posts.is_discoverable())

        posts_caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' in posts_caps.keys())
        self.assertTrue('make_not_discoverable' not in posts_caps.keys())

    #####################
    # test public
    #####################

    def test_04_public_flag(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        posts_caps = posts.get_capabilities()
        self.assertTrue('make_public' in posts_caps.keys())
        self.assertTrue('make_not_public' not in posts_caps.keys())

        posts_caps['make_public']()
        self.assertTrue(posts.is_public())

        # must re-read capabilities; not refreshed
        posts_caps = posts.get_capabilities()
        self.assertTrue('make_public' not in posts_caps.keys())
        self.assertTrue('make_not_public' in posts_caps.keys())

        posts_caps['make_not_public']()
        self.assertFalse(posts.is_public())

        posts_caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_public' in posts_caps.keys())
        self.assertTrue('make_not_public' not in posts_caps.keys())

    #####################
    # test publication
    #####################

    def test_05_published_flag(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        self.assertFalse(posts.is_published())
        self.assertFalse(posts.is_immutable())

        posts_caps = posts.get_capabilities()
        self.assertTrue('make_published' in posts_caps.keys())
        self.assertTrue('make_not_published' not in posts_caps.keys())

        posts_caps['make_published']()
        self.assertTrue(posts.is_published())
        self.assertFalse(posts.is_immutable())

        # must re-read capabilities; not refreshed
        posts_caps = posts.get_capabilities()
        self.assertTrue('make_published' not in posts_caps.keys())
        self.assertTrue('make_not_published' in posts_caps.keys())

        posts_caps['make_not_published']()
        self.assertFalse(posts.is_published())
        self.assertFalse(posts.is_immutable())

        posts_caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_published' in posts_caps.keys())
        self.assertTrue('make_not_published' not in posts_caps.keys())

        #####################
        # test immutability
        #####################

    def test_06_immutable_flag(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        self.assertFalse(posts.is_immutable())

        posts_caps = posts.get_capabilities()
        self.assertTrue('make_immutable' in posts_caps.keys())
        self.assertTrue('make_not_immutable' not in posts_caps.keys())

        posts_caps['make_immutable']()
        self.assertTrue(posts.is_immutable())

        # must re-read capabilities; not refreshed
        posts_caps = posts.get_capabilities()
        self.assertTrue('make_immutable' not in posts_caps.keys())
        self.assertTrue('make_not_immutable' in posts_caps.keys())

        posts_caps['make_not_immutable']()

        self.assertFalse(posts.is_immutable())

        posts_caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_immutable' in posts_caps.keys())
        self.assertTrue('make_not_immutable' not in posts_caps.keys())

    def test_07_get_resources(self):

        # become an unprivileged user
        cat = self.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')

        # check that the resource is listed properly in get_resources()
        resources = cat.get_resources()
        self.assertTrue(len(resources) == 1)
        self.assertTrue(resources[0].get_title() == 'all about scratching posts')


class T04ResourcePublicAndDiscoverable(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')
        cat = self.login('cat')
        # do store resource identifiers: they are needed later.
        self.posts = cat.register_resource('/cat/posts', 'all about scratching posts').get_uuid()

        # self.dog = admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_public(self):

        # become an unprivileged user
        cat = self.login('cat')

        # grab a previously created resource
        posts = HSAccessResource(self.hsaccess_instance, self.posts)

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 0)

        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 0)

        self.assertFalse(posts.is_public())
        self.assertFalse(posts.is_discoverable())

        posts_caps = posts.get_capabilities()
        posts_caps['make_public']()

        self.assertTrue(posts.is_public())
        self.assertFalse(posts.is_discoverable())

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 1)
        self.assertTrue(public[0].get_title() == 'all about scratching posts')

        # public implies discoverable
        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 1)
        self.assertTrue(discoverable[0].get_title() == 'all about scratching posts')

        posts_caps = posts.get_capabilities()
        posts_caps['make_not_public']()

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 0)

        discoverable = cat.get_discoverable_resources()
        self.assertEqual(len(discoverable), 0)

    def test_discoverable(self):

        # become an unprivileged user
        cat = self.login('cat')

        # grab a previously created resource
        posts = HSAccessResource(self.hsaccess_instance, self.posts)

        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 0)
        self.assertFalse(posts.is_discoverable())

        posts_caps = posts.get_capabilities()
        posts_caps['make_discoverable']()
        self.assertTrue(posts.is_discoverable())

        # is it listed amongst discoverable resources?
        public = cat.get_public_resources()
        self.assertEqual(len(public), 0)

        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 1)
        self.assertTrue(discoverable[0].get_title() == 'all about scratching posts')

        # set it back to not discoverable
        posts_caps = posts.get_capabilities()
        posts_caps['make_not_discoverable']()
        self.assertFalse(posts.is_discoverable())

        discoverable = cat.get_discoverable_resources()
        self.assertEqual(len(discoverable), 0)


class T06RegisterGroup(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')
        # cat = self.login('cat')
        # do store resource identifiers: they are needed later.
        # self.posts = cat.register_resource('/cat/posts', 'all about scratching posts').get_uuid()

        # self.dog = admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_create(self):
        # become an unprivileged user
        cat = self.login('cat')

        # create a group
        meowers = cat.register_group('meowers')

        self.assertTrue(meowers.get_name() == 'meowers')
        self.assertTrue(meowers.is_discoverable())
        self.assertTrue(meowers.is_public())
        self.assertTrue(meowers.is_shareable())
        self.assertTrue(meowers.is_owned())
        self.assertTrue(meowers.is_writeable())
        self.assertTrue(meowers.is_readable())
        self.assertTrue(meowers.get_privilege() == 'own')

    #####################
    # test sharability
    #####################

    def test_02_shareable_flag(self):
        # become an unprivileged user
        cat = self.login('cat')

        # create a group
        meowers = cat.register_group('meowers')

        meowers_caps = meowers.get_capabilities()
        self.assertTrue('make_shareable' not in meowers_caps.keys())
        self.assertTrue('make_not_shareable' in meowers_caps.keys())

        meowers_caps['make_not_shareable']()
        self.assertFalse(meowers.is_shareable())

        # must re-read capabilities; not refreshed
        meowers_caps = meowers.get_capabilities()
        self.assertTrue('make_shareable' in meowers_caps.keys())
        self.assertTrue('make_not_shareable' not in meowers_caps.keys())

        meowers_caps['make_shareable']()
        self.assertTrue(meowers.is_shareable())

        meowers_caps = meowers.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_shareable' not in meowers_caps.keys())
        self.assertTrue('make_not_shareable' in meowers_caps.keys())

    #####################
    # test discoverability
    #####################

    def test_03_discoverable_flag(self):
        # become an unprivileged user
        cat = self.login('cat')

        # create a group
        meowers = cat.register_group('meowers')

        meowers_caps = meowers.get_capabilities()
        self.assertTrue(meowers.is_discoverable())
        self.assertTrue('make_discoverable' not in meowers_caps.keys())
        self.assertTrue('make_not_discoverable' in meowers_caps.keys())

        meowers_caps['make_not_discoverable']()
        self.assertFalse(meowers.is_discoverable())

        # must re-read capabilities; not refreshed
        meowers_caps = meowers.get_capabilities()
        self.assertTrue('make_discoverable' in meowers_caps.keys())
        self.assertTrue('make_not_discoverable' not in meowers_caps.keys())

        meowers_caps['make_discoverable']()
        self.assertTrue(meowers.is_discoverable())

        meowers_caps = meowers.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' not in meowers_caps.keys())
        self.assertTrue('make_not_discoverable' in meowers_caps.keys())

    #####################
    # test public
    #####################
    def test_04_public_flag(self):
        # become an unprivileged user
        cat = self.login('cat')

        # create a group
        meowers = cat.register_group('meowers')

        meowers_caps = meowers.get_capabilities()
        self.assertTrue(meowers.is_public())
        self.assertTrue('make_public' not in meowers_caps.keys())
        self.assertTrue('make_not_public' in meowers_caps.keys())

        meowers_caps['make_not_public']()
        self.assertFalse(meowers.is_public())

        # must re-read capabilities; not refreshed
        meowers_caps = meowers.get_capabilities()
        self.assertTrue('make_public' in meowers_caps.keys())
        self.assertTrue('make_not_public' not in meowers_caps.keys())

        meowers_caps['make_public']()
        self.assertTrue(meowers.is_public())

        # must re-read capabilities; not regenerated
        meowers_caps = meowers.get_capabilities()
        self.assertTrue('make_public' not in meowers_caps.keys())
        self.assertTrue('make_not_public' in meowers_caps.keys())

    #####################
    # test public
    #####################
    def test_05_get_groups(self):
        "Created groups show up in get_groups"
        # become an unprivileged user
        cat = self.login('cat')

        # create a group
        meowers = cat.register_group('meowers')
        # check that the group is listed properly in get_groups()
        groups = cat.get_groups()
        self.assertTrue(len(groups) == 1)
        self.assertTrue(groups[0].get_name() == 'meowers')


# class T07GroupFlagSemantics(unittest.TestCase):
#     def test(self):
#         global stasher
#
#         # test basic semantics of public groups
#
#         # need to switch user here and test that it is visible
#         dog = stasher.login('cat')
#         public = dog.get_public_groups()
#
#         self.assertTrue(len(public) == 1)
#         self.assertTrue(public[0].get_name() == 'meowers')
#
#         # and that it is really public
#         gcaps = public[0].get_capabilities()
#         self.assertTrue('get_members' in gcaps.keys())
#         members = gcaps['get_members']()
#         self.assertTrue(len(members) == 1)
#         self.assertTrue(members[0].get_name() == 'one mean meower')
#
#         cat = stasher.login('cat')
#         meowers = stasher.get_group('meowers')
#         meowers_caps = meowers.get_capabilities()
#         meowers_caps['make_not_public']()
#
#         # need to switch user here and test whether it is really invisible
#         dog = stasher.login('dog')
#         meowers = stasher.get_group('meowers')
#         public = dog.get_public_groups()
#         self.assertTrue(len(public) == 0)
#
#         # set it back to public
#         cat = stasher.login('cat')
#         meowers = stasher.get_group('meowers')
#         meowers_caps = meowers.get_capabilities()
#         meowers_caps['make_public']()
#
#         public = cat.get_public_groups()
#         self.assertTrue(len(public) == 1)
#         self.assertTrue(public[0].get_name() == 'meowers')
#
#         # need to switch user here and test that it is visible
#         dog = stasher.login('dog')
#         public = dog.get_public_groups()
#         self.assertTrue(len(public) == 1)
#         self.assertTrue(public[0].get_name() == 'meowers')
#
#         # and that it is really public
#         gcaps = public[0].get_capabilities()
#         self.assertTrue('get_members' in gcaps.keys())
#         members = gcaps['get_members']()
#         self.assertTrue(len(members) == 1)
#         self.assertTrue(members[0].get_name() == 'one mean meower')
#
#         # test basic semantics of discoverability
#         # first switch back to using user 'cat'
#         cat = stasher.login('cat')
#         meowers = stasher.get_group('meowers')
#
#         discoverable = cat.get_discoverable_groups()
#         self.assertTrue(len(discoverable) == 1)
#         self.assertTrue(discoverable[0].get_name() == 'meowers')
#         self.assertTrue(meowers.is_discoverable())
#
#         meowers_caps = meowers.get_capabilities()
#         meowers_caps['make_not_discoverable']()
#
#         # is it definitely not discoverable now?
#         self.assertFalse(meowers.is_discoverable())
#         discoverable = cat.get_discoverable_resources()
#         self.assertTrue(len(discoverable) == 0)
#
#         # set it back to discoverable
#         meowers_caps = meowers.get_capabilities()
#         meowers_caps['make_discoverable']()
#         self.assertTrue(meowers.is_discoverable())
#
#
# class T08ShareResource(unittest.TestCase):
#     def test(self):
#         global stasher
#         # become an unprivileged user
#         cat = stasher.login('cat')
#
#         # get a resource to share
#         posts = stasher.get_resource('posts')
#         rcaps = posts.get_capabilities()
#
#         # check that we can share, and share object
#         self.assertTrue('share_with_user' in rcaps.keys())
#         rcaps['share_with_user'](stasher.get_user('dog'), 'ro')
#
#         # check that we can get the number of accessing users, and get users
#         self.assertTrue('get_users' in rcaps.keys())
#         users = rcaps['get_users']()
#
#         # check that the number of users is correct
#         self.assertTrue(len(users) == 2)
#         logins = [p.get_login() for p in users]
#         # pprint(logins)
#         self.assertTrue(match_lists(logins, ['cat', 'dog']))
#
#         # note: the object for a resource remembers the current user.
#         # we must recontextualize when changing users
#
#         dog = stasher.login('dog')
#         resources = dog.get_resources()
#         self.assertTrue(len(resources) == 1)
#         self.assertTrue(resources[0].get_title() == 'all about scratching posts')
#         posts = resources[0]  # must recontextualize object from point of view of 'dog' user
#
#         self.assertTrue(posts.is_readable())
#         self.assertFalse(posts.is_writeable())
#         self.assertFalse(posts.is_owned())
#         self.assertTrue(posts.get_privilege() == 'ro')
#
#         rcaps = posts.get_capabilities()
#         self.assertTrue(match_lists(rcaps.keys(), ['share_with_user', 'share_with_group']))

class T09GetFolders(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_get_folders_returns_folders_for_current_user_only(self):
        #log in as cat
        cat = self.login("cat")

        #register a folder for cat
        cat.register_folder("cat_food")

        #login as dog
        dog = self.login("dog")

        #create folders for dog
        dog.register_folder("dog_food")
        dog.register_folder("dog_toys")

        #run get_folders, and assert only dog's folders return
        results = dog.get_folders()

        folder_names = []

        for result in results:
            folder_names.append(result.get_user_folder_name())

        self.assertTrue(type(results) == list)
        self.assertTrue(type(results[0]) == HSAccessFolder)
        self.assertTrue('dog_food' in folder_names)
        self.assertTrue('dog_toys' in folder_names)

    def test_02_get_folders_returns_an_empty_list_if_current_user_has_no_folders(self):
        #log in as cat
        cat = self.login("cat")

        #register a folder for cat
        cat.register_folder("cat_food")

        #log in as dog
        dog = self.login("dog")

        #run get_folders, and assert nothing returns
        self.assertEqual(dog.get_folders(), [])

class T10GetTags(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_get_tags_returns_tags_for_current_user_only(self):
        #log in as cat
        cat = self.login("cat")

        #register a folder for cat
        cat.register_tag("cat_food")

        #login as dog
        dog = self.login("dog")

        #create folders for dog
        dog.register_tag("dog_food")
        dog.register_tag("dog_toys")

        #run get_folders, and assert only dog's folders return
        results = dog.get_tags()

        tag_names = []

        for result in results:
            tag_names.append(result.get_user_tag_name())

        self.assertTrue(type(results) == list)
        self.assertTrue(type(results[0]) == HSAccessTag)
        self.assertTrue("dog_food" in tag_names)
        self.assertTrue("dog_toys" in tag_names)

    def test_02_get_tags_returns_an_empty_list_if_current_user_has_no_folders(self):
        #log in as cat
        cat = self.login("cat")

        #register a folder for cat
        cat.register_tag("cat_food")

        #log in as dog
        dog = self.login("dog")

        #run get_folders, and assert nothing returns
        self.assertEqual(dog.get_tags(), [])

class T11RegisterFolder(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_register_folder_fails_if_folder_name_is_none(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_folder(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_register_folder_fails_if_folder_name_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_folder(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_register_folder_fails_if_folder_name_is_empty(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_folder("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_register_folder_fails_if_folder_already_exists(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog.register_folder("dog_food")

        try:
            dog.register_folder("dog_food")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_register_folder_succeeds_if_given_valid_folder_name(self):
        # become an unprivileged user
        dog = self.login("dog")

        result = dog.register_folder("dog_food")

        self.assertTrue(type(result) == HSAccessFolder)
        self.assertTrue(result.get_user_folder_name() == "dog_food")

class T12RegisterTag(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_register_tag_fails_if_tag_name_is_none(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_tag(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_register_tag_fails_if_tag_name_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_tag(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_register_tag_fails_if_tag_name_is_empty(self):
        # become an unprivileged user
        dog = self.login("dog")

        try:
            dog.register_tag("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_register_tag_fails_if_tag_already_exists(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog.register_tag("dog_food")

        try:
            dog.register_tag("dog_food")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_register_tag_succeeds_if_given_valid_tag_name(self):
        # become an unprivileged user
        dog = self.login("dog")

        result = dog.register_tag("dog_food")

        self.assertTrue(type(result) == HSAccessTag)
        self.assertTrue(result.get_user_tag_name() == "dog_food")

class T13UnregisterFolder(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_unregister_folder_fails_if_folder_name_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_folder(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_unregister_folder_fails_if_folder_name_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_folder(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_unregister_folder_fails_if_folder_name_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_folder("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_unregister_folder_fails_if_folder_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_folder("this_folder_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_unregister_folder_succeeds_if_given_valid_folder_name(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog.register_folder("dog_food")

        dog.unregister_folder("dog_food")

        self.assertFalse(dog.get_access().folder_exists("dog_food"))

class T14UnregisterTag(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_unregister_tag_fails_if_tag_name_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_tag(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_unregister_tag_fails_if_tag_name_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_tag(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_unregister_tag_fails_if_tag_name_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_tag("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_unregister_tag_fails_if_tag_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        try:
            dog.unregister_tag("this_tag_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_unregister_tag_succeeds_if_given_valid_tag_name(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog.register_tag("dog_food")

        dog.unregister_tag("dog_food")

        self.assertFalse(dog.get_access().tag_exists("dog_food"))

class T15AddResourceToFolder(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_folder("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_add_resource_to_folder_fails_if_resource_uuid_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.add_resource(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_add_resource_to_folder_fails_if_resource_uuid_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.add_resource(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_add_resource_to_folder_fails_if_resource_uuid_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.add_resource("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_add_resource_to_folder_fails_if_resource_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.add_resource("this_resource_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_add_resource_to_folder_succeeds_if_given_valid_resource_uuid(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]
        dog_resources = dog.get_resources()
        resource_uuid = dog_resources[0].get_uuid()
        resource_name = dog_resources[0].get_title()

        dog_folder.add_resource(resource_uuid)

        dog_folder_resources = dog_folder.get_resources()

        dog_folder_names = []
        for resource in dog_folder_resources:
            dog_folder_names.append(resource.get_title())

        self.assertTrue(resource_name in dog_folder_names)

class T16AddResourceToTag(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_tag("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_add_resource_to_tag_fails_if_resource_uuid_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.add_resource(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_add_resource_to_tag_fails_if_resource_uuid_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.add_resource(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_add_resource_to_tag_fails_if_resource_uuid_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.add_resource("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_add_resource_to_tag_fails_if_resource_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.add_resource("this_resource_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_add_resource_to_tag_succeeds_if_given_valid_resource_uuid(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]
        dog_resources = dog.get_resources()
        resource_uuid = dog_resources[0].get_uuid()
        resource_name = dog_resources[0].get_title()

        dog_tag.add_resource(resource_uuid)

        dog_tag_resources = dog_tag.get_resources()

        dog_tag_names = []
        for resource in dog_tag_resources:
            dog_tag_names.append(resource.get_title())

        self.assertTrue(resource_name in dog_tag_names)

class T17RemoveResourceFromFolder(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_folder("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_remove_resource_from_folder_fails_if_resource_uuid_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.remove_resource(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_remove_resource_from_folder_fails_if_resource_uuid_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.remove_resource(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_remove_resource_from_folder_fails_if_resource_uuid_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.remove_resource("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_remove_resource_from_folder_fails_if_resource_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]

        try:
            dog_folder.remove_resource("this_resource_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_remove_resource_from_folder_fails_if_folder_does_not_have_the_resource(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]
        dog_resource = dog.get_resources()[0].get_uuid()

        try:
            dog_folder.remove_resource(dog_resource)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_06_remove_resource_from_folder_succeeds_if_given_valid_resource_uuid(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_folder = dog.get_folders()[0]
        dog_resources = dog.get_resources()
        resource_uuid = dog_resources[0].get_uuid()
        resource_name = dog_resources[0].get_title()

        dog_folder.add_resource(resource_uuid)

        dog_folder_resources = dog_folder.get_resources()

        dog_folder_names = []
        for resource in dog_folder_resources:
            dog_folder_names.append(resource.get_title())

        self.assertTrue(resource_name in dog_folder_names)

        dog_folder.remove_resource(resource_uuid)

        dog_folder_resources = dog_folder.get_resources()

        dog_folder_names = []
        for resource in dog_folder_resources:
            dog_folder_names.append(resource.get_title())

        self.assertFalse(resource_name in dog_folder_names)

class T18RemoveResourceFromTag(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_tag("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_remove_resource_from_tag_fails_if_resource_uuid_is_none(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.remove_resource(None)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_02_remove_resource_from_tag_fails_if_resource_uuid_is_the_wrong_type(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.remove_resource(123)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_03_remove_resource_from_tag_fails_if_resource_uuid_is_empty(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.remove_resource("")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_04_remove_resource_from_tag_fails_if_resource_does_not_exist(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]

        try:
            dog_tag.remove_resource("this_resource_does_not_exist")
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_05_remove_resource_from_tag_fails_if_tag_does_not_have_the_resource(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]
        dog_resource = dog.get_resources()[0].get_uuid()

        try:
            dog_tag.remove_resource(dog_resource)
            self.fail("expected an exception")
        except HSAUsageException, ex:
            pass
        except:
            self.fail("expected an HSAException")

    def test_06_remove_resource_from_tag_succeeds_if_given_valid_resource_uuid(self):
        # become an unprivileged user
        dog = self.login('dog')

        dog_tag = dog.get_tags()[0]
        dog_resources = dog.get_resources()
        resource_uuid = dog_resources[0].get_uuid()
        resource_name = dog_resources[0].get_title()

        dog_tag.add_resource(resource_uuid)

        dog_tag_resources = dog_tag.get_resources()

        dog_tag_names = []
        for resource in dog_tag_resources:
            dog_tag_names.append(resource.get_title())

        self.assertTrue(resource_name in dog_tag_names)

        dog_tag.remove_resource(resource_uuid)

        dog_tag_resources = dog_tag.get_resources()

        dog_tag_names = []
        for resource in dog_tag_resources:
            dog_tag_names.append(resource.get_title())

        self.assertFalse(resource_name in dog_tag_names)

class T19GetResourcesInFolder(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_folder("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_get_resources_in_folder_returns_a_list_of_resources(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog_folder = dog.get_folders()[0]

        dog_folder.add_resource(dog.get_resources()[0].get_uuid())

        dog_folder_resources = dog_folder.get_resources()

        self.assertTrue(type(dog_folder_resources) == list)
        self.assertTrue(type(dog_folder_resources[0]) == HSAccessResource)
        self.assertTrue(dog_folder_resources[0].get_title() == "kibbles")

    def test_02_get_resources_in_folder_returns_an_empty_list_in_no_resources_exist(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog_folder = dog.get_folders()[0]

        dog_folder_resources = dog_folder.get_resources()

        self.assertTrue(type(dog_folder_resources) == list)
        self.assertTrue(len(dog_folder_resources) == 0)

class T20GetResourcesByTag(unittest.TestCase):
    def setUp(self):
        # start as privileged user
        admin = self.login('admin')
        admin._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")
        admin_caps = admin.get_capabilities()
        # don't store user objects; they get stale quickly.
        admin_caps['register_user']('cat', 'one mean meower')
        admin_caps['register_user']('dog', 'one little arfer')

        dog = self.login("dog")
        dog.register_tag("dog_food")
        dog.register_resource("/dog/food", "kibbles")

    def login(self, login):
        self.hsaccess_instance = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user_object = HSAccessUser(self.hsaccess_instance, self.hsaccess_instance.get_uuid())
        return self.user_object

    def test_01_get_resources_by_tag_returns_a_list_of_resources(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog_tag = dog.get_tags()[0]

        dog_tag.add_resource(dog.get_resources()[0].get_uuid())

        dog_tag_resources = dog_tag.get_resources()

        self.assertTrue(type(dog_tag_resources) == list)
        self.assertTrue(type(dog_tag_resources[0]) == HSAccessResource)
        self.assertTrue(dog_tag_resources[0].get_title() == "kibbles")

    def test_02_get_resources_by_tag_returns_an_empty_list_in_no_resources_exist(self):
        # become an unprivileged user
        dog = self.login("dog")

        dog_tag = dog.get_tags()[0]

        dog_tag_resources = dog_tag.get_resources()

        self.assertTrue(type(dog_tag_resources) == list)
        self.assertTrue(len(dog_tag_resources) == 0)

if __name__ == '__main__':
    unittest.main()
