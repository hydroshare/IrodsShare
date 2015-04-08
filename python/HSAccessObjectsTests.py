__author__ = 'Alva'
from HSAlib import HSAccess, HSAccessException, HSAUsageException, HSAIntegrityException
from HSAccessObjects import HSAccessUser, HSAccessGroup, HSAccessResource

import unittest
from pprint import pprint


class Stasher(object):

    def __init__(self):
        self.test_context = {'users':{}, 'groups':{}, 'resources':{}}
        self.hsa = None
        self.login_name = None
        self.user = None

    def login(self, login):
        self.hsa = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
        self.login_name = login
        self.user = HSAccessUser(self.hsa, self.hsa.get_uuid())
        self.stash_user(self.user, login)
        # pprint(stasher)
        return self.user

    def reset(self):
        self.hsa._HSAccessCore__global_reset("yes, I'm sure")

    def stash_user(self, user, name):
        if type(user) is not HSAccessUser:
            raise HSAUsageException("cannot stash non-user")
        if name in self.test_context['users'].keys()\
                and self.test_context['users'][name] != user.get_uuid():
            raise HSAIntegrityException("attempt to change user id for name not allowed")
        self.test_context['users'][name] = user.get_uuid()

    def get_user(self, name):
        if type(name) is not str:
            raise HSAUsageException("name is not a string")
        return HSAccessUser(self.hsa, self.test_context['users'][name])

    def stash_group(self, group, name):
        if type(group) is not HSAccessGroup:
            raise HSAUsageException("cannot stash non-group")
        if name in self.test_context['groups'].keys():
            raise HSAIntegrityException("attempt to reuse group name is not allowed")
        # print "group name is ", group.get_name()
        # print "name is ", name
        # print "uuid is ", group.get_uuid()
        self.test_context['groups'][name] = group.get_uuid()
        # pprint(self.test_context)

    def get_group(self, name):
        if type(name) is not str:
            raise HSAUsageException("name is not a string")
        return HSAccessGroup(self.hsa, self.test_context['groups'][name])

    def stash_resource(self, resource, name):
        if type(resource) is not HSAccessResource:
            raise HSAUsageException("cannot stash non-resource")
        if name in self.test_context['resources'].keys():
            raise HSAIntegrityException("attempt to reuse resource name not allowed")
        self.test_context['resources'][name] = resource.get_uuid()

    def get_resource(self, name):
        if type(name) is not str:
            raise HSAUsageException("name is not a string")
        return HSAccessResource(self.hsa, self.test_context['resources'][name])


def match_lists(l1, l2):
    return len(set(l1) & set(l2)) == len(set(l1))


stasher = Stasher()


class T01Reset(unittest.TestCase):
    def test(self):
        global stasher
        current = stasher.login('admin')
        stasher.reset()


class T02CreateUser(unittest.TestCase):
    def test(self):
        global stasher
        # start as privileged user
        admin = stasher.login('admin')

        self.assertTrue(admin.get_access().get_number_of_resources_owned_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_groups_owned_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_resources_held_by_user() == 0)
        self.assertTrue(admin.get_access().get_number_of_groups_of_user() == 0)
        admin_caps = admin.get_capabilities()
        self.assertTrue('register_user' in admin_caps.keys())

        cat = admin_caps['register_user']('cat', 'not a dog', True, False)
        stasher.stash_user(cat, 'cat')

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

        # make user an admin, and back 
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

        # make user inactive, and back 
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

        # make another user 
        dog = admin_caps['register_user']('dog', 'one little arfer')
        stasher.stash_user(dog, 'dog')
        self.assertTrue(dog.get_login() == 'dog')
        self.assertTrue(dog.get_name() == 'one little arfer')
        self.assertTrue(dog.is_active())
        self.assertFalse(dog.is_admin())


class T03RegularUser(unittest.TestCase):
    def test(self):
        global stasher

        # become an unprivileged user
        cat = stasher.login('cat')

        cat_caps = cat.get_capabilities()
        self.assertTrue('register_user' not in cat_caps.keys())
        self.assertTrue(len(cat_caps.keys()) == 0)


class T04RegisterResource(unittest.TestCase):
    def test(self):
        global stasher

        # become an unprivileged user
        cat = stasher.login('cat')

        # create a resource
        posts = cat.register_resource('/cat/posts', 'all about scratching posts')
        stasher.stash_resource(posts, 'posts')

        self.assertTrue(posts.get_path() == '/cat/posts')
        self.assertTrue(posts.get_title() == 'all about scratching posts')
        self.assertFalse(posts.is_discoverable())
        self.assertFalse(posts.is_public())
        self.assertFalse(posts.is_published())
        self.assertTrue(posts.is_shareable())
        self.assertFalse(posts.is_immutable())
        self.assertTrue(posts.is_owned())
        self.assertTrue(posts.is_writeable())
        self.assertTrue(posts.is_readable())
        self.assertTrue(posts.get_privilege() == 'own')

        #####################
        # test shareability
        #####################
        rcaps = posts.get_capabilities()
        self.assertTrue('make_shareable' not in rcaps.keys())
        self.assertTrue('make_not_shareable' in rcaps.keys())

        rcaps['make_not_shareable']()
        self.assertFalse(posts.is_shareable())

        # must re-read capabilities; not refreshed
        rcaps = posts.get_capabilities()  
        self.assertTrue('make_shareable' in rcaps.keys())
        self.assertTrue('make_not_shareable' not in rcaps.keys())

        rcaps['make_shareable']()
        self.assertTrue(posts.is_shareable())

        rcaps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_shareable' not in rcaps.keys())
        self.assertTrue('make_not_shareable' in rcaps.keys())

        #####################
        # test discoverability
        #####################
        rcaps = posts.get_capabilities()
        self.assertTrue('make_discoverable' in rcaps.keys())
        self.assertTrue('make_not_discoverable' not in rcaps.keys())

        rcaps['make_discoverable']()
        self.assertTrue(posts.is_discoverable())

        # must re-read capabilities; not refreshed
        rcaps = posts.get_capabilities()  
        self.assertTrue('make_discoverable' not in rcaps.keys())
        self.assertTrue('make_not_discoverable' in rcaps.keys())

        rcaps['make_not_discoverable']()
        self.assertFalse(posts.is_discoverable())

        rcaps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' in rcaps.keys())
        self.assertTrue('make_not_discoverable' not in rcaps.keys())

        #####################
        # test public
        #####################
        rcaps = posts.get_capabilities()
        self.assertTrue('make_public' in rcaps.keys())
        self.assertTrue('make_not_public' not in rcaps.keys())

        rcaps['make_public']()
        self.assertTrue(posts.is_public())

        # must re-read capabilities; not refreshed
        rcaps = posts.get_capabilities()  
        self.assertTrue('make_public' not in rcaps.keys())
        self.assertTrue('make_not_public' in rcaps.keys())

        rcaps['make_not_public']()
        self.assertFalse(posts.is_public())

        rcaps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_public' in rcaps.keys())
        self.assertTrue('make_not_public' not in rcaps.keys())

        #####################
        # test publication
        #####################
        rcaps = posts.get_capabilities()
        self.assertTrue('make_published' in rcaps.keys())
        self.assertTrue('make_not_published' not in rcaps.keys())

        rcaps['make_published']()
        self.assertTrue(posts.is_published())

        # must re-read capabilities; not refreshed
        rcaps = posts.get_capabilities()  
        self.assertTrue('make_published' not in rcaps.keys())
        self.assertTrue('make_not_published' in rcaps.keys())

        rcaps['make_not_published']()
        self.assertFalse(posts.is_published())

        rcaps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_published' in rcaps.keys())
        self.assertTrue('make_not_published' not in rcaps.keys())

        #####################
        # test immutability 
        #####################
        rcaps = posts.get_capabilities()
        self.assertTrue('make_immutable' in rcaps.keys())
        self.assertTrue('make_not_immutable' not in rcaps.keys())

        rcaps['make_immutable']()
        self.assertTrue(posts.is_immutable())

        # must re-read capabilities; not refreshed
        rcaps = posts.get_capabilities()  
        self.assertTrue('make_immutable' not in rcaps.keys())
        self.assertTrue('make_not_immutable' not in rcaps.keys())

        try: 
            rcaps['make_not_immutable']()
            self.fail("should not be able to override immutability") 
        except: 
            pass

        self.assertTrue(posts.is_immutable())

        rcaps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_immutable' not in rcaps.keys())
        self.assertTrue('make_not_immutable' not in rcaps.keys())

        # check that the resource is listed properly in get_resources()
        resources = cat.get_resources()
        self.assertTrue(len(resources) == 1)
        self.assertTrue(resources[0].get_title() == 'all about scratching posts')


class T05ResourceFlagSemantics(unittest.TestCase):
    def test(self):
        global stasher

        # become an unprivileged user
        cat = stasher.login('cat')

        # grab a previously created resource
        posts = stasher.get_resource('posts')

        # test basic semantics of public resources

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 0)

        posts_caps = posts.get_capabilities()
        posts_caps['make_public']()

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 1)
        self.assertTrue(public[0].get_title() == 'all about scratching posts')

        posts_caps = posts.get_capabilities()
        posts_caps['make_not_public']()

        public = cat.get_public_resources()
        self.assertTrue(len(public) == 0)

        # test basic semantics of discoverability
        # making something public makes it discoverable

        discoverable = cat.get_discoverable_resources()
        # pprint(discoverable)
        self.assertTrue(len(discoverable) == 0)
        self.assertFalse(posts.is_discoverable())

        posts_caps = posts.get_capabilities()
        posts_caps['make_discoverable']()
        self.assertTrue(posts.is_discoverable())

        # is it listed amongst discoverable resources?
        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 1)
        self.assertTrue(discoverable[0].get_title() == 'all about scratching posts')

        # set it back to not discoverable
        posts_caps = posts.get_capabilities()
        posts_caps['make_not_discoverable']()
        self.assertFalse(posts.is_discoverable())


class T06RegisterGroup(unittest.TestCase):
    def test(self):
        global stasher

        # become an unprivileged user
        cat = stasher.login('cat')

        # create a resource 
        meowers = cat.register_group('meowers')
        stasher.stash_group(meowers, 'meowers')
        # pprint(stasher.test_context)
        # meowers.pprint()

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
        rcaps = meowers.get_capabilities()
        self.assertTrue('make_shareable' not in rcaps.keys())
        self.assertTrue('make_not_shareable' in rcaps.keys())

        rcaps['make_not_shareable']()
        self.assertFalse(meowers.is_shareable())

        # must re-read capabilities; not refreshed
        rcaps = meowers.get_capabilities()  
        self.assertTrue('make_shareable' in rcaps.keys())
        self.assertTrue('make_not_shareable' not in rcaps.keys())

        rcaps['make_shareable']()
        self.assertTrue(meowers.is_shareable())

        rcaps = meowers.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_shareable' not in rcaps.keys())
        self.assertTrue('make_not_shareable' in rcaps.keys())

        #####################
        # test discoverability
        #####################
        rcaps = meowers.get_capabilities()
        # pprint(rcaps.keys())
        self.assertTrue(meowers.is_discoverable())
        self.assertTrue('make_discoverable' not in rcaps.keys())
        self.assertTrue('make_not_discoverable' in rcaps.keys())

        rcaps['make_not_discoverable']()
        self.assertFalse(meowers.is_discoverable())

        # must re-read capabilities; not refreshed
        rcaps = meowers.get_capabilities()  
        self.assertTrue('make_discoverable' in rcaps.keys())
        self.assertTrue('make_not_discoverable' not in rcaps.keys())

        rcaps['make_discoverable']()
        self.assertTrue(meowers.is_discoverable())

        rcaps = meowers.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' not in rcaps.keys())
        self.assertTrue('make_not_discoverable' in rcaps.keys())

        #####################
        # test public
        #####################
        rcaps = meowers.get_capabilities()
        self.assertTrue(meowers.is_public())
        self.assertTrue('make_public' not in rcaps.keys())
        self.assertTrue('make_not_public' in rcaps.keys())

        rcaps['make_not_public']()
        self.assertFalse(meowers.is_public())

        # must re-read capabilities; not refreshed
        rcaps = meowers.get_capabilities()  
        self.assertTrue('make_public' in rcaps.keys())
        self.assertTrue('make_not_public' not in rcaps.keys())

        rcaps['make_public']()
        self.assertTrue(meowers.is_public())

        # must re-read capabilities; not regenerated
        rcaps = meowers.get_capabilities()  
        self.assertTrue('make_public' not in rcaps.keys())
        self.assertTrue('make_not_public' in rcaps.keys())

        # check that the group is listed properly in get_groups()
        groups = cat.get_groups()
        self.assertTrue(len(groups) == 1)
        self.assertTrue(groups[0].get_name() == 'meowers')


class T07GroupFlagSemantics(unittest.TestCase):
    def test(self):
        global stasher

        # test basic semantics of public groups

        # need to switch user here and test that it is visible
        dog = stasher.login('cat')
        public = dog.get_public_groups()

        self.assertTrue(len(public) == 1)
        self.assertTrue(public[0].get_name() == 'meowers')

        # and that it is really public
        gcaps = public[0].get_capabilities()
        self.assertTrue('get_members' in gcaps.keys())
        members = gcaps['get_members']()
        self.assertTrue(len(members) == 1)
        self.assertTrue(members[0].get_name() == 'one mean meower')

        cat = stasher.login('cat')
        meowers = stasher.get_group('meowers')
        meowers_caps = meowers.get_capabilities()
        meowers_caps['make_not_public']()

        # need to switch user here and test whether it is really invisible
        dog = stasher.login('dog')
        meowers = stasher.get_group('meowers')
        public = dog.get_public_groups()
        self.assertTrue(len(public) == 0)

        # set it back to public
        cat = stasher.login('cat')
        meowers = stasher.get_group('meowers')
        meowers_caps = meowers.get_capabilities()
        meowers_caps['make_public']()

        public = cat.get_public_groups()
        self.assertTrue(len(public) == 1)
        self.assertTrue(public[0].get_name() == 'meowers')

        # need to switch user here and test that it is visible
        dog = stasher.login('dog')
        public = dog.get_public_groups()
        self.assertTrue(len(public) == 1)
        self.assertTrue(public[0].get_name() == 'meowers')

        # and that it is really public
        gcaps = public[0].get_capabilities()
        self.assertTrue('get_members' in gcaps.keys())
        members = gcaps['get_members']()
        self.assertTrue(len(members) == 1)
        self.assertTrue(members[0].get_name() == 'one mean meower')

        # test basic semantics of discoverability
        # first switch back to using user 'cat'
        cat = stasher.login('cat')
        meowers = stasher.get_group('meowers')

        discoverable = cat.get_discoverable_groups()
        self.assertTrue(len(discoverable) == 1)
        self.assertTrue(discoverable[0].get_name() == 'meowers')
        self.assertTrue(meowers.is_discoverable())

        meowers_caps = meowers.get_capabilities()
        meowers_caps['make_not_discoverable']()

        # is it definitely not discoverable now?
        self.assertFalse(meowers.is_discoverable())
        discoverable = cat.get_discoverable_resources()
        self.assertTrue(len(discoverable) == 0)

        # set it back to discoverable
        meowers_caps = meowers.get_capabilities()
        meowers_caps['make_discoverable']()
        self.assertTrue(meowers.is_discoverable())


class T08ShareResource(unittest.TestCase):
    def test(self):
        global stasher
        # become an unprivileged user
        cat = stasher.login('cat')

        # get a resource to share 
        posts = stasher.get_resource('posts')
        rcaps = posts.get_capabilities()

        # check that we can share, and share object 
        self.assertTrue('share_with_user' in rcaps.keys())
        rcaps['share_with_user'](stasher.get_user('dog'), 'ro')

        # check that we can get the number of accessing users, and get users
        self.assertTrue('get_users' in rcaps.keys())
        users = rcaps['get_users']()

        # check that the number of users is correct 
        self.assertTrue(len(users) == 2)
        logins = [p.get_login() for p in users]
        # pprint(logins)
        self.assertTrue(match_lists(logins, ['cat', 'dog']))

        # note: the object for a resource remembers the current user.
        # we must recontextualize when changing users

        dog = stasher.login('dog')
        resources = dog.get_resources()
        self.assertTrue(len(resources) == 1)
        self.assertTrue(resources[0].get_title() == 'all about scratching posts')
        posts = resources[0]  # must recontextualize object from point of view of 'dog' user

        self.assertTrue(posts.is_readable())
        self.assertFalse(posts.is_writeable())
        self.assertFalse(posts.is_owned())
        self.assertTrue(posts.get_privilege() == 'ro')

        rcaps = posts.get_capabilities()
        self.assertTrue(match_lists(rcaps.keys(), ['share_with_user', 'share_with_group']))

if __name__ == '__main__':
    unittest.main()
