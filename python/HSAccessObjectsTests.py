__author__ = 'Alva'
from HSAlib import HSAccess, HSAccessException, HSAUsageException, HSAIntegrityException
from HSAccessObjects import HSAccessUser, HSAccessGroup, HSAccessResource

import unittest
from pprint import pprint

def startup(login):
    hsa = HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')
    return HSAccessUser(hsa, hsa.get_uuid())

def match_lists(l1, l2):
    return len(set(l1) & set(l2)) == len(set(l1))

# storage for test context; users, groups, and resources created durign testing
context = {'groups': {}, 'users': {}, 'resources': {}}
resources = {}
users = {}
groups = {}

class T01Reset(unittest.TestCase):
    def test(self):
        hsu = startup('admin')
        hsu._HSAccessUser__hsa._HSAccessCore__global_reset("yes, I'm sure")


class T02CreateUser(unittest.TestCase):
    def test(self):
        global users
        global resources
        global groups
        # start as privileged user
        hsu = startup('admin')
        self.assertTrue(hsu.get_access().get_number_of_resources_owned_by_user() == 0)
        caps = hsu.get_capabilities()
        self.assertTrue('register_user' in caps.keys())


        cat = users['cat'] = caps['register_user']('cat', 'not a dog', True, False)

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'not a dog')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        caps = cat.get_capabilities()
        self.assertTrue('change_name' in caps.keys())
        caps['change_name']('one mean meower')

        self.assertTrue(cat.get_login() == 'cat')
        self.assertTrue(cat.get_name() == 'one mean meower')
        self.assertTrue(cat.is_active())
        self.assertFalse(cat.is_admin())

        dog = users['dog'] = caps['register_user']('dog', 'one little arfer')
        self.assertTrue(dog.get_login() == 'dog')
        self.assertTrue(dog.get_name() == 'one little arfer')
        self.assertTrue(dog.is_active())
        self.assertFalse(dog.is_admin())

        # now become an unprivileged user
        hsu = startup('cat')

        caps = hsu.get_capabilities()
        self.assertTrue('register_user' not in caps.keys())
        self.assertTrue(len(caps.keys()) == 0)

        posts = resources['posts'] = hsu.register_resource('/cat/posts', 'all about scratching posts')
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

        caps = posts.get_capabilities()
        self.assertTrue('make_discoverable' in caps.keys())
        self.assertTrue('make_not_discoverable' not in caps.keys())

        caps['make_discoverable']()
        self.assertTrue(posts.is_discoverable())

        caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' not in caps.keys())
        self.assertTrue('make_not_discoverable' in caps.keys())

        caps['make_not_discoverable']()
        self.assertFalse(posts.is_discoverable())

        caps = posts.get_capabilities()  # must re-read capabilities; not regenerated
        self.assertTrue('make_discoverable' in caps.keys())
        self.assertTrue('make_not_discoverable' not in caps.keys())

        self.assertTrue('share_with_user' in caps.keys())
        caps['share_with_user'](dog, 'ro')

        self.assertTrue('get_users' in caps.keys())
        users = caps['get_users']()
        self.assertTrue(len(users) == 2)
        logins = [p.get_login() for p in users]
        self.assertTrue(match_lists(logins, ['cat', 'dog']))

        resources = hsu.get_resources()
        self.assertTrue(len(resources) == 1)
        self.assertTrue(resources[0].get_title() == 'all about scratching posts')

        # note: the object for a resource remembers the current user.
        # we must recontextualize when changing users

        hsu = startup('dog')
        resources = hsu.get_resources()
        self.assertTrue(len(resources) == 1)
        self.assertTrue(resources[0].get_title() == 'all about scratching posts')
        posts = resources[0]  # must recontextualize object from point of view of 'dog' user

        self.assertTrue(posts.is_readable())
        self.assertFalse(posts.is_writeable())
        self.assertFalse(posts.is_owned())
        self.assertTrue(posts.get_privilege() == 'ro')

        caps = posts.get_capabilities()
        self.assertTrue(match_lists(caps.keys(), ['share_with_user', 'share_with_group']))

        # # change user metadata
        # ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=context['users']['cat'])
        # meta = ha.get_user_metadata(context['users']['cat'])
        # self.assertTrue(meta['login'] == 'cat')
        # self.assertTrue(meta['name'] == 'not a gerbil')
        # self.assertTrue(meta['active'])
        # self.assertFalse(meta['admin'])
        #
        # # now try to do something to user cat as cat
        # ha = startup('cat')
        # self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        # self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        # self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        # self.assertTrue(ha.get_number_of_groups_of_user() == 0)
        #
        # ha.get_user_metadata(context['users']['cat'])
        # self.assertTrue(meta['login'] == 'cat')
        # self.assertTrue(meta['name'] == 'not a gerbil')
        # self.assertTrue(meta['active'])
        # self.assertFalse(meta['admin'])
        #
        # # now start up as admin again
        # ha = startup('admin')
        # self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        # self.assertTrue(ha.get_number_of_groups_owned_by_user() == 0)
        # self.assertTrue(ha.get_number_of_resources_held_by_user() == 0)
        # self.assertTrue(ha.get_number_of_groups_of_user() == 0)
        #
        # # make a user 'dog'
        # context['users']['dog'] = ha.assert_user('dog', 'Meow', True, False)
        # self.assertTrue(len(context['users']['dog']) == 32)
        #
        # meta = ha.get_user_metadata(context['users']['dog'])
        # self.assertTrue(meta['login'] == 'dog')
        # self.assertTrue(meta['name'] == 'Meow')
        # self.assertTrue(meta['active'])
        # self.assertFalse(meta['admin'])
        #
        # ha = startup('cat')
        #
        # # this should fail; non-administrators cannot create users
        # try:
        #     ha.assert_user('gerbil', 'Woof', True, False)
        #     self.fail("a non-administrator should not be able to create a user")
        # except HSAlib.HSAccessException as e:
        #     self.assertTrue(e.value == "User is not an administrator")
        # self.assertTrue(ha.get_number_of_resources_owned_by_user() == 0)
        #
        # # check on user logins
        # logins = ha._HSAccessCore__get_user_logins() # private function: used for testing only
        # self.assertTrue(match_lists(logins, ['admin', 'cat', 'dog']))
        # # pprint(logins)
        #

if __name__ == '__main__':
    unittest.main()