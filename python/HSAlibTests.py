__author__ = 'Alva'
import HSAlib
import unittest

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

def reset():
    ha = startup('admin')
    # this doesn't seem to work because of remote execution.
    # it seems to want to fetch the file from somewhere else.
    # it works when running locally.
    # file = open("/home/acouch/database.psql", "r")
    # junk = file.read()
    # ha._conn.autocommit = True
    # ha._cur.execute(junk)
    # ha._conn.autocommit = False
    # ha._conn.commit()

class T01_Reset(unittest.TestCase):
    def test(self):
        ha = startup('admin')
        ha._global_reset(("yes, I'm sure"))

class T02_CreateUser(unittest.TestCase):
    def test(self):
        # start as privileged user
        ha = startup('admin')
        uuid01 = ha.assert_user('cat', 'not a dog', True, False, user_uuid="uuid01")
        self.assertTrue(uuid01 is "uuid01")
        meta = ha.get_user_metadata(uuid01)
        # print meta
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a dog')
        self.assertTrue(meta['active'] == True)
        self.assertTrue(meta['admin'] == False)
        ha.assert_user('cat', 'not a gerbil', True, False, user_uuid=uuid01)
        meta = ha.get_user_metadata(uuid01)
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'] == True)
        self.assertTrue(meta['admin'] == False)
        # now try to do something as cat
        ha = startup('cat')
        ha.get_user_metadata(uuid01)
        self.assertTrue(meta['login'] == 'cat')
        self.assertTrue(meta['name'] == 'not a gerbil')
        self.assertTrue(meta['active'] == True)
        self.assertTrue(meta['admin'] == False)
        # now start up as admin again
        ha=startup('admin')
        uuid02 = ha.assert_user('dog', 'Meow', True, False)
        self.assertTrue(len(uuid02) == 32)
        meta=ha.get_user_metadata(uuid02)
        self.assertTrue(meta['login'] == 'dog')
        self.assertTrue(meta['name'] == 'Meow')
        self.assertTrue(meta['active'] == True)
        self.assertTrue(meta['admin'] == False)
        self.assertTrue(len(uuid02) == 32)
        ha = startup('cat')
        try:
            temp = ha.assert_user('gerbil', 'Woof', True, False)
            self.assertTrue(False)
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "User uuid 'uuid01' is not an administrator; operation requires privilege")

class T03_CreateResource(unittest.TestCase):
    def test(self):
        ha = startup('cat') # regular user
        # print "cat uuid is",ha._user_uuid
        ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
        self.assertTrue(ruid01 == 'ruid01')
        meta = ha.get_resource_metadata(ruid01)
        # print meta['title']
        self.assertTrue(meta['title'] == 'all about dogs')
        self.assertTrue(meta['path'] == '/cat/foo')
        self.assertTrue(meta['immutable'] == False)
        self.assertTrue(ha.resource_exists(ruid01))
        self.assertTrue(not ha.resource_is_immutable(ruid01))
        self.assertTrue(ha.resource_is_owned(ruid01))
        self.assertTrue(ha.resource_is_readwrite(ruid01))
        self.assertTrue(ha.resource_is_readable(ruid01))
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01))
        ha.assert_resource('/cat/bar', 'no more about dogs', False, resource_uuid=ruid01)
        meta = ha.get_resource_metadata(ruid01)
        self.assertTrue(meta['title'] == 'no more about dogs')
        self.assertTrue(meta['path'] == '/cat/bar')
        self.assertTrue(meta['immutable'] == False)

class T04_CreateGroup(unittest.TestCase):
    def test(self):
        ha = startup('dog') # regular user
        # print "cat uuid is",ha._user_uuid
        uuid01 = ha._user_uuid
        guid01 = ha.assert_group('arfers', group_uuid='guid01')
        self.assertTrue(guid01 == 'guid01')
        meta = ha.get_group_metadata(guid01)
        self.assertTrue(len(meta) == 6)
        self.assertTrue(meta['name'] == 'arfers')
        self.assertTrue(meta['uuid'] == guid01)
        self.assertTrue(meta['asserting_login'] == 'dog')
        self.assertTrue(ha.group_exists(guid01))
        self.assertTrue(ha.group_is_owned(guid01))
        self.assertTrue(ha.group_is_readwrite(guid01))
        self.assertTrue(ha.group_is_readable(guid01))
        self.assertTrue(ha.group_is_readable_without_sharing(guid01))
        ha.assert_group('all about dogs', group_uuid=guid01)
        meta = ha.get_group_metadata(guid01)
        self.assertTrue(len(meta) == 6)
        self.assertTrue(meta['name'] == 'all about dogs')
        self.assertTrue(meta['uuid'] == guid01)
        self.assertTrue(meta['asserting_login'] == 'dog')
        ha.retract_group(guid01)
        # try to read the metadata of a non-existent group
        try:
            meta = ha.get_group_metadata(guid01)
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == "no such group " + guid01)

class T05_ProtectResource(unittest.TestCase):
    def test(self):
        ha= startup('cat')
        dog_uuid = ha._get_user_uuid_from_login('dog')
        ruid01 = 'ruid01'

        # dog should not have sharing privileges
        ha = startup('dog')
        # print ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)
        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==100)
        self.assertTrue(ha.resource_is_owned(ruid01)==False)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==False)
        self.assertTrue(ha.resource_is_readable(ruid01)==False)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==False)
        try:
            ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # now share something with dog
        ha = startup('cat')
        ha.share_resource_with_user(ruid01, dog_uuid, 'own')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==1)
        self.assertTrue(ha.resource_is_owned(ruid01)==True)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==True)
        self.assertTrue(ha.resource_is_readable(ruid01)==True)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==True)
        try:
            ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
        except HSAlib.HSAException as e:
            self.assertTrue("invalid exception" == "")

        # downgrade permission to rw
        ha = startup('cat')
        ha.share_resource_with_user(ruid01, dog_uuid, 'rw')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==2)
        self.assertTrue(ha.resource_is_owned(ruid01)==False)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==True)
        self.assertTrue(ha.resource_is_readable(ruid01)==True)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==True)
        try:
            ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
            self.assertTrue("unreachable line reached" == "")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # downgrade permission to 'ro'
        ha = startup('cat')
        ha.share_resource_with_user(ruid01, dog_uuid, 'ro')
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==3)
        self.assertTrue(ha.resource_is_owned(ruid01)==False)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==False)
        self.assertTrue(ha.resource_is_readable( ruid01)==True)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==True)
        try:
            ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        ha= startup('cat')
        ha.unshare_resource_with_user(ruid01, dog_uuid)
        meowers = ha.assert_group('some random meowers', group_uuid='guid02')
        ha.assert_user_in_group(dog_uuid, meowers)
        try:
            ha.share_resource_with_group(ruid01, meowers, 'own')
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value=="Cannot assert 'ownership' privilege for a group")

        ha.share_resource_with_group(ruid01, meowers, 'rw')
        # ha.unshare_resource_with_group(ruid01, meowers)

        # second phase: check group membership privilege
        ha = startup('dog')
        # print ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)

        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==2)
        self.assertTrue(ha.resource_is_owned(ruid01)==False)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==True)
        self.assertTrue(ha.resource_is_readable(ruid01)==True)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==True)
        try:
            ruid01 = ha.assert_resource('/cat/foo', 'all about dogs', False, resource_uuid='ruid01')
            self.assertTrue("unreachable line reached"=="")
        except HSAlib.HSAException as e:
            self.assertTrue(e.value == 'Insufficient privileges to modify resource: must be owner or admin')

        # turn off group sharing
        ha = startup('cat')
        ha.unshare_resource_with_group(ruid01, meowers)
        ha = startup('dog')
        self.assertTrue(ha.get_user_privilege_over_resource(ha._user_uuid, ruid01)==100)
        self.assertTrue(ha.resource_is_owned(ruid01)==False)
        self.assertTrue(ha.resource_is_readwrite(ruid01)==False)
        self.assertTrue(ha.resource_is_readable(ruid01)==False)
        self.assertTrue(ha.resource_is_readable_without_sharing(ruid01)==False)

class T06_ProtectGroup(unittest.TestCase):
    def test(self):
        ha= startup('cat')


if __name__== '__main__':
    unittest.main()

