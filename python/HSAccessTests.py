__author__ = 'Alva'

import HSAlib

ha = HSAlib.HSAccess('admin', 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

print "user_login_exists('fat') is ",ha.user_exists('fat')

ha.assert_user('guiduser0003', 'cat', 'Not a Dog')
ha.assert_user('guiduser0002', 'foo', 'More About Foo', True, False)

print "get_user_logins() is ",ha.get_user_logins()

print "get_user_id_from_login('cat') is ",ha._get_user_id_from_login('cat')
print "get_user_id_from_login('foo') is ",ha._get_user_id_from_login('foo')

ha.assert_resource('ruid0001',  "/couch/foo", "My favorite Bathtime Gurgles", False)
ha.assert_resource('ruid0002',  "/foo/foo", "I seem to be having trouble with my lifestyle", False)
ha.share_resource_with_user('ruid0002', 'guiduser0003', 'own')
ha.assert_group("groupguid0001", "This is a group", True)
ha.assert_group('groupguid0002', "This is another group", True)
ha.share_resource_with_group("ruid0001", "groupguid0001", "ro")
ha.share_group_with_user("groupguid0001", "guiduser0002", "rw")
ha.assert_user_in_group('guiduser0002', 'groupguid0001')

print ha.resources_held_by_user('guiduser0002')
print ha.groups_of_user('guiduser0002')
print ha.get_groups()
print ha.get_group_metadata('groupguid0001')
print ha.get_user_metadata('guiduser0002')
print ha.get_resource_metadata("ruid0001")