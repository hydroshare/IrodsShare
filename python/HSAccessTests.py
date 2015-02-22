__author__ = 'Alva'

import HSAlib
ha = HSAlib.HSAccess('acouch', 'acouch', 'xyzzy', 'localhost', '5432')

print "user_login_exists('fat') is ",ha.user_exists('fat')

ha.assert_user('cat', 'admin', 'guiduser0003', 'Not a Dog')
ha.assert_user('foo', 'admin', 'guiduser0002', 'More About Foo', True, False)

print "get_user_logins() is ",ha.get_user_logins()


print "get_user_id_from_login('cat') is ",ha._get_user_id_from_login('cat')
print "get_user_id_from_login('foo') is ",ha._get_user_id_from_login('foo')

ha.assert_resource('ruid0001', 'admin', "/couch/foo", "My favorite Bathtime Gurgles", False)
ha.assert_resource('ruid0002', 'foo', "/foo/foo", "I seem to be having trouble with my lifestyle", False)
ha.share_resource_with_user('admin', 'ruid0002', 'cat', 'own')
ha.assert_group("groupguid0001", "admin", "This is a group")
ha.assert_group('groupguid0002', "admin", "This is another group")
ha.share_resource_with_group("admin", "ruid0001", "groupguid0001", "ro")
ha.share_group_with_user("admin", "groupguid0001", "foo", "rw")
ha.assert_user_in_group('admin', 'foo', 'groupguid0001')

print ha.resources_held_by_user('foo')
print ha.groups_of_user('foo')
print ha.get_groups()
print ha.get_resource_metadata("ruid0001")