__author__ = 'Alva'

import HSAlib

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

ha = startup('admin')
ha._global_reset("yes, I'm sure")   # clear the database

print "user_login_exists('fat') is ",ha.user_exists('fat')

uuuid03 = ha.assert_user('cat', 'Not a Dog', user_uuid='guiduser0003')
uuuid02 = ha.assert_user('foo', 'More About Foo', True, False)

print "get_user_logins() is ",ha._get_user_logins()

print "get_user_id_from_login('cat') is ",ha._get_user_id_from_login('cat')
print "get_user_id_from_login('foo') is ",ha._get_user_id_from_login('foo')
# we need to assert the resource uuid in the second call,
# but need to check whether it exists first.
ruid01 = ha.assert_resource( "/couch/foo", "My favorite Bathtime Gurgles", False)
ruid02 = ha.assert_resource("/foo/foo", "I seem to be having trouble with my lifestyle", False)
print "ruid02 is", ruid02
print "ruid01 is", ruid01
ha.share_resource_with_user(ruid02, uuuid03, 'own')
guid01 = ha.assert_group("This is a group", True)
guid02 = ha.assert_group("This is another group", True)
ha.share_resource_with_group(ruid01, guid01, "ro")
ha.share_group_with_user(guid02, uuuid02, "rw")
ha.share_group_with_user(guid02, uuuid02)
print "get groups for user", uuuid02, "is", ha.get_groups_for_user(uuuid02)

print ha.resources_held_by_user(uuuid02)
print ha.groups_of_user(uuuid02)
print ha.get_groups()
print ha.get_group_metadata(guid01)
print ha.get_user_metadata(uuuid02)
print ha.get_resource_metadata(ruid01)