__author__ = 'Alva'

import HSAlib
from pprint import pprint

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

ha = startup('admin')
ha._HSAccessCore__global_reset("yes, I'm sure")     # clear the database

print "user_login_exists('fat') is ",ha.user_exists('fat')

uuuid03 = ha.assert_user('cat', 'Not a Dog', user_uuid='guiduser0003')
uuuid02 = ha.assert_user('foo', 'More About Foo', True, False)

print "get_user_logins() is ",ha._HSAccessCore__get_user_logins()

print "get_user_id_from_login('cat') is ",ha._HSAccessCore__get_user_id_from_login('cat')
print "get_user_id_from_login('foo') is ",ha._HSAccessCore__get_user_id_from_login('foo')
# we need to assert the resource uuid in the second call,
# but need to check whether it exists first.
ruuid01 = ha.assert_resource( "/couch/foo", "My favorite Bathtime Gurgles", None)
ruuid02 = ha.assert_resource("/foo/foo", "I seem to be having trouble with my lifestyle", None)
print "ruid02 is", ruuid02
print "ruid01 is", ruuid01
ha.share_resource_with_user(ruuid02, uuuid03, 'own')
guuid01 = ha.assert_group("This is a group", True)
guuid02 = ha.assert_group("This is another group", True)
ha.share_resource_with_group(ruuid01, guuid01, "ro")
ha.share_group_with_user(guuid02, uuuid02, "rw")
ha.share_group_with_user(guuid02, uuuid02)

print
print "get groups for user", uuuid02, "is"
pprint(ha.get_groups_for_user(uuuid02))

print
print "get resources held by user", uuuid02, "is"
pprint(ha.get_resources_held_by_user(uuuid02))

print
print "get groups of user", uuuid02, "is"
pprint(ha.get_groups_of_user(uuuid02))

print
print "get groups is"
pprint(ha.get_groups())

print
print "get group metadata for", guuid01, "is"
pprint(ha.get_group_metadata(guuid01))

print
print "get user metadata for", uuuid02, "is"
pprint(ha.get_user_metadata(uuuid02))

print
print "get_resource_metadata for", ruuid01, "is"
pprint(ha.get_resource_metadata(ruuid01))