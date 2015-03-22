__author__ = 'Alva'

import HSAlib
from HSAccessObjects import HSAccessUser, HSAccessGroup, HSAccessResource
from pprint import pprint

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

ha = startup('admin')
ha._HSAccessCore__global_reset("yes, I'm sure")     # clear the database

userAdmin = HSAccessUser(ha, ha.get_uuid())
uJoe = userAdmin.register_user('joe', 'Joe Cool')
uFrank = userAdmin.register_user('frank', 'Frank Furter')
uIma = userAdmin.register_user('ima', 'Ima Nutcase', False, False)
pprint(uJoe)
print "Joe is admin? ", uJoe.is_admin()
print "Joe is active? ", uJoe.is_active()
pprint(uFrank)
print "Frank is admin? ", uFrank.is_admin()
print "Frank is active? ", uFrank.is_active()
pprint(uIma)
print "Ima is admin? ", uIma.is_admin()
print "Ima is active? ", uFrank.is_active()
ha = startup('joe')
uJoe = HSAccessUser(ha, uJoe.get_uuid())
gCoolies = uJoe.create_group('coolies')
pprint(gCoolies)
print "Coolies is active? ", gCoolies.is_active()
print "Joe owns Coolies?", gCoolies.is_owned()
pprint(gCoolies.get_capabilities())
caps = gCoolies.get_capabilities()
caps['make_not_discoverable']()
pprint(gCoolies.get_capabilities())

rDives = uJoe.register_resource("/joe/dives", "The best dives")
rDivesCaps = rDives.get_capabilities()
pprint(rDivesCaps)
rDivesCaps['change_title']("The bestest dives")
print "Dives title is ", rDives.get_title()



