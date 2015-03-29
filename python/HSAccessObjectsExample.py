__author__ = 'Alva'

import HSAlib
from HSAccessObjects import HSAccessUser, HSAccessGroup, HSAccessResource
from pprint import pprint

def startup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

ha = startup('admin')
ha._HSAccessCore__global_reset("yes, I'm sure")     # clear the database

uAdmin = HSAccessUser(ha, ha.get_uuid())
uAdmin.pprint()

uJoe = uAdmin.get_capabilities()['register_user']('joe', 'Joe Cool')
uJoe.pprint()
uFrank = uAdmin.get_capabilities()['register_user']('frank', 'Frank Furter')
uFrank.pprint()
uIma = uAdmin.get_capabilities()['register_user']('ima', 'Ima Nutcase', False, False)
uIma.pprint()

ha = startup('joe')
uJoe = HSAccessUser(ha, uJoe.get_uuid())
uJoe.pprint()

gCoolies = uJoe.register_group('coolies')
gCoolies.pprint()


caps = gCoolies.get_capabilities()
caps['make_not_discoverable']()
gCoolies.pprint()

rDives = uJoe.register_resource("/joe/dives", "The best dives")
rDives.pprint()

rDivesCaps = rDives.get_capabilities()
rDivesCaps['change_title']("The bestest dives")

rDives.pprint()

pprint(uJoe.get_groups())
pprint(uJoe.get_resources())

rDives.get_capabilities()['make_public']()

rDives.pprint()

gCoolies.get_capabilities()['invite_user'](uFrank, "ro")

# pprint(gCoolies.get_invited_users())

uJoe.pprint()
uAdmin['register_user']

rDives.pprint()
gCoolies.pprint()
