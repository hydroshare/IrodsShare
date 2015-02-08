# api.py
# This file defines a rudimentary Python API for Hydroshare's iRODS instance
# 
# For those calls which require a session, use:
#
#     from irods.session import iRODSSession
#     s = iRODSSession(host='localhost', port=1247, user='rods', password='c0rv3tt3', zone='tempZone')

def share_with_user(resource, user):
  pass

def unshare_with_user(resource, user):
  pass

def share_with_group(sess, resource, group):
  sess.data_objects.get(resource).metadata.add("hsAccess", group, "groups")

def unshare_with_group(sess, resource, group):
  sess.data_objects.get(resource).metadata.remove('hsAccess', group, 'groups')

def add_to_group(group, user):
  pass

def remove_from_group(group, user):
  pass

def ls_held_resources():
  pass

if __name__ == "__main__":
  from irods.session import iRODSSession
  s = iRODSSession(host='localhost', port=1247, user='rods', password='c0rv3tt3', zone='tempZone')

  resource = "/tempZone/home/rods/test1.txt"
  group = "TestGroup4"

  print "Testing share_with_group..."
  share_with_group(s, resource, group)

  value = s.data_objects.get(resource).metadata.get_all('hsAccess')[0].value
  if value == group:
    print "Success - group %s added to %s" % (group, resource)
  else:
    print "Failure - Group not added"

  print "Testing unshare_with_group..."
  unshare_with_group(s, resource, group)
  if s.data_objects.get(resource).metadata.items() == []:
    print "Success - group %s removed from %s" % (group, resource)
  else:
    print "Failure - Group not removed"
