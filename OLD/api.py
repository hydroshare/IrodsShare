# api.py
# This file defines a rudimentary Python API for Hydroshare's iRODS instance
# 
# For those calls which require a session, use:
#
#     from irods.session import iRODSSession
#     s = iRODSSession(host='localhost', port=1247, user='rods', password='c0rv3tt3', zone='tempZone')
#
# RULES
# -----
#
# 1. You can only add a user to a group if you are in that group yourself. 
# 2. You can only access a document if you or one of your groups is listed for the document. * (later) 
# 3. You can only share a document if you can access it. 
# 4. You cannot unshare a document unless you are unsharing it from yourself. 
# 5. You can list all documents shared with you.
# 6. You can access anything you can list.
# 7. You can only unshare a resource from a group if you own the resource
# 8. You can only remove yourself from groups

from subprocess import call

# Rule 3
def share_with_user(sess, resource, user):
  sharable =  True # should be set if resource.metadata includes user
  if sharable:
    sess.data_objects.get(resource).metadata.add("hsAccess", user, "users")

# Rule 4
def unshare_with_user(sess, resource, user):
  curr_user = user # should be set if sess.user == user
  if curr_user == user:
    sess.data_objects.get(resource).metadata.remove('hsAccess', user, 'users')

# Rule 3
def share_with_group(sess, resource, group):
  access = True # should be set if you or one of your groups listed for document
  if access:
    sess.data_objects.get(resource).metadata.add("hsAccess", group, "groups")

# Rule 7
def unshare_with_group(sess, resource, group):
  owner = True # should be set if resource.owner == sess.user
  if owner:
    sess.data_objects.get(resource).metadata.remove('hsAccess', group, 'groups')

# Rule 1
def add_to_group(group, user):
  in_group = True # should be set if sess.user.groups.contains(group)
  if in_group:
    call(['imeta', 'add', '-u', '%s' % user, 'hsAccess', '%s' % group, 'groups'])

# Rule 8 
def remove_from_group(group, user):
  in_group = True # should be set if sess.user == user
  if in_group:
    call(['imeta', 'rm', '-u', '%s' % user, 'hsAccess', '%s' % group, 'groups'])

def ls_held_resources():
  pass

if __name__ == "__main__":
  from irods.session import iRODSSession
  s = iRODSSession(host='localhost', port=1247, user='rods', password='c0rv3tt3', zone='tempZone')

  resource = "/tempZone/home/rods/test1.txt"
  group    = "Hydroshare"
  user     = "rods"

  # share_with_group
  share_with_group(s, resource, group)
  value = s.data_objects.get(resource).metadata.get_all('hsAccess')[0].value
  if value == group:
    print "Success - group %s added to %s" % (group, resource)
  else:
    print "Failure - group %s not added to %s" % (group, resource)

  # unshare_with_group
  unshare_with_group(s, resource, group)
  if s.data_objects.get(resource).metadata.items() == []:
    print "Success - group %s removed from %s" % (group, resource)
  else:
    print "Failure - group %s not removed to %s" % (group, resource)

  # share_with_user
  share_with_user(s, resource, user)
  value = s.data_objects.get(resource).metadata.get_all('hsAccess')[0].value
  if value == user:
    print "Success - user %s added to %s" % (user, resource)
  else:
    print "Failure - user %s not added to %s" % (user, resource)

  # unshare_with_user
  unshare_with_user(s, resource, user)
  if s.data_objects.get(resource).metadata.items() == []:
    print "Success - user %s removed from %s" % (user, resource)
  else:
    print "Failure - user %s not removed to %s" % (user, resource)

  # NOTE cannot test w/o query functions

  # add_to_group
  add_to_group(group, user)
  # remove_from_group
  remove_from_group(group, user)

