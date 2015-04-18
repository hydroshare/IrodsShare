Interfacing IrodsShare with Django
==================================

.. module:: HSAlib

In this version of IrodsShare, there are new methods in :py:mod:`HSAlib` for interfacing to Django's access control system. 
Each one takes one argument that is the uuid of a resource or group. 

* For resources: 
    * :py:meth:`HSAccess.can_change_resource` returns True if the current user can 
      change the referenced resource. 
    * :py:meth:`HSAccess.can_change_resource_flags` returns True if the current user can 
      change the referenced resource's flags, including 'public', 'discoverable', 'published', 
      'immutable', and 'shareable'. 
    * :py:meth:`HSAccess.can_view_resource` returns True if the current user can view the resource. 
    * :py:meth:`HSAccess.can_share_resource` returns True if the current user can share the resource with others. 
* For groups: 
    * :py:meth:`HSAccess.can_change_group` returns True if the current user can change group metadata. 
    * :py:meth:`HSAccess.can_change_group_flags` returns True if the current user can 
      change the referenced group's flags, including 'public', 'discoverable', and 'shareable'. 
    * :py:meth:`HSAccess.can_view_group` returns True if the current user can list members of the group. 
    * :py:meth:`HSAccess.can_share_group` returns True if the current user can invite group members. 

Likewise, in :py:mod:`HSAccessObjects`, each object has exposed public methods 
'can_change', 'can_change_flags', 'can_view', and 'can_share'. 
