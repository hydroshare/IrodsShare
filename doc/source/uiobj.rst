Thoughts on the IrodsShare/Django Object Interface 
======================================================

.. module::  HSAccessObjects

The IrodsShare interface is designed with a specific kind of user interface in mind. 
The object interface in :py:mod:`HSAccessObjects` uses primitive routines in :py:mod:`HSAlib` to 
create "objects" that are in a sense self-describing.

The User Object
---------------

Instances of the :py:class:`HSAccessUser` class describe users, including the current authenticated user. 
Each object is aware of the identity of the authenticated user and that user's capabilities. 
For example, the following methods are written and intended to drive the 
contents of the user's home page: 

* :py:meth:`HSAccessUser.get_resources`: get a list of :py:class:`HSAccessResource` instances describing resources 
  to which the user has access. These do not include public resources. 
* :py:meth:`HSAccessUser.get_groups`: get a list of groups to which the user belongs. 
* :py:meth:`HSAccessUser.get_capabilities`: describe other capabilities via a dictionary object. 

The :py:meth:`HSAccessUser.get_capabilities` method has a return that is a dictionary object and 
describes the private methods to which a user has access. 

Also, the primitive statistics functions 

* :py:meth:`HSAccess.get_number_of_groups_of_user`
* :py:meth:`HSAccess.get_number_of_groups_owned_by_user`
* :py:meth:`HSAccess.get_number_of_resources_held_by_user`
* :py:meth:`HSAccess.get_number_of_resources_owned_by_user`

are designed for reporting statistics on the user's home page. 

The Resource Object
-------------------

Instances of :py:class:`HSAccessResource` describe resources to which a user has access. 
These instances are aware of the identity of the authenticated user. The following routines
are intended for use on the resource landing page: 

* :py:meth:`HSAccessResource.is_public`: True if resource is public. 
* :py:meth:`HSAccessResource.is_published`: True if resource is published. 
* :py:meth:`HSAccessResource.is_discoverable`: True if resource is discoverable. 
* :py:meth:`HSAccessResource.is_shareable`: True if resource is shareable by non-owners. 
* :py:meth:`HSAccessResource.get_privilege`: Returns the string privilege of the current 
  authenticated user over the resource, which can be 'own', 'rw', 'ro', or 'none' (for public resources). 
* :py:meth:`HSAccessResource.get_capabilities`: Returns a dictionary object describing capabilities of the 
  current authenticated user over the resource in question. 

The Group Object
----------------

Instances of :py:class:`HSAccessGroup` describe groups of users in which a user is a member 
or which have been marked discoverable or public. 
The following routines are intended for use on the group landing page: 

* :py:meth:`HSAccessGroup.is_member`: True if current authenticated user is a member of the group.
* :py:meth:`HSAccessGroup.is_owner`: True if current authenticated user is an owner of the group.
* :py:meth:`HSAccessGroup.is_public`: True if group is public; non-members can read the member list. 
* :py:meth:`HSAccessGroup.is_discoverable`: True if group is discoverable; non-members can discover 
  the existence of the group. 
* :py:meth:`HSAccessGroup.is_shareable`: True if non-owners can add members to the group. 
* :py:meth:`HSAccessGroup.get_privilege`: Returns the string privilege of the current 
  authenticated user over the resource, which can be 'own', 'rw', 'ro', or 'none' (for public resources). 
* :py:meth:`HSAccessGroup.get_capabilities`: Returns a dictionary object describing capabilities of the 
  current authenticated user over the group in question. 


