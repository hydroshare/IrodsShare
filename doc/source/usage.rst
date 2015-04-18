Using the HSAlib HSAccess implementation 
====================================

.. module:: HSAlib

The :py:mod:`HSAlib` module and :py:class:`HSAccess` class implement a python interface to the iRODS 
access control system.  This document describes usage of the low level python interface.  There is also a high-level 
python interface :py:mod:`HSAccessObjects`. 

Overview
--------

To use this class, one establishes a connection via the :py:class:`HSAccess` constructor. 
This class is a wrapper around native iRODS access control and does not create iRODS objects 
nor objects in HydroShare. Instead, it maintains a concept of access control for three kinds 
of objects: 

1. Users in iRODS
2. Resources stored in iRODS
3. Groups of users defined in HydroShare in django. 

The first and second kinds of objects are physical entities. The third is contained solely inside 
the access control system. 

Rationale and need
~~~~~~~~~~~~~~~~~~

This module was created in order to extend the concept of protection available in iRODS. Currently
in iRODS, creation of a user group is a privileged action. We wanted to create unprivileged notions
of:

* Creating a group. 
* Sharing a file with another user or group. 

that can be used by any user and allows a very flexible and fluid form of data sharing similar to what
is available in Dropbox, Google Drive, OneDrive, but acts at the filesystem level so that the 
resources under its control are usable as if they exist in a file system. 

Architecture
~~~~~~~~~~~~

IrodsShare is based upon a PostgreSQL database that is deployed in parallel to the iRODS database iCAT. 
It was found early in the design process that iCAT extensions are not sufficiently expressive to be used as a security 
and access control model of this type. Thus, a separate database was created. 
This database stores access control information for iRODS "resources". 

In order to accomplish this, the iRODS instance must be specially configured. All resources in iRODS must be group-writeable to 
a special iRODS group 'HydroShare' that contains all users of IrodsShare. IrodsShare imposes its protections on top of iRODS 
protections, but at all levels of iRODS, so that access through the command line, iRODS API, and iRODS REST services are all
subject to this access control.

Theory of operation
~~~~~~~~~~~~~~~~~~~

This module acts on two levels: 

1. Controlling access to resources existing in iRODS. 
2. Controlling access through the django web interface. 

It exists as a separate entity because these access control mechanisms must be consistent. 

In iRODS, it is possible to define a method that is called before anything is done to a resource. 
This method allows one to deny access to unauthorized users. We utilize this method to 
invoke our own authorization system based upon our authorization database. 

In Django, this library serves as a definitive source of access control information. 
Access is registered by Django, and read from this source as necessary. The module API 
includes listing functions that allow one to list resources by access. 

Modules and Naming conventions 
------------------------------

In the library, there are several strong naming conventions: 

* Methods starting with *assert_* create and change records for an entity. These are idempotent and can be 
  reused to change object metadata after creating an object. 

    * E.g., :py:meth:`HSAccessCore.assert_user` registers or changes metadata for a user. 

* Methods starting with *share_* and *unshare_* grant and remove privileges to an object, which could be a resource or a group. 

    * E.g., :py:meth:`HSAccessCore.share_resource_with_user` shares a given resource with a given user. 

* Methods starting with *get_* are queries and report various things about the access control system. 

    * E.g., :py:meth:`HSAccessCore.get_users` returns a list of all registered users.

* Methods starting with *can_* return boolean and report high-level privileges necessary for django representations of objects. 

    * E.g., :py:meth:`HSAccessCore.can_change_resource` reports whether the current user can change a particular resource. 

* Methods containing *_is_* return boolean and report on the state of objects. 

    * E.g., :py:meth:`HSAccessCore.user_is_admin` reports whether the current user has administrative privilege 

HSAccess and HSAccessCore
~~~~~~~~~~~~~~~~~~~~~~~~~

The low-level interface of IrodsShare contains routines that manipulate entities via their universal unique identifiers (UUIDS). 
Each user, group, or resource is assigned a UUID, and that UUID is an argument to all routines that manipulate the entity's state. 
This logic is contained in the module :py:mod:`HSAlib`, which contains two main classes. 

* :py:class:`HSAccess` is the main class for users, which contains both 
  methods from a base class :py:class:`HSAccessCore` and helper methods at a higher level than appear in 
  :py:class:`HSAccessCore`. 
* The base class :py:class:`HSAccessCore` contains the routines that actually talk 
  to the access control database and iRODS. 

HSAccessUser, HSAccessGroup, and HSAccessResource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As well, there is a high-level "object" library based upon :py:mod:`HSAlib` supplied in the module :py:mod:`HSAccessObjects`. 
This creates concepts of users, resources, and groups as objects with appropriate methods. This does exactly the same thing as 
:py:mod:`HSAlib` but provides a way to determine easily which methods apply to what objects. 

HSAccess Usage
--------------

After utilizing the :py:class:`HSAccess` constructor, one gains access as a specific user. 
This user must be already created in iRODS and that user's uuid is available by calling 
:py:meth:`HSAccessCore.get_uuid`. 

When using HSAccess, every object is identified by a 32-byte Universal Unique Identifier (UUID). 
There are UUID namespaces for users, groups, and resources. Other objects, including folders, 
do not have UUIDs within the system. In general, when the system references a group, user, or resource, 
one must know the uuid. Listing functions allow one to easily recover the uuid for 
all relevant objects that one is allowed to access. 

The use of UUIDs allows us to be quite flexible on naming of objects. For example, in IrodsShare, it is not
an error for two groups or resources to have the exact same name. The UUIDs disambiguate between these. 

For example, consider :py:meth:`HSAccessCore.share_resource_with_user`. This requires two uuids: 
one identifying the user and another identifying the resource. A third uuid is that of the 
current user, which is contained inside the$:py:class:`HSAccessCore` object and need not be 
mentioned. 

Many methods in :py:class:`HSAccess` have optional parameters. For example, whenever appropriate, the user 
uuid is optional and defaults to that of the current user as defined when creating the object. 

Sharing in IrodsShare
---------------------

The sharing interface is the reason for the existence of IrodsShare. 
It has several unique properties, including: 

* *Fluidity*: sharing privileges are unprivileged and based upon the idea that one can delegate any privilege one has. 
* *Cumulative privilege*: sharing privileges are cumulative over all intents to share from all users. If two people 
  share the same object with different privileges, the higher privilege wins.

Privileges and privilege policy 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The privilege system in IrodsShare is based upon four distinct levels of privilege, including: 

* *Owner*: can do anything to an object, and can unshare it with a user as necessary. 
* *Read/Write*: can read or update an object, but cannot delete it or override other users' sharing of it. 
* *Read-Only*: can read but not write the object. 

The privilege system is based upon several policy rules: 

* Every object (resource and group) must have an owner. The initial owner is the creator. 
* The last owner cannot be removed from an object. But new owners can be assigned before removing the 
  original creator as owner. 
* There can be multiple owners. 
* A user of the system can share an object only at the user's own privilege level or below. E.g., a person with read/write 
  privilege cannot share an object as owner, but can share with "read/write", "read-only", or "read-only without sharing" access. 
  Obviously, a user with "read-only without sharing" cannot share the object. 
* A user can change the privilege on an existing share without notice, within these bounds.  E.g., one can grant one's graduate students 'read-write' privilege for a time, and then downgrade it to 'read-only'. 
* A user that is a member of a group can share an object with the group. Group privilege applies to all members of the group and is based upon the member's privilege over the object. 

For groups, there are extra meanings to the protections

* *Owner* means that one can destroy the group and remove members. 
* *Read/Write* means that one can add members to the group. 
* *Read-only* means that one can only list members. There is no lower level of group access. 

Instantaneous and invited privilege 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two kinds of sharing in IrodsShare: instantaneous and invited. 

* Sharing can be *instantaneous*; the privilege appears immediately. 
* Sharing can also be *invited*; the invited user must approve the invitation in a separate confirmation. 

The current implementation does not enforce either one. Thus, there are completely separate commands 
for invitation logic and instantaneous logic 

Handling invitations
~~~~~~~~~~~~~~~~~~~~

The invitation system is a state-machine model of sharing, to wit: 

1. One user invites another to a group with :py:meth:`HSAccessiCore.invite_user_to_group`. 
2. The user can: 
   a. List invitations through :py:meth:`HSAccessCore.get_group_invitations_for_user`. 
   b. Accept invitations through :py:meth:`HSAccessCore.accept_invitation_to_group`. 
   c. Refuse invitations through :py:meth:`HSAccessCore.refuse_invitation_to_group`. 
3. Meanwhile, if too much time passes, the original inviter can: 
   a. List unaccepted invitations through :py:meth:`HSAccessCore.get_group_invitations_sent_by_user`
   b. Uninvite the invited user via :py:meth:`HSAccessCore.uninvite_user_to_group`. 

List of methods and categories 
------------------------------

The following is an abbreviated list of the most common methods in :py:mod:`HSAlib`.

* Managing users
    * User creation and management: 
        * :py:meth:`HSAccessCore.assert_user`: create a user and update user metadata. 
        * :py:meth:`HSAccessCore.get_user_metadata`: get a user record. 
        * :py:meth:`HSAccessCore.assert_user_metadata`: push a user record with changes. 
        * :py:meth:`HSAccess.get_user_print_name`: get the print name of a user. 
        * :py:meth:`HSAccessCore.make_user_admin`: make a user an administrator. 
        * :py:meth:`HSAccessCore.make_user_not_active`: deactivate a user. 
    * User status 
        * :py:meth:`HSAccessCore.user_exists`: True if user is valid. 
        * :py:meth:`HSAccessCore.user_is_active`: True if the user is active and enabled. 
        * :py:meth:`HSAccessCore.user_is_admin`: True if the user is an administrator. 
    * Miscellaneous: 
        * :py:meth:`HSAccessCore.get_users`: a list of all active users. 
* Managing groups
    * Creation and management: 
        * :py:meth:`HSAccessCore.assert_group`: register a group. 
        * :py:meth:`HSAccessCore.get_group_metadata`: read a group registration record. 
        * :py:meth:`HSAccessCore.assert_group_metadata`: make changes in a group registration record. 
        * :py:meth:`HSAccessCore.retract_group`: remove a group (not recommended).
        * :py:meth:`HSAccess.get_group_print_name`: get the print name for a group. 
    * Views of group membership
        * :py:meth:`HSAccessCore.get_groups`: a list of all valid groups. 
        * :py:meth:`HSAccessCore.get_groups_for_user`: a list of groups to which a user belongs. 
    * Status of a group
        * :py:meth:`HSAccessCore.group_exists`: whether group is valid
        * :py:meth:`HSAccessCore.group_is_public`: whether a group is public and can be viewed by anyone. 
        * :py:meth:`HSAccessCore.group_is_discoverable`: whether a group is discoverable and its existence can be discovered by anyone. 
        * :py:meth:`HSAccessCore.group_is_shareable`: whether a group is shareable and can be shared by non-owners. 
    * Django interface
        * :py:meth:`HSAccessCore.can_change_group`: whether the current user can add someone to a group. 
        * :py:meth:`HSAccessCore.can_change_group_flags`: whether the current user can change group status, including 
          the flags 'public, 'discoverable', 'shareable', and 'active'. 
        * :py:meth:`HSAccessCore.can_view_group`: whether the current user can list group members. 
        * :py:meth:`HSAccessCore.can_share_group`: whether the current user can invite a user to the group. 
* Managing resources
    * Creation and update: 
        * :py:meth:`HSAccessCore.assert_resource`: register a resource or update resource registration. 
        * :py:meth:`HSAccessCore.get_resource_metadata`: get a registration record. 
        * :py:meth:`HSAccessCore.assert_resource_metadata`: post changes to a registration record. 
        * :py:meth:`HSAccess.get_resource_print_name`: get the print name of a resource. 
    * Status of a resource
        * :py:meth:`HSAccessCore.resource_exists`: whether resource is valid. 
        * :py:meth:`HSAccessCore.resource_accessible`: whether a resource is accessible to a user. 
        * :py:meth:`HSAccessCore.resource_is_published`: whether a resource is published and thus archival. 
        * :py:meth:`HSAccessCore.resource_is_immutable`: whether a resource is immutable and cannot be changed. 
        * :py:meth:`HSAccessCore.resource_is_public`: whether a resource is public and can be viewed by anyone. 
        * :py:meth:`HSAccessCore.resource_is_discoverable`: whether a resource is discoverable and its existence can be discovered by anyone. 
        * :py:meth:`HSAccessCore.resource_is_shareable`: whether a resource is shareable and can be shared by non-owners. 
    * Django interface
        * :py:meth:`HSAccessCore.can_change_resource`: whether the current user can add someone to a resource. 
        * :py:meth:`HSAccessCore.can_change_resource_flags`: whether the current user can change resource status, including 
          the flags 'public, 'discoverable', 'published', 'immutable', and 'shareable'. 
        * :py:meth:`HSAccessCore.can_view_resource`: whether the current user can list resource members. 
        * :py:meth:`HSAccessCore.can_share_resource`: whether the current user can invite a user to use the resource. 
* Access control 
    * For resources: 
        * Access status: 
            * :py:meth:`HSAccessCore.resource_is_owned`: True if resource is owned by a user. 
            * :py:meth:`HSAccessCore.resource_is_readwrite`: True of resource is read/write to a user. 
            * :py:meth:`HSAccessCore.resource_is_readable`: True if resource is readable to a user. 
        * User access to resources: 
            * :py:meth:`HSAccessCore.share_resource_with_user`: make a resource accessible to a user. 
            * :py:meth:`HSAccessCore.unshare_resource_with_user`: remove access to a resource for a user. 
            * :py:meth:`HSAccessCore.get_resources_held_by_user`: list the resources accessible to a user (by any means). 
        * Group access to resources: 
            * :py:meth:`HSAccessCore.share_resource_with_group`: make a resource accessible to a group. 
            * :py:meth:`HSAccessCore.unshare_resource_with_group`: remove access to a resource for a group. 
            * :py:meth:`HSAccessCore.get_resources_held_by_group`: list the resources available to a group. 
        * Invitation logic 
            * :py:meth:`HSAccessCore.invite_user_to_resource`: invite a user. 
            * :py:meth:`HSAccessCore.get_resource_invitations_sent_by_user`: get all invitations. 
            * :py:meth:`HSAccessCore.uninvite_user_to_resource`: retract an invitation. 
            * :py:meth:`HSAccessCore.get_resource_invitations_for_user`: get all invitations. 
            * :py:meth:`HSAccessCore.accept_invitation_to_resource`: accept an invitation. 
            * :py:meth:`HSAccessCore.refuse_invitation_to_resource`: refuse an invitation. 
    * For groups: 
        * Access status: 
            * :py:meth:`HSAccessCore.group_is_owned`: whether group is owned by a specified user
            * :py:meth:`HSAccessCore.group_is_readwrite`: whether group is read/write to a specified user. 
            * :py:meth:`HSAccessCore.group_is_readable`: whether group is readable to a user; minimum privilege. 
        * User access to groups: 
            * :py:meth:`HSAccessCore.share_group_with_user`:  group membership without invitation. 
            * :py:meth:`HSAccessCore.unshare_group_with_user`: remove all access to a group for a user. 
        * Membership reporting
            * :py:meth:`HSAccessCore.user_in_group`: True if user is in a given group. 
            * :py:meth:`HSAccessCore.get_groups_for_user`: list all groups to which a user belongs. 
        * Invitation logic 
            * :py:meth:`HSAccessCore.invite_user_to_group`: invite a user. 
            * :py:meth:`HSAccessCore.get_group_invitations_sent_by_user`: get all invitations. 
            * :py:meth:`HSAccessCore.uninvite_user_to_group`: retract an invitation. 
            * :py:meth:`HSAccessCore.get_group_invitations_for_user`: get all invitations. 
            * :py:meth:`HSAccessCore.accept_invitation_to_group`: accept an invitation. 
            * :py:meth:`HSAccessCore.refuse_invitation_to_group`: refuse an invitation. 
* Resource organization (not yet implemented) 
    * Tagging of resources 
        * :py:meth:`HSAccessCore.assert_tag`: make a new tag. 
        * :py:meth:`HSAccessCore.retract_tag`: destroy a tag and delete all uses. 
        * :py:meth:`HSAccessCore.assert_resource_has_tag`: tag a resource.
        * :py:meth:`HSAccessCore.retract_resource_has_tag`: untag a resource.
        * :py:meth:`HSAccessCore.get_tags`: get a list of all active tags. 
        * :py:meth:`HSAccessCore.get_resources_by_tag`: get a structure of resources, filed by tag. 
    * Folders for resources
        * :py:meth:`HSAccessCore.assert_folder`: make a new folder. 
        * :py:meth:`HSAccessCore.retract_folder`: destroy a folder and remove all links in the folder. 
        * :py:meth:`HSAccessCore.get_folders`: get a list of all folders. 
        * :py:meth:`HSAccessCore.assert_resource_in_folder`: put a resource into a folder. 
        * :py:meth:`HSAccessCore.retract_resource_in_folder`: remove a resource from a folder. 
        * :py:meth:`HSAccessCore.get_resources_in_folders`: list resources by folder. 
* Statistics 
    * :py:meth:`HSAccessCore.get_number_of_group_owners`
    * :py:meth:`HSAccessCore.get_number_of_groups_of_user`
    * :py:meth:`HSAccessCore.get_number_of_groups_owned_by_user`
    * :py:meth:`HSAccessCore.get_number_of_resource_owners`
    * :py:meth:`HSAccessCore.get_number_of_resources_held_by_user`
    * :py:meth:`HSAccessCore.get_number_of_resources_owned_by_user`
* Current user 
    * :py:meth:`HSAccessCore.get_uuid`
    * :py:meth:`HSAccessCore.get_login`
