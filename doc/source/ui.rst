Thoughts on the IrodsShare/Django UI
====================================

The IrodsShare interface is designed with a specific kind of user interface in mind. 
This interface uses the directory reporting in IrodsShare to generate lists of objects
in IrodsShare that are appropriate for display in the user interface. 

HSAccess Methods that drive the user's home page
---------------------------------------

For example, the following methods are written and intended to drive the 
resource lists on the user's home page: 

* :py:meth:`HSAccess.resources_held_by_user`: list the resources accessible to a user (by any means). Note: will be refactored to "get_resources_held_by_user" ASAP. 
* :py:meth:`HSAccess.get_resources_by_tag`: get a structure of resources, filed by tag. 
* :py:meth:`HSAccess.get_resources_in_folders`: list resources by folder. 

are three ways of listing resources. A fourth way: 

* :py:meth:`HSAccess.get_resources_by_group`: file user resources by group. 

is coming soon.  Many others are possible. 

Meanwhile, each of the "get_resources_by_*" routines contains an extra 
parameter that limits the listing to a specific tag, folder, or group. 
One can discover the appropriate values of these tags via: 

* :py:meth:`HSAccess.get_groups_for_user`: a list of groups to which a user belongs. 
* :py:meth:`HSAccess.get_tags`: get a list of all active tags for a user. 
* :py:meth:`HSAccess.get_folders`: get a list of all folders. 

These are intended to drive menus that allow one to select a specific tag, folder, or group. 

Also, the statistics functions 

* :py:meth:`HSAccess.get_number_of_groups_of_user`
* :py:meth:`HSAccess.get_number_of_groups_owned_by_user`
* :py:meth:`HSAccess.get_number_of_resources_held_by_user`
* :py:meth:`HSAccess.get_number_of_resources_owned_by_user`

are designed for reporting statistics on the user's home page. 

While the emphasis so far has been upon creating functions that can be used on a user's landing 
page, these routines can also be used on the user's public landing page as part of a 
user profile. 

How we are thinking about the user interface to held resources 
--------------------------------------------------------------

:py:class:`HSAccess` is designed around a specific philosophy of user interfaces. The user 
is presented with a listing containing various classifications of resources, and can 
click on any classification to see all resources with that classification.  
As well, complete lists of classifications (groups, users who shared something, groups with access, user-level tags, and user-level folders) are available and one can select a specific classification to see folders with that classification. 

This is in no sense the final version of the interface. I hope to engage in a dialogue with the 
users and create "held resources" formats that are most useful. 

