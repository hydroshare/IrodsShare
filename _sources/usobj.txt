Using HSAccessObjects 
=====================

.. module:: HSAccessObjects 

The :py:mod:`HSAccessObjects` library is a wrapper around 
the :py:mod:`HSAlib` module that is intended to make using :py:mod:`HSAlib` easier. 
While :py:mod:`HSAlib` manipulates opaque UUIDs, :py:mod:`HSAccessObjects` exposes three 
wrapper classes that make handling of the three kinds of entities more transparent: 

* :py:class:`HSAccessUser` represents a user and the user's capabilities. 
* :py:class:`HSAccessGroup` represents a user group. 
* :py:class:`HSAccessResource` represents a HydroShare resource. 

Instances of these classes maintain a list of 'capabilities' that each object acquires as a result of user privilege. 
Thus there is no doubt at any time as to what the user is allowed to do with an object. 

Rationale and need
------------------

While :py:mod:`HSAlib` functionally accomplishes the needs of IrodsShare, it is notably difficult to use, because
the business logic of the access control system is rather complex. Thus, it is difficult for a user of :py:mod:`HSAlib` 
to determine what is permitted in a particular situation. :py:mod:`HSAccessObjects` provides this missing piece, 
by maintaining lists of capabilities that a user has over each kind of thing, which makes writing a user interface 
much easier. 

Usage
-----

To use this class, one establishes a connection via the :py:class:`HSAlib.HSAccess` constructor
and then creates an :py:class:`HSAccessUser` instance *representing the current user*. This user object 
exposes methods the user can utilize, and also exposes dynamic methods depending upon user privilege 
via the class :py:meth:`HSAccessUser.get_capabilities`. This function returns references to methods 
that can be used according to the user's privilege level. 

Capabilities
~~~~~~~~~~~~

The concept of 'get_capabilities' is ubiquitous in :py:mod:`HSAccessObjects`. Each kind of object, whether 
it represents a user, group, or resource, maintains a list of methods (capabilities) that can be done to it. 
These are all relative to the authorization of the current user. These capabilities distinguish -- among other
things -- whether a user is allowed to modify a resource or its metadata; whether a user is allowed to 
invite other users to a group, and whether a user is allowed to share a resource with either another user or
a group of users. 

Sharing in HSAccessObjects 
~~~~~~~~~~~~~~~~~~~~~~~~~~

For example, *the ability to share a group or resource is a capability.* One discovers that capability by 
calling 'get_capabilities' for the object one wishes to share. This call exposes some methods as capabilities
and leaves others unexposed. Unexposed methods are those that will raise an access control exception if used. 
So, for example, to determine whether a resource can be shared with another user, one might write::

    resource_object = HSAccessResource(resource_uuid)
    caps = resource_object.get_capabilities()
    if 'share_with_user' in caps.keys(): 
        user_object = HSAccessUser(user_uuid)
        caps['share_with_user'](user_object, 'ro')

where 'ro' is the sharing privilege. Note that the values in caps are so-called "bound methods", in the sense that 
they contain a reference to the referenced object. Thus, the object need not be mentioned. 

In the unlikely event that the current user is not allowed to share the object, the capability will be absent from caps. 
There are many ways this could happen, including not having sufficient privilege over the resource, or being stopped 
from sharing by the owner. 

For each kind of object, a user can determine the possible methods returned by 'get_capabilities' by calling 
'get_methods'. This returns a simple list of method names available. 

Public, private, and unexposed private members
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In :py:mod:`HSAccessObjects`, the public methods of each class are always available 
to the user. Capabilities are exposed as private methods that are bound to the capability
when appropriate. Thus there are three kinds of methods in each object: 

* Public methods that can always be used. 
* Private, bindable methods that can be used in certain situations. 
* Private methods that are not exposed via binding. 

Note that *this is not an access control mechanism* and that all that :py:mod:`HSAccessObjects` does is to obey
the access control from :py:mod:`HSAlib` and avoid exceptions from that source. Thus *one cannot work around 
access control limits by calling unbound methods directly.* This will result in an access control exception, just like
it would if you called the corresponding :pu:mod:`HSAlib` function. 

