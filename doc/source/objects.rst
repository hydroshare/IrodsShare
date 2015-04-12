IrodsShare Object Library
=========================

The IrodsShare Object Library exposes python objects that represent entities in the IrodsShare system. 
These objects have the rudimentary ability to describe methods that apply to them, dynamically. 

The key to this self-describing system is the get_capabilities() method of each class, which lists
the methods that the current user has permission to use. These are listed as "bound methods" whose binding
includes the reference object. Thus, one can call one on the reference object without explicit reference to the
object itself. 

The return value of get_capabilities() is a Dict of key-value pairs::

        { 'capability_key': bound_method, ... } 

One can call a bound method via the following pattern::

        caps = Objects.get_capabilities()
        if 'method' in caps.keys(): 
            caps['method'](...method arguments...) 

where each method has arguments documented in the get_capabilities() documentation for the specific object. 
    
Note that there is no value in overriding the privacy mechanism enforced by get_capabilities(), as the methods
not listed are protected from use at a lower level, in :py:mod:`HSAlib`. The get_capabilities() mechanism only 
provides a convenient way to check whether there is permission to use a method or not. 

Theory of Operation
-------------------

The theory of operation for this library is that the user interface will list objects and their capabilities. 
The user can select from capabilities to invoke them. Thus, the programmer does not need to understand complex
business logic in order to discover which operations can be done on which objects. 

.. automodule:: HSAccessObjects

HSAccessUser: represent a user
------------------------------
.. autoclass:: HSAccessObjects.HSAccessUser
   :members:
   :special-members:
   :private-members:

HSAccessGroup: represent a user group 
-------------------------------------
.. autoclass:: HSAccessObjects.HSAccessGroup
   :members:
   :special-members:
   :private-members:

HSAccessResource: represent a resource file
-------------------------------------------
.. autoclass:: HSAccessObjects.HSAccessResource
   :members:
   :special-members:
   :private-members:
