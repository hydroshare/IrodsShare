IrodsShare module documentation
======================================

The IrodsShare module :py:mod:`HSAlib` contains two main classes: 

* :py:class:`HSAccessCore`: low-level routines for interacting with iRODS directly. 
* :py:class:`HSAccess`: higher level class that inherits from :py:class:`HSAccessCore` 
  and includes usability features. 

These are the lowest-level routines in the IrodsShare project. For a higher-level interface
suitable for User Interface development, see :py:class:`HSAccessObjects`. 

.. automodule:: HSAlib

HSAccessCore: iRODS/HydroShare communication 
--------------------------------------------
.. autoclass:: HSAccessCore
   :members:
   :private-members: 
   :special-members: 

HSAccess: Convenience functions 
-------------------------------
.. autoclass:: HSAccess
   :members:
   :private-members: 
   :special-members: 

Exceptions
-----------
.. autoclass:: HSAccessException 
   :members: 
   :special-members: 

.. autoclass:: HSAUsageException
   :members: 
   :special-members: 

.. autoclass:: HSAIntegrityException 
   :members: 
   :special-members: 
