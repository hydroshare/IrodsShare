//----------------------------------------------------
// mediate an irods read request using a dynamic Policy Enforcement Point. 
//----------------------------------------------------
// =-=-=-=-=-=-=-
#include "msParam.hpp"
#include "reGlobalsExtern.hpp"
#include "irods_ms_plugin.hpp"

// =-=-=-=-=-=-=-
// STL Includes
#include <iostream>

extern "C" {

    // =-=-=-=-=-=-=-
    // 1. Write a standard issue microservice
    int irods_irodsShare_read( msParam_t* _out, ruleExecInfo_t* _rei ) {
        std::string my_str = "Hello World!";
        fillStrInMsParam( _out, my_str.c_str() );

        return 0; // normal, non-error return. 
    }

    // =-=-=-=-=-=-=-
    // 2.  Create the plugin factory function which will return a microservice
    //     table entry
    // (this is a reserved name)
    irods::ms_table_entry*  plugin_factory() {
        // =-=-=-=-=-=-=-
        // 3. allocate a microservice plugin which takes the number of function
        //    params as a parameter to the constructor
	// (This number does not include the obligatory argument 
	// ruleExecInfo_t *)
        irods::ms_table_entry* msvc = new irods::ms_table_entry( 1 );

        // =-=-=-=-=-=-=-
        // 4. add the microservice function as an operation to the plugin
        //    the first param is the name / key of the operation, the second
        //    is the name of the function which will be the microservice
        msvc->add_operation( "irods_irodsShare_read" , "irods_irodsShare_read" );

        // =-=-=-=-=-=-=-
        // 5. return the newly created microservice plugin
        return msvc;
    }

}; // extern "C"
