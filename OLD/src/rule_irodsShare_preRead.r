pep_resource_read_pre {
	write('stdout', 'physical path:');
	writeLine('stdout', $KVPairs.physical_path);  
	write('stdout', 'mode_kw:');
	writeLine('stdout', $KVPairs.mode_kw);  
	write('stdout', 'flagse_kw:');
	writeLine('stdout', $KVPairs.flags_kw);  
}
input null
output ruleExecOut
