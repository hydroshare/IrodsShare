GCC = g++ 
INC=-I/usr/include/irods/

all: libirods_irodsShare_preRead.so 

libirods_irodsShare_preRead.so : irodsShare_preRead.cpp
	${GCC} ${INC} -fPIC -shared -o libirods_irodsShare_preRead.so irodsShare_preRead.cpp -Wno-deprecated /usr/lib/irods/libirods_client.a
	
clean:
	@rm -f ./*.so

install: libirods_irodsShare_preRead.so
	sudo -u irods cp -f libirods_irodsShare_preRead.so  /var/lib/irods/plugins/microservices/

uninstall: libirods_irodsShare_preRead.so 
	sudo -u irods rm -rf /var/lib/irods/plugins/microservices/libirods_irodsShare_preRead.so 

test: 
	irule -F test_irodsShare_preRead.r
