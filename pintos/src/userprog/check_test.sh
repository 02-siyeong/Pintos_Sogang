#pintos -p ./build/tests/userprog/args-single -a args-single -- -q
#pintos -- -q run 'args-single 1'


#pintos -f -q
#pintos -p ./build/tests/userprog/create-normal -a create-normal -- -q
#pintos -p ./build/tests/userprog/create-null -a create-null -- -q
#pintos -p ./build/tests/userprog/open-twice -a open-twice -- -q
#pintos -p ./build/tests/userprog/read-bad-ptr -a read-bad-ptr -- -q
#pintos -p ./build/tests/userprog/no-vm/multi-oom -a multi-oom -- -q
#pintos -p ../tests/userprog/sample.txt -a sample.txt -- -q
#pintos -p ./build/tests/userprog/child-args -a child-args -- -q
#pintos -p ./build/tests/userprog/exec-missing -a exec-missing -- -q
#pintos -p ./build/tests/userprog/child-simple -a child-simple -- -q
#pintos -- -q run 'exec-missing'
#pintos -- -q run 'create-normal'
pintos -- -q run 'multi-oom'
