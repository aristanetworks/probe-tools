# probe-tools
Some test tools for RFC8335 PROBE aka ICMP Extended Echo

These are written to be standalone scripts, using scapy for packet
access.  Since scapy doesn't have support for PROBE, and I wanted
to keep these scripts standalone without "and also install this
scapy update from somewhere somehow", there is some ugly use of
struct.pack instead of scapy primitives.

There are two scripts in this repository:

1. probe.py sends a probe request and prints out any received
   probe reply.  It's quite verbose about what it's sending and
   receiving, and isn't meant to be a user-friendly client, the
   idea is more for someone who wants to see what's going on on
   the wire.

2. proberesponder.py listens for probe requests, and sends responses
   based on a predetermined list.  It doesn't care what the request
   is asking about, other than the L bit - it just goes through a list
   of responses - some valid, some invalid - and finally it fails
   to respond at all (resulting in a timeout) before starting through
   the list again.  This is intended to help fine-tune a client's
   user interface: how does it behave when it sees a certain response,
   without having to configure a router to have the state that results
   in that response.
