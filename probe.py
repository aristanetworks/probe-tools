#!/usr/bin/env python3
# Copyright (c) 2023 Arista Networks, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This began as a little proof-of-concept, and grew and grew.
# One of those things that you wouldn't have done it this way
# if you knew it would have become this from scratch.  But,
# I'm publishing it anyway, since it does seem useful even
# if it's awkward and ugly.

from scapy.all import *
import struct
import argparse

# Patch scapy to allow sr() to treat type-43 as a reply to type-42.
origIcmpAnswers = ICMP.answers
def extendedIcmpAnswers( self, other ):
    if isinstance( other, ICMP ) and (other.type,self.type) == (42, 43):
        # id + seq, for extended ICMP echo request and reply
        return ( other.unused & 0xffffff00 ) == ( self.unused & 0xffffff00 )
    return origIcmpAnswers( self, other )
ICMP.answers = extendedIcmpAnswers

codes = {
          0: 'No Error',
          1: 'Malformed Query',
          2: 'No Such Interface',
          3: 'No Such Table Entry',
          4: 'Multiple Interfaces Satisfy Query',
          }
states = {
          0: 'Reserved',
          1: 'Incomplete',
          2: 'Reachable',
          3: 'Stale',
          4: 'Delay',
          5: 'Probe',
          6: 'Failed',
          }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument( 'ipaddr' )
    group = parser.add_mutually_exclusive_group( required=True )
    group.add_argument( '--ifindex', type=int )
    group.add_argument( '--ifname' )
    group.add_argument( '--addr' )
    parser.add_argument( '--remote', action='store_true' )
    parser.add_argument( '--checksum', default=-1, type=int )
    parser.add_argument( '--extra', action='store_true' )
    parser.add_argument( '--id', default=42, type=int )
    parser.add_argument( '--seq', default=42, type=int )
    args = parser.parse_args()

    probeid = args.id
    seq = args.seq
    l = 0 if args.remote else 1
    pkt = IP(dst=args.ipaddr)/ICMP(type=42, unused=( probeid << 16 ) | (seq << 8 ) | l)
    def icmpPayload( cksum=0 ):
        data = struct.pack( '>HH', ( 2 << 12 ), cksum ) # ver, checksum
        if args.ifname:
            ctype = 1
            payload = args.ifname.encode()
            if len( payload ) % 4:
                payload += b'\x00' * ( 4 - len( payload ) % 4 )
        elif args.ifindex:
            ctype = 2
            payload = struct.pack( '>I', args.ifindex )
        else:
            assert args.addr
            ctype = 3
            if ':' in args.addr:
                af = socket.AF_INET6
            else:
                af = socket.AF_INET
            addr = socket.inet_pton( af, args.addr )
            payload = struct.pack( '>HBB', 1 if af == socket.AF_INET else 2, len(addr), 0 )
            payload += addr
        # length = N, Class-Num = iio = 3, C-Type = ctype
        data += struct.pack( '>HBB', len( payload ) + 4, 3, ctype )
        return data + payload
    if args.checksum == -1:
        # This is a stupid way to calculate and fill in the checksum, but,
        # I don't feel like replacing bytes in the middle.
        payload = icmpPayload( checksum( icmpPayload() ) )
    else:
        payload = icmpPayload( args.checksum )
    # One responder says my payload is malformed.  Looking at what *they* send,
    # it looks similar but with a timestamp appended.  So let's just
    # append a timestamp like we saw from them.
    if args.extra:
        payload += b'e\x83b\x97\x00\x02-\xe3'
    pkt /= Raw( payload )
    ans, unans = sr( pkt, filter='icmp[icmptype] == 43', timeout=10 )
    # for each answer:
    for a in ans:
        print( 'Request:' )
        a[ 0 ][ ICMP ].show()
        icmp = a[ 1 ][ ICMP ]
        val = icmp.unused
        state = ( val & 0xe0 ) >> 5
        active = bool( val & 0x04 )
        ipv4 = bool( val & 0x02 )
        ipv6 = bool( val & 0x01 )
        print( 'Response:' )
        icmp.show()
        print( f"code {icmp.code} ({codes.get(icmp.code,'?')}) state {state} ({states.get(state,'?')}) active {active} ipv4 {ipv4} ipv6 {ipv6}" )

if __name__ == "__main__":
    main()

# vi:et sw=4
