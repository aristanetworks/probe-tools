#!/usr/bin/env python3
# Copyright (c) 2024 Arista Networks, Inc.
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

from scapy.all import *
import struct
import argparse
from collections import namedtuple

# A synthetic PROBE (RFC8335) response generator.
# We get an ICMP PROBE request, and only parse the
# L bit.  For each setting of the L bit, we have a
# series of responses that we iterate through -
# various code and other bit values - to exercise the
# code in the probe client that prints out responses.
# Once we've gone through the list, we time out once
# and then start the list again from the beginning.

# Local bit = 1: responses have code value, A, 4, 6 bits.
L1 = namedtuple( 'L1', ['code', 'A', 'v4', 'v6' ] )

# Note: the status field should be zero for all of
# these responses; should we have a response where
# we set it to test the client's behavior?
localResponses = [
        L1( code=0, A=0, v4=0, v6=0 ),     # interface is not active
        L1( code=0, A=1, v4=0, v6=0 ),     # curious, interface is active but no v4/v6
        L1( code=0, A=1, v4=1, v6=0 ),
        L1( code=0, A=1, v4=0, v6=1 ),
        L1( code=0, A=1, v4=1, v6=1 ),
        L1( code=1, A=0, v4=0, v6=0 ),
        L1( code=2, A=0, v4=0, v6=0 ),
        L1( code=3, A=0, v4=0, v6=0 ),
        L1( code=4, A=0, v4=0, v6=0 ),
        L1( code=5, A=0, v4=0, v6=0 ),     # invalid code
        L1( code=255, A=0, v4=0, v6=0 ),   # really invalid code
        L1( code=1, A=1, v4=1, v6=1 ),     # shouldn't happen: code != 0 => A = 0
        ]

# Local bit = 0: responses have code and state.
L0 = namedtuple( 'L0', ['code', 'state'] )

# Note: any packet with A, v4, v6 set would be
# malformed (or, those values should just be ignored);
# should we test those?
remoteResponses = [
        L0( code=0, state=1 ),
        L0( code=0, state=2 ),
        L0( code=0, state=3 ),
        L0( code=0, state=4 ),
        L0( code=0, state=5 ),
        L0( code=0, state=6 ),
        L0( code=0, state=7 ),    # invalid state
        L0( code=5, state=0 ),    # invalid code
        L0( code=255, state=0 ),  # really invalid code
        L0( code=0, state=0 ),    # shouldn't happen, if we found it, state should be nonzero
        ]

l0idx = 0
l1idx = 0

iface = None

def respond( pkt ):
    global l0idx, l1idx
    print( 'got', repr( pkt ) )
    if IP in pkt:
        ip = IP
        icmp = ICMP
        responseType = 43
    else:
        if IPv6 not in pkt:
            print( '[ignoring]' )
            return
        ip = IPv6
        icmp = ICMPv6Unknown
        responseType = 161
    response = pkt[ ip ]
    esrc, edst = pkt.src, pkt.dst
    pkt.dst, pkt.src = esrc, edst
    src, dst = response.src, response.dst
    response.dst, response.src = src, dst
    if ip == IP:
        response.id = ( response.id + 42 ) % 65536
    response.chksum = None
    response.len = None
    if icmp == ICMP:
        secondWord = response[ ICMP ].unused
    else:
        # Why does an unknown ICMPv6 type parse to Raw
        # and not ICMPv6Unknown?  That's unknown.
        response.payload = icmp( response.payload )
        print( "Updated", repr( response ) )
        secondWord = struct.unpack( ">I", response[ icmp ].msgbody[ : 4 ] )[ 0 ]
    response[ icmp ].type = responseType
    local = secondWord & 0x1
    idAndSeq = secondWord & 0xffffff00
    if local:
        if l1idx >= len( localResponses ):
            # Last one - let it time out, but reset
            # so we start the loop again next time
            l1idx = 0
            print( "letting it time out" )
            return
        resp = localResponses[ l1idx ]
        l1idx += 1
        response[ icmp ].code = resp.code
        if resp.A:
            idAndSeq |= 0x4
        if resp.v4:
            idAndSeq |= 0x2
        if resp.v6:
            idAndSeq |= 0x1
    else:
        if l0idx >= len( remoteResponses ):
            # Last one - let it time out, but reset
            # so we start the loop again next time
            l0idx = 0
            print( "letting it time out" )
            return
        resp = remoteResponses[ l0idx ]
        l0idx += 1
        response[ icmp ].code = resp.code
        idAndSeq |= resp.state << 5
    if icmp == ICMP:
        response[ ICMP ].unused = idAndSeq
    else:
        response[ icmp ].msgbody = struct.pack( ">I", idAndSeq ) + response[ icmp ].msgbody[ 4 : ]
    # recalculate checksums
    if icmp == ICMP:
        response[ icmp ].chksum = None
    else:
        # There's no "h" in IPv6
        response[ icmp ].cksum = None
    print( "sending", repr( pkt ) )
    sendp( pkt, iface=iface )

def main():
    global iface

    parser = argparse.ArgumentParser()
    parser.add_argument( '--iface' )
    args = parser.parse_args()

    if args.iface:
        iface = args.iface
    sniff(iface=iface, filter='icmp[icmptype] == 42 or icmp6[icmptype] == 160', prn=respond)

if __name__ == '__main__':
    main()

# vi:et sw=4
