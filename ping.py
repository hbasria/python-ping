#!/usr/bin/env python

"""
    A pure python ping implementation using raw socket.


    Note root access not required


    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.

    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependenceies here.

    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.

    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py

    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122


    Revision history
    ~~~~~~~~~~~~~~~~

    March 11, 2010
    changes by Samuel Stauffer:
    - replaced time.clock with default_timer which is set to
      time.clock on windows and time.time on other systems.

    May 30, 2007
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"

    November 22, 1997
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.

    December 16, 1997
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().

    December 4, 2000
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.

    Januari 27, 2015
    Changed receive response to not accept ICMP request messages.
    It was possible to receive the very request that was sent.
    
    May 29, 2016
    root access not required
    latency (MIN/MAX/AVG) calc added

    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: $
    $Rev: $
    $Author: $
"""
import collections
import getopt
import os
import select
import socket
import struct
import sys
import time

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8  # Seems to be the same on Solaris.


def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    countTo = (len(source_string) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2

    if countTo < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff  # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def receive_one_ping(my_socket, ID, timeout):
    """
    receive the ping from the socket.
    """
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return

        timeReceived = time.time()
        recPacket, addr = my_socket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        if packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return


def send_one_ping(my_socket, dest_addr, ID):
    """
    Send one ping to the given >dest_addr<.
    """
    dest_addr = socket.gethostbyname(dest_addr)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0

    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", time.time()) + data

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1))  # Don't know about the 1


def do_one(dest_addr, timeout):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except socket.error, (errno, msg):
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise  # raise the original error

    my_ID = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_ID)
    delay = receive_one_ping(my_socket, my_ID, timeout)

    my_socket.close()
    return delay


def ping(dest, count=10, timeout=2):
    lost = 0  # Number of loss packets
    mos = 0  # Mean Opinion Score
    latency = []  # Delay values [MIN. MAX, AVG]
    jitter = []  # Jitter values [MAX, AVG]
    time_sent = []  # Timestamp when packet is sent
    time_recv = []  # Timestamp when packet is received
    PingResult = collections.namedtuple('PingResult', 'lost lost_perc min max avg jitter mos')

    if count <= 0:
        raise Exception("count must be greater than zero.")

    if timeout <= 0:
        Exception("timeout must be greater than zero.")

    for i in range(0, count):
        try:
            time_sent.append(int(round(time.time() * 1000)))
            d = do_one(dest, timeout)
            if d == None:
                lost = lost + 1
                time_recv.append(None)
                continue
            else:
                time_recv.append(int(round(time.time() * 1000)))
        except:
            raise Exception("Socket error")

        # Calculate Latency:
        latency.append(time_recv[i] - time_sent[i])

        # Calculate Jitter with the previous packet
        # http://toncar.cz/Tutorials/VoIP/VoIP_Basics_Jitter.html
        if len(jitter) == 0:
            # First packet received, Jitter = 0
            jitter.append(0)
        else:
            # Find previous received packet:
            for h in reversed(range(0, i)):
                if time_recv[h] != None:
                    break
            # Calculate difference of relative transit times:
            drtt = (time_recv[i] - time_recv[h]) - (time_sent[i] - time_sent[h])
            jitter.append(jitter[len(jitter) - 1] + (abs(drtt) - jitter[len(jitter) - 1]) / float(16))

    # Calculating MOS
    if len(latency) > 0:
        EffectiveLatency = sum(latency) / len(latency) + max(jitter) * 2 + 10
        if EffectiveLatency < 160:
            R = 93.2 - (EffectiveLatency / 40)
        else:
            R = 93.2 - (EffectiveLatency - 120) / 10
            # Now, let's deduct 2.5 R values per percentage of packet loss
            R = R - (lost * 2.5)
            # Convert the R into an MOS value.(this is a known formula)
        mos = 1 + (0.035) * R + (.000007) * R * (R - 60) * (100 - R)

    # Setting values (timeout, lost and mos are already calculated)
    lost_perc = lost / float(count) * 100
    if len(latency) > 0:
        min_latency = min(latency)
        max_latency = max(latency)
        avg_latency = sum(latency) / len(latency)
    else:
        min_latency = 'NaN'
        max_latency = 'NaN'
        avg_latency = 'NaN'
    if len(jitter) != 0:
        tot_jitter = jitter[len(jitter) - 1]
    else:
        tot_jitter = 'NaN'

    return PingResult(lost=lost, lost_perc=lost_perc, min=min_latency, max=max_latency, avg=avg_latency,
                      jitter=tot_jitter, mos=mos)


if __name__ == '__main__':
    dest, timeout, count = None, 2, 10

    try:
        dest = sys.argv[1]
        opts, args = getopt.getopt(sys.argv[1:], ':hc:t:d:o:f:')
    except Exception as err:
        print 'Usage: %s 8.8.8.8 -c [count] -t [timeout]' % sys.argv[0]
        sys.exit(1)

    for opt, arg in opts:
        if opt in '-h':
            print 'Usage: %s -c <count> -t <timeout> -d <host>' % sys.argv[0]
            sys.exit(1)

        if opt in '-c':
            count = int(arg)
        elif opt in '-t':
            timeout = int(arg)

    result = ping(dest, timeout=timeout, count=count)

    print("Statistics for %s:" % (dest))
    print(" - packet loss: %i (%.2f%%)" % (result.lost, result.lost_perc))
    print(" - latency (MIN/MAX/AVG): %s/%s/%s" % (result.min, result.max, result.avg))

    if type(result.jitter) != str:
        print(" - jitter: %.4f" % result.jitter)
    else:
        print(" - jitter: %s" % result.jitter)

    print(" - MOS: %.1f" % result.mos)
