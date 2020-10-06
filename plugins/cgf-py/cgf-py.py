#/*
# * Rapid Analysis QEMU System Emulator
# *
# * Copyright (c) 2020 Cromulence LLC
# *
# * Distribution Statement A
# *
# * Approved for Public Release, Distribution Unlimited
# *
# * Authors:
# *  Joseph Walker
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */

import sys
from sys import stdout
import binascii
import itertools
import random
from pyqemu.messages import *
from pyqemu.plugin import *

sinput = ''
UPPER_ALPHA   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER_ALPHA   = "abcdefghijklmnopqrstuvwxyz"
NUMERALS      = "0123456789"

NBINS = 0x8faf2 - 0x7aa
SINPUT_SIZE = 256
REPORT_FREQ = 0x1F

#Generates a random input
def rand_input():
    input_length = SINPUT_SIZE
    char_max = 255
    ret_str = [chr(random.randint(0,char_max)) for i in range(input_length)]
    joint = "".join(ret_str)
    return joint

def iter_str(iter_str):
    #increment first item
    base = iter_str[0]
    #create new empty string
    length = len(iter_str)
    newStr = [chr(0) for i in range(length)]
    newStr[0] = chr(ord(base))

    for i in range(length):
        cur_char = iter_str[i]
        if cur_char == 0:
            if i < 255:
                newStr[i+1] =chr(ord(cur_char) + 1)
            newStr[i] = 0
    
    return "".join(newStr)


                


def on_plugin_load(*args):
    print("args[0]" + str(args[0]))
    print("args[1]" + str(args[1]))
    print("SYS PATH" + str(sys.path))
    
    global sinput, instrBins, done, cum_old
    global fuzzJobCount
    global done
    fuzzJobCount = 0
    cum_old = 0
    done = False
    #setup NBIN to all 0s
    instrBins = [0 for i in range(NBINS)]
    #generate str of all 0
    sinput = "".join([chr(0) for i in range(SINPUT_SIZE)])

def on_ra_start(work_item):
    global fuzzJobCount
    #print("Python: RA Started")
    if(fuzzJobCount % REPORT_FREQ == 0):
        print("Fuzz Job: {}".format(fuzzJobCount))

def on_ra_stop(work_results):
    global done, sinput
    global instrNew, instrBase, instrBins, instrCount
    global fuzzJobCount
    global cum_old
    #print("Python: RA Stopped")
   
    #increment our job count
    fuzzJobCount += 1
    if instrNew == False:
        cum_old += 1
    else:
        cum_old = 0
    
    if cum_old > 5:
        sinput = rand_input()
    else:
        sinput = iter_str(sinput)
    

def on_ra_idle():
    #print("Python: RA Idle")
    global done, sinput, fuzzJobCount, cum_old
    global instrNew, instrBase, instrBins, instrCount

    if done:
        print("Found Segfault")
        return

    instrCount = 0
    instrBase = 0
    instrNew = False
    bHash = "2cfa4aafd5904143d61fbf795b215da016f70cf5"
    #bHash = "ccd12c4d12fef17da56d3ee6d6cc9e789a3cefb4"
    
    offset = 0x7fffffffe580
    if fuzzJobCount % REPORT_FREQ == 0:
        print("Starting Job {}".format(fuzzJobCount, sinput))
        for i in sinput:
            stdout.write("%02x " % (ord(i)))
        stdout.write("\n")
        scale = int(NBINS / 68)
        print("Coverage is: Scale {}".format(scale))
        inc = 0
        while inc < NBINS:
            bin_sum = 0
            for j in range(scale):
                bin_sum += instrBins[j+inc]
            stdout.write("%lu " % (bin_sum))
            inc += scale
        stdout.write("\n")
        print("Stale path count: {}".format(cum_old))
        
    message = CommsMessage() / CommsRequestJobAddMsg(
            
            queue = 1,
            job_id = fuzzJobCount,
            base_hash = bHash,
            entries = [
                CommsRequestJobAddMemorySetup(flags="memory_virtual", size=len(sinput), offset=offset, value=bytes(sinput, "UTF-8"))
            ]
    )

    if not done:
        RapidAnalysis.addJob(1, message)

#def get_ra_report_type():
#    return 1

#def on_breakpoint_hit(cpu_id, pc, bp_id):
#    print("Python: Breakpoint hit")
#    continue_vm()

def on_exception(exception):
    global done
    stdout.write('Exception found on input: ')
    for i in sinput:
        stdout.write("%02x " % (ord(i)))
    stdout.write("\n")
    print("Exception # {}".format(exception))
    done = True

def on_execute_instruction(vaddr, addr):
    global sinput, instrNew, instrBase, instrBins, instrCount
    #print("Python: On Instruction {}".format(str(addr)))
    
    if instrCount == 0:
        instrBase = vaddr
    else:
        bin_hit = vaddr - instrBase
        if bin_hit > 0 and bin_hit < NBINS:
            if instrBins[bin_hit] == 0:
                instrNew = True
            instrBins[bin_hit] += 1
    instrCount += 1

#def on_memory_write(paddr, pval, pbytes):
#    print("Python: On Memory Write " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_memory_read(paddr, pval, pbytes):
#    print("Python: On Memory Read " + hex(paddr) + " value " + hex(pval))
#    print(binascii.hexlify(CPU.getPhysicalMemory(paddr, len(pbytes))))

#def on_syscall(number, args):
#    print("on_syscall")

#def on_vm_change_state(running, state):
#    print('on_vm_change_state' , running)

#def on_interrupt(mask):
#    print('on_interrupt')

#def on_packet_recv(data):
#    print('on_packet_recv: ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

#def on_packet_send(data):
#    print('on_packet_send ', ''.join('{:02x}'.format(x) for x in bytearray(data)))
#    return None

#def on_vm_shutdown():
#    print('VM is closing')
