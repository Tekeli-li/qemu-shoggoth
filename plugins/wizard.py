#!/usr/bin/env python3
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
# *  Daniel Reyes
# *
# * This work is licensed under the terms of the GNU GPL, version 2 or later.
# * See the COPYING file in the top-level directory.
# * 
# * The creation of this code was funded by the US Government.
# */
# TODO:
#   - Add logic to allow plugin names with '_' and '-'

import os
import sys
import argparse
from mako.template import Template

callback_list = ['ra_start', 'ra_stop', 'ra_idle', 'interrupt',
                        'memory_read', 'memory_write', 'state_change', 'exception',
                        'syscall', 'syscall_exit', 'command', 'breakpoint', 'instructions']

templates = {
            'C' :      {'template' : 'PluginTemplate.c',
                        'extension' : '.c',
                        'makefile' : 'MakefileTemplate'},
            'python' : {'template' : 'PythonTemplate.py',
                        'extension' : '.py',
                        'makefile' : 'PyMakefile'}
            }

def run_wizard(plugins, interface, callbacks):

    if '?' in callbacks:
        callbacks = callback_list
    workdir = os.path.dirname(os.path.realpath(__file__)) + '/'

    for plugin in plugins:
        plugdir = workdir + plugin + '/'
        try:
            os.mkdir(plugdir)
        except FileExistsError:
            print("Error: Plugin exist already")
            sys.exit(1)

        srcFile = templates[interface]['template']
        extension = templates[interface]['extension']
        makeFile = templates[interface]['makefile']

        srcskeleton  = Template(filename=workdir+ srcFile)
        makeskeleton = Template(filename=workdir+ makeFile)

        # write rendered skeleton and Makefile
        with open(plugdir+plugin+ extension, 'w') as f:
            code = srcskeleton.render(name=plugin.lower(), Name=plugin.title(),
                                NAME=plugin.upper(), callback=callbacks)

            f.write(code)

        with open(plugdir+ 'Makefile', 'w') as f:
            code = makeskeleton.render(name=plugin.lower(), Name=plugin.title(),
                                NAME=plugin.upper())
            f.write(code)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Creates QEMU plugin directory and skeleton")
    
    parser.add_argument("action", type=str, metavar="ACTION", help="Action to take (create)",
                        choices=['create'])

    parser.add_argument("plugins", nargs='+', type=str, metavar="PLUGIN", help="name of plugin")
   
    parser.add_argument('-i', '--interface', metavar='--interface',
                        help="sets plugin interface mode, default C",
                        choices=['C', 'python'])

    parser.add_argument('-cb', '--callbacks', nargs='+', metavar='--callbacks',
                        help="callback function to include in template",
                        choices=callback_list + ['?'], default=[])
    
    args = parser.parse_args()
    
    if args.interface == None:
        args.interface = 'C'

    if args.action == 'create':
        run_wizard(args.plugins, args.interface, args.callbacks)

