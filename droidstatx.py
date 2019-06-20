#!/usr/bin/python3

import argparse
import os
from App import App
from Device import Device
from ApkXmind import ApkXmind


HEADER = """
 _____                _      _                            _    _ 
(____ \              (_)    | |       _           _      \ \  / /
 _   \ \  ____  ___   _   _ | |  ___ | |_   ____ | |_  ___\ \/ / 
| |   | |/ ___)/ _ \ | | / || | /___)|  _) / _  ||  _)(___))  (  
| |__/ /| |   | |_| || |( (_| ||___ || |__( ( | || |__    / /\ \ 
|_____/ |_|    \___/ |_| \____|(___/  \___)\_||_| \___)  /_/  \_\ v0.4
      Android Applications Security Analyser, Xmind Generator
      Created by @clviper
"""

if __name__ == "__main__":
    print(HEADER)
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", nargs=1, help="APK file.", metavar='<File>')
    parser.add_argument("--package", nargs=1, help="Package name.", metavar='<Package>')
    args = parser.parse_args()
    if not (args.apk) and not (args.package):
        parser.print_help()
        exit()
    if args.apk:
        a = App(args.apk[0])
        xmindFile = ApkXmind(a)
    if args.package:
        androidDevice = Device()
        packageList = androidDevice.searchPackageByName(args.package[0])
        index = androidDevice.showPackagesMenu(packageList)
        location = androidDevice.pullApk(packageList,index)
        if location is not "":
            a = App(location)
            xmindFile = ApkXmind(a)
 
