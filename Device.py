from subprocess import Popen, PIPE  # check_output

class Device:


    def checkForAdbConnection(self):
        try:
            adbCommandParameters = ["adb","devices"]
            adbCommand = Popen(adbCommandParameters,stdout=PIPE, universal_newlines=True)
            output = adbCommand.communicate()[0]
            if "	device" in output:
                pass
            elif "	unauthorized" in output:
                print("[!] Device is not unauthorized.")
                exit()
            elif "	offline" in output:
                print("[!] Device is offline.")
                exit()
            else:
                print("[!] No device connected.")
                exit()
        except FileNotFoundError:
            print("[!] ADB is not available in the system.")

    def searchPackageByName(self,packageName):
        self.checkForAdbConnection()
        pmCommandParameters = ["adb", "exec-out", "pm", "list", "packages"]
        pmCommand = Popen(pmCommandParameters, stdout=PIPE, universal_newlines=True)
        grepCommand = Popen(["grep", "-i", packageName], stdin=pmCommand.stdout, stdout=PIPE, universal_newlines=True)
        packageList = []
        for package in grepCommand.stdout:
            packageList.append(package.rstrip()[8:])
        return packageList

    def pullApk(self,packageList,choosenIndex):
        packageName = packageList[choosenIndex]
        command = ["adb","exec-out","pm","path",packageName]
        path = Popen(command, stdout=PIPE, universal_newlines=True)
        apkAuxLocation = path.communicate()[0][8:].rstrip()
        apkLocation = apkAuxLocation[0:apkAuxLocation.find(".apk")+4]
        destinationApkLocation = "/tmp/"+packageName+".apk"
        adbCommandParameters = ["adb","pull",apkLocation,destinationApkLocation]
        adbCommand = Popen(adbCommandParameters, stdout=PIPE, universal_newlines=True)
        print("[-] Pulling APK")
        output = adbCommand.communicate()[0]
        if "1 file pulled" in output:
            print("[-] APK pulled")
            return destinationApkLocation
        else:
            return ""

    def showPackagesMenu(self,packageList):
        packageIndex = 1
        for package in packageList:
            print("["+str(packageIndex)+"] - "+package)
            packageIndex+=1
        choosenPackage = int(input("Type package index or enter 0 to quit: "))
        while choosenPackage < 0 or choosenPackage > len(packageList):
            choosenPackage = int(input("Invalid index. Type package index or enter 0 to quit: "))
        if choosenPackage == 0:
            exit() 
        return choosenPackage-1
