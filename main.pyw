# Zdenek Loucka, SMO DT IT / 2021
# Log4Shell vulnerability scanner
# Version 2.4
# GNU General Public License v3.0

import re
import os
import sys
import time
import queue
import string
import tkinter
import zipfile
import threading
import subprocess
from sys import platform
from ctypes import windll

#----------------------------------------

# currently only Windows is supported, exit if OS is not Windows
if platform != "win32":
    quit()

#----------------------------------------

# define main window class
class mainWindow(tkinter.Tk):
    def __init__(self):
        # inherit super
        super().__init__()

        # init icon and define colors, add window settings
        self.setIcon()
        self.background = self.rgbToHex(30, 30, 30)
        self.activebackground = self.rgbToHex(60, 60, 60)
        self.selectbackground = self.rgbToHex(45, 45, 45)
        self.width = 20
        self.title('Log4Shell jar scanner')
        self.statustext = "Not started"
        self.disclaimer = "Zdenek Loucka, SMO DT IT / 2021"
        self.disclaimer2 = "GNU General Public License v3.0, no warranty"
        self.geometry("1200x675")  # 800x450 * 1.25
        self.foreground = 'white'
        self.resizable(False, False)
        self.configure(background=self.background)

        # define shared class variables
        self.drives = self.getDrives()
        self.resultsLock = threading.RLock()
        self.animationLock = threading.RLock()
        self.results = []
        self.hasRun = False
        self.isScanning = False

        # define widgets, create spacer pack spacerDict[x]
        self.spacerDict = {}
        for spacer in range(3):
            self.spacerDict[spacer] = tkinter.Label(background = self.background)
            
        self.button1 = tkinter.Button (
            text                = "Log4Shell jar scanner",
            background          = self.background,
            foreground          = self.foreground,
            width               = self.width,
            activebackground    = self.activebackground,
            activeforeground    = self.foreground,
            command             = self.findJars
        )
        
        self.log1 = tkinter.Listbox (
            width               = int(9 * self.width),
            height              = int(1.5 * self.width),
            background          = self.activebackground,
            foreground          = self.foreground,
            selectbackground    = self.selectbackground,
            activestyle         = "none"
        )
        
        self.label1 = tkinter.Label (
            text                = self.statustext,
            background          = self.background,
            foreground          = self.foreground
        )
        
        self.label2 = tkinter.Label (
            text                = self.disclaimer,
            background          = self.background,
            foreground          = self.foreground
        )
        
        self.label3 = tkinter.Label (
            text                = self.disclaimer2,
            background          = self.background,
            foreground          = self.foreground
        )

        # assign widgets to layout
        self.spacerDict[0].pack()
        self.button1.pack()
        self.spacerDict[1].pack()
        self.log1.pack()
        self.spacerDict[2].pack()
        self.label1.pack()
        self.label2.pack()
        self.label3.pack()

        #bind functionality and init log
        self.log1.bind (
            '<Double-Button>', 
            self.logClickHandler
        )
        
        self.log1.insert (
            1,
            "Welcome, detected system drives: " + str(self.drives)
        )

        # focus window and start event loop
        self.log1.focus_set()
        self.lift()
        self.mainloop()

    # class method to call when button pressed
    def findJars(self):
        # if not already scanning, define a new thread
        if not self.isScanning:
            # if app has run, clear the log and shared results and join previous thread before running again
            if self.hasRun:
                self.log1.delete(0, tkinter.END)
                with self.resultsLock:
                    self.results = []
                self.searchThread.join()
                
            self.searchThread = threading.Thread(
                name    = "searchThread",
                target  = self.searchFunction
            )
            
            self.searchThread.daemon = True
            self.searchThread.start()
            self.isScanning = True

    # class method to animate search
    def animateSearch(self):
        animationList = ["Searching",
                        ". Searching .",
                        ". . Searching . .",
                        ". . . Searching . . ."]
        while True:
            for animationIndex, anim in enumerate(animationList):
                with self.animationLock:
                    self.label1.config(text=animationList[animationIndex])
                    if not self.animating:
                        break
                time.sleep(1)
            with self.animationLock:
                if not self.animating:
                    break

    # static class method to check if a file is a log4j jar file
    @staticmethod
    def isL4J(target):
        expression_L4J = re.compile("log4j-.+\.jar$")
        result = expression_L4J.findall(target)
        if len(result) > 0:
            return True

    # static class method to check if a jar file has nested L4J files
    @staticmethod
    def hasNestedL4J(target):
        # define local regular expressions
        expression_L4J = re.compile("log4j-.+\.jar$")
        expression_anyJar = re.compile("\.jar$")
        try:
            target = os.path.abspath(target)
            with zipfile.ZipFile(target, 'r') as ZipFile:
                listFileNames = ZipFile.namelist()
                for file in listFileNames:
                    filename = os.path.basename(file)
                    if expression_L4J.findall(filename):
                        return True
                    else:
                        return False
        except:
            # skip BadZipFile
            pass 

    # static class method to check if a jar file has nested jar files
    @staticmethod
    def hasNestedJar(target):
        expression_L4J = re.compile("log4j-.+\.jar$")
        expression_anyJar = re.compile("\.jar$")
        try:
            with zipfile.ZipFile(target, 'r') as ZipFile:
                listFileNames = ZipFile.namelist()
                for file in listFileNames:
                    filename = os.path.basename(file)
                    if filename == nestedJarName:
                        with zipfile.ZipFile(file, 'r') as nestedZipFile:
                            nestedListFileNames = nestedZipFile.namelist()
                            for nestedFile in nestedListFileNames:
                                nestedFilename = os.path.basename(
                                    nestedFile)
                                if expression_L4J.findall(nestedFilename):
                                    return True
                                elif expression_anyJar.findall(nestedFilename):
                                    if mainWindow.hasNestedL4J(target, True, nestedFilename):
                                        return True
                                else:
                                    return False
        except:
            # skip BadZipFile etc.
            pass

    # static class method to find all jar files
    @staticmethod
    def subSearchFunction(target, thread_queue):
        try:
            # define local regular expression
            expression_anyJar = re.compile("\.jar$")
            with os.scandir(str(target)) as scandirObject:
                for entry in scandirObject:
                    if entry.is_file(follow_symlinks=False):
                        isJarfile = expression_anyJar.search(entry.name)
                        if isJarfile:
                            thread_queue.put(str(os.path.abspath(entry.path)))
                    elif entry.is_dir(follow_symlinks=False):
                        mainWindow.subSearchFunction(
                            os.path.abspath(entry.path), thread_queue)
        except:
            # skip inaccessible directories
            pass 

    # static class method to consume thread data queue
    @staticmethod
    def consumeQueue(thread_queue):
        queueResults = []
        while True:
            try:
                queueResults.append(thread_queue.get_nowait())
            except:
                break
        return queueResults

    # main class method for executing search tasks
    def searchFunction(self):
        # acquire animation lock and start animation thread
        with self.animationLock:
            self.animating = True
            
        self.animationThread = threading.Thread (
            name = "animationThread",
            target=self.animateSearch
        )
        
        self.animationThread.start()

        # create and dispatch scanning thread per drive, get all jar files
        driveThreadDictionary = {}
        drive_thread_queues = {}
        drive_thread_results = {}
        
        for drive_index, drive in enumerate(self.drives):
            if platform == "win32":
                drive = str(drive) + ":\\"
                
            drive_thread_queues[drive_index] = queue.Queue()
            driveThreadDictionary[drive_index] = threading.Thread (
                name    = f'driveThread{drive_index}',
                target  = mainWindow.subSearchFunction,
                args    = (drive, drive_thread_queues[drive_index])
            )
                
            driveThreadDictionary[drive_index].daemon = True
            driveThreadDictionary[drive_index].start()

        # wait for threads to finish, join them and get all respective local results
        for drive_index, drive in enumerate(self.drives):
            driveThreadDictionary[drive_index].join()
            drive_thread_results[drive_index] = mainWindow.consumeQueue(
                drive_thread_queues[drive_index])
            newResults = []

            # append local results per drive to shared results 
            for result in drive_thread_results[drive_index]:
                # if they match as L4J
                if mainWindow.isL4J(result):
                    newResults.append(result)
                # or as nested jar 
                elif mainWindow.hasNestedL4J(result):
                    newResults.append(result)
            with self.resultsLock:
                self.results = self.results + newResults

        # if we have any results, get versions of L4J and insert them to the log
        with self.resultsLock:
            if len(self.results) > 0:
                for resultIndex, result in enumerate(self.results):
                    resultIndex = resultIndex + 1
                    if mainWindow.isL4J(result):
                        result = (str(resultIndex) + ": " +
                                  str(mainWindow.getVersion(result)) + ": " + result)
                    elif mainWindow.hasNestedL4J(result):
                        result = (str(resultIndex) + ": " +
                                  "Nested Jar" + ": " + result)
                    self.log1.insert(resultIndex, result)
            else:
                self.log1.insert(1, "No results, all good!")

        # stop animation
        with self.animationLock:
            self.animating = False
        self.animationThread.join()
        
        # set status to done
        with self.animationLock:
            self.label1.config(text="Done, double click a result to open directory")
        if self.hasRun == False:
            # offset for welcome message
            with self.resultsLock:
                self.results.insert (
                    0,
                    "blank"
                )
                
            self.hasRun = True
            self.isScanning = False

    # class method to call when log item double-clicked
    def logClickHandler(self, arg):
        selection = self.log1.curselection()[0]
        if self.hasRun:
            with self.resultsLock:
                path = os.path.dirname(self.results[selection])
        else:
            path = ""
        if path != 0:
            subprocess.Popen(f'explorer "{path}"')

    # class method to try and set app icon
    def setIcon(self):
        try:
            iconFile = 'icon.ico'
            if getattr(sys, 'frozen', False):
                application_path = sys._MEIPASS
            elif __file__:
                application_path = os.path.dirname(__file__)
            self.iconbitmap(os.path.join(application_path, iconFile))
        except:
            pass # don't crash while trying to set a missing icon

    # static class method to get drives on Windows, target root on linux/unix
    @staticmethod
    def getDrives():
        drives = []
        if platform == "win32":
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(letter)
                bitmask >>= 1
        else:
            drives.append("/")
        return drives

    # static class method to convert RGB to HEX colors
    @staticmethod
    def rgbToHex(r, g, b):
        return f'#{r:02x}{g:02x}{b:02x}'

    # static class method to get version information from the Manifest or POM file
    @staticmethod
    def getVersion(target):
        # submethod to check manifest files
        def disassembleManifest(manifest):
            expression_manifest = re.compile(
                "Implementation-Version: (.+)\\\\r")
            content = ZipFile.read(manifest)
            content = str(content).split("\\n")
            for line in content:
                result = expression_manifest.findall(line)
                if result:
                    version = str(result)
            if "version" in locals():
                return version
                
        # submethod to check pom files
        def disassemblePomfile(pomfile):
            expression_maven = re.compile("version=(.+)")
            content = ZipFile.read(pomfile)
            content = str(content).split("\\n")
            for line in content:
                result = expression_maven.findall(line)
                if result:
                    version = str(result)
            if "version" in locals():
                return version
                
        # primary block
        try:
            with zipfile.ZipFile(target, 'r') as ZipFile:
                listFileNames = ZipFile.namelist()
                for file in listFileNames:
                    filename = os.path.basename(file)
                    if filename == 'MANIFEST.MF':
                        if disassembleManifest(file):
                            version = disassembleManifest(file)
                    elif filename == 'pom.properties':
                        if disassemblePomfile(file):
                            version = disassemblePomfile(file)
            if "version" in locals():
                return version
            else:
                return "unknown"
        except:
            return "error"

#----------------------------------------

# start application
if __name__ == "__main__":
    appWindow = mainWindow() 
