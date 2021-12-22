# Zdenek Loucka, SMO DT IT / 2021
# Log4Shell vulnerability scanner
# Version 2.3
# GNU General Public License v3.0

import re
import os
import sys
import time
import threading
import subprocess
import tkinter
import string
import zipfile
import multiprocessing
from ctypes import windll
from sys import platform



import functools
def timeit(func):
    @functools.wraps(func)
    def new_func(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        print('function [{}] finished in {} ms'.format(
            func.__name__, int(elapsed_time * 1_000)))
        return result
    return new_func



if platform == "win32":
    pass
else:
    quit()

class mainWindow(tkinter.Tk):
    def __init__(self):
        super().__init__()
        self.setIcon()
        self.background = self.rgbtohex(30,30,30)
        self.activebackground = self.rgbtohex(60,60,60)
        self.selectbackground = self.rgbtohex(45,45,45)
        self.statustext="Not started"
        self.foreground='white'
        self.width = 20
        self.disclaimer = "Zdenek Loucka, SMO DT IT / 2021"
        self.disclaimer2 = "GNU General Public License v3.0, no warranty"
        self.geometry("1000x565") # 800x450 * 1.25
        self.resizable(0, 0)
        self.title('Log4Shell jar scanner')
        self.configure(background=self.background)
        self.drives = self.getDrives()
        self.spacerDict={}
        for spacer in range(3):
            self.spacerDict[spacer] = tkinter.Label(background=self.background)
        self.button1 = tkinter.Button(text="Log4Shell jar scanner", background=self.background, foreground=self.foreground, width=self.width, activebackground=self.activebackground, activeforeground=self.foreground,command=self.findJars)
        self.log1 = tkinter.Listbox(width=int(7.5*self.width), height=int(1.25*self.width), background=self.activebackground, foreground=self.foreground, selectbackground=self.selectbackground,activestyle="none")
        self.label1 = tkinter.Label(text=self.statustext, background=self.background, foreground=self.foreground)
        self.label2 = tkinter.Label(text=self.disclaimer, background=self.background, foreground=self.foreground)
        self.label3 = tkinter.Label(text=self.disclaimer2, background=self.background, foreground=self.foreground)
        self.spacerDict[0].pack()
        self.button1.pack()
        self.spacerDict[1].pack()
        self.log1.pack()
        self.spacerDict[2].pack()
        self.label1.pack()
        self.label2.pack()
        self.label3.pack()
        self.log1.bind('<Double-Button>', self.logClickHandler)
        self.log1.insert(1, "Welcome, detected system drives: " + str(self.drives))
        self.log1.focus_set()
        self.lift()
        self.resultsLock = threading.RLock()
        self.animLock = threading.RLock()
        self.results=[]
        self.hasRun=False
        self.mainloop()

    def findJars(self):
        if threading.active_count() < 2:
            if self.hasRun:
                self.log1.delete(0, tkinter.END)
                with self.resultsLock:
                    self.results=[]
                self.searchThread.join()
            self.searchThread = threading.Thread(target=self.searchfunction)                
            self.searchThread.daemon = True                
            self.searchThread.start()

    def animateSearch(self):
        animList = ["Searching",". Searching .",". . Searching . .",". . . Searching . . ."]
        while True:
            for animIndex, anim in enumerate(animList):
                with self.animLock:
                    self.label1.config(text = animList[animIndex])
                time.sleep(1)
                with self.animLock:
                    if self.animating == False:
                        break
            with self.animLock:
                if self.animating == False:
                    break

    @staticmethod
    def subSearchFunction(target, queue):
        expression = re.compile("log4j-.+\.jar$")
        with os.scandir(str(target)) as scandirObject:
            for entry in scandirObject:
                try:
                    if entry.is_file():
                        result = expression.search(entry.name)
                        if result:
                            queue.put(str(os.path.abspath(entry.path)))
                    elif entry.is_dir():
                        mainWindow.subSearchFunction(os.path.abspath(entry.path), queue)
                except:
                    pass

    @staticmethod
    def consumeQueue(queue):
        queueResults=[]
        while True:
            try:
                queueResults.append(queue.get_nowait())
            except:
                break      
        return queueResults
        
    @timeit
    def searchfunction(self):
        with self.animLock:
            self.animating = True
        self.animateThread = threading.Thread(target=self.animateSearch)
        self.animateThread.start()
        driveProcessDictionary={}
        driveProcessQueues={}
        driveProcessResults={}
        for driveIndex, drive in enumerate(self.drives):
            driveProcessQueues[driveIndex] = multiprocessing.Queue()
            driveProcessDictionary[driveIndex] = multiprocessing.Process(target=mainWindow.subSearchFunction, args=(str(drive)+":\\", driveProcessQueues[driveIndex]))
            driveProcessDictionary[driveIndex].daemon = True
            driveProcessDictionary[driveIndex].start()
        for driveIndex, drive in enumerate(self.drives):
            driveProcessDictionary[driveIndex].join()
            driveProcessResults[driveIndex] = mainWindow.consumeQueue(driveProcessQueues[driveIndex])
            with self.resultsLock:
                self.results = self.results + driveProcessResults[driveIndex]
        with self.resultsLock:
            if len(self.results) > 0:
                for resultIndex, result in enumerate(self.results):
                    resultIndex = resultIndex+1
                    result = (str(resultIndex)+": "+str(self.getVersion(result))+": "+result)
                    self.log1.insert(resultIndex, result)
            else:
                self.log1.insert(1, "No results, all good!")
        with self.animLock:
            self.animating = False
        self.animateThread.join()
        with self.animLock:
            self.label1.config(text = "Done, double click a result to open directory")
        if self.hasRun == False:
            with self.resultsLock:
                self.results.insert(0, "blank")
            self.hasRun=True

    def logClickHandler(self, arg):
        selection = self.log1.curselection()[0]
        if self.hasRun == True:
            with self.resultsLock:
                path = os.path.dirname(self.results[selection])
        else:
            path = ""
        if path != 0:
            subprocess.Popen(f'explorer "{path}"')

    def setIcon(self):
        try:
            iconFile = 'icon.ico'
            if getattr(sys, 'frozen', False):
                application_path = sys._MEIPASS
            elif __file__:
                application_path = os.path.dirname(__file__)
            self.iconbitmap(os.path.join(application_path, iconFile))
        except:
            pass

    @staticmethod
    def getDrives():
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1
        return drives

    @staticmethod
    def rgbtohex(r,g,b):
        return f'#{r:02x}{g:02x}{b:02x}'

    @staticmethod
    def getVersion(source):
        def disassembleManifest(manifest):
            expression_manifest = re.compile("Implementation-Version: (.+)\\\\r")
            content = ZipFile.read(manifest)
            content = str(content).split("\\n")
            for line in content:
                result = expression_manifest.findall(line)
                if result:
                    version = str(result)    
            if "version" in locals():
                return version
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
        try:
            nested_expression = re.compile("\.jar$")
            isNested = False
            with zipfile.ZipFile(source, 'r') as ZipFile:
                listFileNames = ZipFile.namelist()
                for file in listFileNames:
                    filename = os.path.basename(file)
                    if nested_expression.findall(filename):
                        version = ">>>NESTED JARFILES! INSPECT MANUALLY<<<"
                        isNested = True
                    elif filename == 'MANIFEST.MF' and isNested == False: 
                        if disassembleManifest(file):
                            version = disassembleManifest(file)
                    elif filename == 'pom.properties' and isNested == False:
                        if disassemblePomfile(file):
                            version = disassemblePomfile(file)
            if "version" in locals():
                return version
            else:
                return "unknown"
        except:
            return "error"

if __name__ == "__main__":
    multiprocessing.freeze_support()
    appWindow = mainWindow()