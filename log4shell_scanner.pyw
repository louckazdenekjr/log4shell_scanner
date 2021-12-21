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
from ctypes import windll
from sys import platform

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
        self.resultsPath=["blank",]
        self.hasRun=False
        self.mainloop()

    def getDrives(self):
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1
        return drives

    def animateSearch(self):
        animList = ["Searching",". Searching .",". . Searching . .",". . . Searching . . ."]
        animIndex=0
        while True:
            with self.animLock:
                self.label1.config(text = animList[animIndex])
            time.sleep(1)
            if animIndex < 3:
                animIndex=animIndex+1
            else:
                animIndex=0
            with self.animLock:
                if self.animating == False:
                    break

    def subSearchFunction(self, drive):
        expression = re.compile("log4j-.+\.jar$")
        for root,dir,files in os.walk(str(drive)+":\\"):
            for file in files:
                result = expression.search(file)
                if result:
                    with self.resultsLock:
                        self.results.append(str(root)+"\\"+str(file))
                        self.resultsPath.append((str(root)+"\\"))

    def searchfunction(self):
        with self.animLock:
            self.animating = True
        self.animateThread = threading.Thread(target=self.animateSearch)
        self.animateThread.start()
        driveIndex=0
        driveThreadDict={}
        for drive in self.drives:
            driveThreadDict[driveIndex] = threading.Thread(target=self.subSearchFunction, args=(drive,))
            driveThreadDict[driveIndex].start()
            driveIndex=driveIndex+1
        driveIndex=0
        for drive in self.drives:
            driveThreadDict[driveIndex].join()
            driveIndex=driveIndex+1
        count=1
        if len(self.results) > 0:
            for i in self.results:
                i = (str(count)+": "+str(self.getVersion(i))+": "+i)
                count=count+1
                self.log1.insert(count, i)
        else:
            self.log1.insert(1, "No results, all good!")
        with self.animLock:
            self.animating = False
        self.animateThread.join()
        with self.animLock:
            self.label1.config(text = "Done, double click a result to open directory")
        self.hasRun=True

    def findJars(self):
        if threading.active_count() < 2:
            if self.hasRun:
                self.log1.delete(0, tkinter.END)
                self.results=[]
                self.resultsPath=[]
                self.searchThread.join()
            self.searchThread = threading.Thread(target=self.searchfunction)                
            self.searchThread.daemon = True                
            self.searchThread.start()

    def logClickHandler(self, arg):
        selection = self.log1.curselection()[0]
        path = self.resultsPath[selection]
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
            with zipfile.ZipFile(source, 'r') as ZipFile:
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
        except Exception as exc:
            print(exc)
            return "error"

if __name__ == "__main__":
    appWindow = mainWindow()