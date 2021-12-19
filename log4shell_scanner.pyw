# Zdenek Loucka, SMO DT IT / 2021
# Log4Shell vulnerability scanner
# Version 2.2
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
        self.drives = self.getdrives()
        self.spacer1 = tkinter.Label(background=self.background)
        self.spacer2 = tkinter.Label(background=self.background)
        self.spacer3 = tkinter.Label(background=self.background)
        self.button1 = tkinter.Button(text="Log4Shell jar scanner", background=self.background, foreground=self.foreground, width=self.width, activebackground=self.activebackground, activeforeground=self.foreground,command=self.findJars)
        self.log1 = tkinter.Listbox(width=int(7.5*self.width), height=int(1.25*self.width), background=self.activebackground, foreground=self.foreground, selectbackground=self.selectbackground,activestyle="none")
        self.label1 = tkinter.Label(text=self.statustext, background=self.background, foreground=self.foreground)
        self.label2 = tkinter.Label(text=self.disclaimer, background=self.background, foreground=self.foreground)
        self.label3 = tkinter.Label(text=self.disclaimer2, background=self.background, foreground=self.foreground)
        self.spacer1.pack()
        self.button1.pack()
        self.spacer2.pack()
        self.log1.pack()
        self.spacer3.pack()
        self.label1.pack()
        self.label2.pack()
        self.label3.pack()
        self.log1.bind('<Double-Button>', self.logClickHandler)
        self.log1.insert(1, "Welcome, detected system drives: " + str(self.drives))
        self.log1.focus_set()
        self.lift()
        self.lock = threading.RLock()
        self.results=[]
        self.resultsPath=["blank",]
        self.animating = True
        self.mainloop()

    def getdrives(self):
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1
        return drives

    def animateSearch(self):
        animList = ["Searching",". Searching .",". . Searching . .",". . . Searching . . ."]
        animCount=0
        while True:
            self.label1.config(text = animList[animCount])
            time.sleep(1)
            if animCount < 3:
                animCount=animCount+1
            else:
                animCount=0
            if self.animating == False:
                break

    def subSearchFunction(self, drive):
        expression = re.compile("log4j-.+\.jar$")
        for root,dir,files in os.walk(str(drive)+":\\"):
            for file in files:
                result = expression.search(file)
                if result:
                    with self.lock:
                        self.results.append(str(root)+"\\"+str(file))
                        self.resultsPath.append((str(root)+"\\"))

    def searchfunction(self):
        self.animateThread = threading.Thread(target=self.animateSearch)
        self.animateThread.start()
        driveCounter=0
        driveThreadDict={}
        for drive in self.drives:
            driveThreadDict[driveCounter] = threading.Thread(target=self.subSearchFunction, args=(drive,))
            driveThreadDict[driveCounter].start()
            driveCounter=driveCounter+1
        driveCounter=0
        for drive in self.drives:
            driveThreadDict[driveCounter].join()
            driveCounter=driveCounter+1
        count=1
        if len(self.results) > 0:
            for i in self.results:
                i = (str(count)+": "+str(self.getVersion(i))+": "+i)
                count=count+1
                self.log1.insert(count, i)
        else:
            self.log1.insert(1, "No results, all good!")
        self.animating = False
        self.animateThread.join()
        self.label1.config(text = "Done, double click a result to open directory")

    def findJars(self):
        if threading.active_count() < 2:
            self.searchThread = threading.Thread(target=self.searchfunction)
            self.searchThread.start()

    def logClickHandler(self, arg):
        selection = self.log1.curselection()[0]
        path = self.resultsPath[selection]
        if path != 0:
            subprocess.Popen(f'explorer "{path}"')

    def setIcon(self):
        iconFile = 'icon.ico'
        if getattr(sys, 'frozen', False):
            application_path = sys._MEIPASS
        elif __file__:
            application_path = os.path.dirname(__file__)
        self.iconbitmap(os.path.join(application_path, iconFile))

    def rgbtohex(self, r,g,b):
        return f'#{r:02x}{g:02x}{b:02x}'
        
    def getVersion(self, source):
        try:
            version = "unknown"
            version_expression_maven = re.compile("version=(.+)")
            version_expression_manifest = re.compile("Implementation-Version: (.+)\\\\r")
            with zipfile.ZipFile(source, 'r') as ZipFile:
                listFileNames = ZipFile.namelist()
                for file in listFileNames:
                    filename = os.path.basename(file)
                    if filename == 'MANIFEST.MF': 
                        member = ZipFile.read(file)
                        member = str(member).split("\\n")
                        for line in member:
                            result = version_expression_manifest.findall(line)
                            if result:
                                version = str(result)
                        if version != "unknown":
                            return version
                    elif filename == 'pom.properties': 
                        member = ZipFile.read(file)
                        member = str(member).split("\\n")
                        for line in member:
                            result = version_expression_maven.findall(line)
                            if result:
                                version = str(result)
                        return version
        except Exception as exc:
            message="error while extracting: " +  str(source)
            print(message)
            print(exc)
            self.animating = False
            self.animateThread.join()
            self.label1.config(text = message)



if __name__ == "__main__":
    appWindow = mainWindow()