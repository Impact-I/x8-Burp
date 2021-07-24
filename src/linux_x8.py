__version__ = '0.1.2'
__description__ = """\
Bruteforce via x8 - Hidden parameters discovery suite
"""

# Burp imports
from burp import IBurpExtender, ITab, IContextMenuFactory

from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList
import time
from burp import IScanIssue
import os
import sys
import tarfile
import urllib
import subprocess
import shlex
import threading

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    proxy = 'http://127.0.0.1:8083' # custom proxy example: http://p.webshare.io ?
    threadCsmall = "5"
    threadClarge = "15"

    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        
        if not os.path.isfile("x8"):
            urllib.urlretrieve("https://github.com/Sh1Yo/x8/releases/download/v2.5.0/x8_linux.tar.gz", "x8_linux.tar.gz")
            tar = tarfile.open("x8_linux.tar.gz")
            tar.extractall()
            tar.close()
        
        popen = subprocess.Popen("chmod +x x8",shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        popen.wait()
        popen.stderr.close()
        popen.stdout.close()
        
        self.callbacks = callbacks

        self.helpers = callbacks.getHelpers()

        self.callbacks.setExtensionName("X8")
        self.global_issues = {}

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
 

        return
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when  multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0
    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "X8 Params"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def createMenuItems(self, invocation):
        menuListt = ArrayList()
        self.context = invocation
        itemContext = invocation.getSelectedMessages()
        if itemContext > 0:
            menuList = ArrayList()
            parentMenu = swing.JMenu("Send " +str(len(itemContext))+"x8 Params")
            menuItemSmallWordList = swing.JMenuItem("Small WordList",
                                        actionPerformed=self.handleHttpTrafficSmall)
            menuItemLargeWordList = swing.JMenuItem("Large WordList",
                                        actionPerformed=self.handleHttpTrafficLarge)
            menuItemProxy = swing.JMenuItem("Small via Proxy x8083",
                                        actionPerformed=self.handleHttpTrafficProxy)
            menuItemDebug = swing.JMenuItem("Debug Params",
                                        actionPerformed=self.handleHttpTrafficDebug)            
            parentMenu.add(menuItemSmallWordList)
            parentMenu.add(menuItemLargeWordList)
            parentMenu.add(menuItemProxy)
            parentMenu.add(menuItemDebug)
            menuList.add(parentMenu)
            return menuList
        return None
    
    SELECT_MENU=0
    threadsT = [None]*10000

    def x8(self,event,requestIssue,argsf,origResponseCode):
        print '-----------------------------------------------------------------------------\nBruteforce via x8 - Hidden parameters discovery suite - ' + str(self.helpers.analyzeRequest(requestIssue).getMethod()) + ' - ' + str(self.helpers.analyzeRequest(requestIssue).getUrl())+'\n--------------------------------------------------------------------------------'
        #print argsf
        popen = subprocess.Popen(argsf,shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        output = output + popen.stderr.read()
        print output
        if (" -> " in output or "reflects: " in output) and not ("Code 429" in output):
         issue = CustomScanIssue(requestIssue.getHttpService(),self.helpers.analyzeRequest(requestIssue).getUrl(),[self.callbacks.applyMarkers(requestIssue, None, None)],"X8 Params",output.replace("\n", "<br>"),"Low")
         if("(PROTOCOL_ERROR" in output):
           issue = CustomScanIssue(requestIssue.getHttpService(),self.helpers.analyzeRequest(requestIssue).getUrl(),[self.callbacks.applyMarkers(requestIssue, None, None)],"X8 Params",output.replace("\n", "<br>").replace("[!]","<br><br>Please disable HTTP/2: Project Options -> HTTP -> Enable HTTP/2 -> \"uncheck\"<br><br>[!]"),"Low")
         self.callbacks.addScanIssue(issue)
        if ("Code 429" in output) or ((origResponseCode)!=403 and ("Code 403" in output)):
         issue = CustomScanIssue(requestIssue.getHttpService(),self.helpers.analyzeRequest(requestIssue).getUrl(),[self.callbacks.applyMarkers(requestIssue, None, None)],"X8 Params - WAF Found - Block","WAF Found - Block. Too Many Requests.<br>Please Use Rotate Proxy<br><br>"+output.replace("\n", "<br>"),"Information")
         self.callbacks.addScanIssue(issue)
        popen.stderr.close()
        popen.stdout.close()
 
    def x8ThreadControl(self,event):
         req=0
         while req < len(self.context.getSelectedMessages()):
          origResponseCode = 403
          try:
           origResponseCode = self.helpers.analyzeResponse(self.context.getSelectedMessages()[req].getRequest()).getStatusCode()
          except Exception:
           print ""
          iRequestInfo = self.helpers.analyzeRequest(self.context.getSelectedMessages()[req].getRequest())
          prebody=self.helpers.bytesToString(self.context.getSelectedMessages()[req].getRequest())
          b=''
          b = self.helpers.bytesToString(prebody[iRequestInfo.getBodyOffset():])
          if b !='':
           b='"'+b.replace('\\','\\\\').replace('"','\\"')+'"'
          #print b
          url = '"'+str(self.helpers.analyzeRequest(self.context.getSelectedMessages()[req]).getUrl()).replace('\\','\\\\').replace('"','\\"')+'"'
          X = iRequestInfo.getMethod()
          i=0
          H = ''
          argss=["",""]
          if self.SELECT_MENU == 1:
             if b !='':
              if iRequestInfo.getContentType()!=4:
                 argss = ["./x8","--disable-progress-bar","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
              else:
                 argss = ["./x8","--disable-progress-bar","-t","json","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
             else:
                 argss = ["./x8","--disable-progress-bar","-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
                 
          if self.SELECT_MENU == 2:    
             if b !='':
              if iRequestInfo.getContentType()!=4:
                 argss = ["./x8","--disable-progress-bar","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadClarge,"-w","./large-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
              else:
                 argss = ["./x8","--disable-progress-bar","-t","json","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadClarge,"-w","./large-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
             else:
                 argss = ["./x8","--disable-progress-bar","-X",X,"-u",str(url),"-v","1","-c",self.threadClarge,"-w","./large-wordlist.txt","--replay-proxy","http://127.0.0.1:8080","--http2"]
                
          if self.SELECT_MENU == 3:    
             if b !='':
              if iRequestInfo.getContentType()!=4:
                 argss = ["./x8","--disable-progress-bar","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","-x",self.proxy,"--replay-proxy","http://127.0.0.1:8080","--http2"]
              else:
                 argss = ["./x8","--disable-progress-bar","-t","json","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","-x",self.proxy,"--replay-proxy","http://127.0.0.1:8080","--http2"]
             else:
                 argss = ["./x8","--disable-progress-bar","-X",X,"-u",str(url),"-v","1","-c",self.threadCsmall,"-w","./small-wordlist.txt","-x",self.proxy,"--replay-proxy","http://127.0.0.1:8080","--http2"]
          if self.SELECT_MENU == 4:    
             if b !='':
              if iRequestInfo.getContentType()!=4:
                 argss = ["./x8","--disable-progress-bar","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c","3","--custom-parameters","debug" , "_debug" ,"source" , "admin" , "show" , "bot" , "antibot" , "antirobot" , "staging" , "test" , "testing" , "pre" , "pre-staging" , "daily" , "env" , "uat" , "anticrawl" , "recaptcha" ,"captcha", "signing" , "signature" , "enc" , "encryption" , "automation" , "disabled" , "waf" , "disable" , "security" , "dosinglesignon" , "singlesignon" , "dosso" , "sso","--replay-proxy","http://127.0.0.1:8080","--http2"]
              else:
                 argss = ["./x8","--disable-progress-bar","-t","json","--as-body","-b",b,"-X",X,"-u",str(url),"-v","1","-c","3","--custom-parameters","debug" ,"_debug" , "source" , "admin" , "show" , "bot" , "antibot" , "antirobot" , "staging" , "test" , "testing" , "pre" , "pre-staging" , "daily" , "env" , "uat" , "anticrawl" , "captcha" , "recaptcha","signing" , "signature" , "enc" , "encryption" , "automation" , "disabled" , "waf" , "disable" , "security" , "dosinglesignon" , "singlesignon" , "dosso" , "sso","--replay-proxy","http://127.0.0.1:8080","--http2"]
             else:
                 argss = ["./x8","--disable-progress-bar","-X",X,"-u",str(url),"-v","1","-c","3","--custom-parameters","debug" , "_debug" ,"source" , "admin" , "show" , "bot" , "antibot" , "antirobot" , "staging" , "test" , "testing" , "pre" , "pre-staging" , "daily" , "env" , "uat" , "anticrawl" , "captcha" , "recaptcha","signing" , "signature" , "enc" , "encryption" , "automation" , "disabled" , "waf" , "disable" , "security" , "dosinglesignon" , "singlesignon" , "dosso" , "sso","--replay-proxy","http://127.0.0.1:8080","--http2"]
          
          argss.append('-H')
          for header in iRequestInfo.getHeaders():
              if i>0 and not header.lower().startswith("Content-Length:".lower()) and not header.lower().startswith("Host:".lower()):
               argss.append('"'+header.replace('\\','\\\\').replace('"','\\"')+'"')
              i=i+1
          argsf = ' '.join(argss)
          if '%s' in url:
              argsf=argsf.replace(" --as-body","").replace("-t json ","")
          self.threadsT[req] = threading.Thread(target=self.x8, args=(None,self.context.getSelectedMessages()[req],argsf,origResponseCode,))
          self.threadsT[req].start()
          #self.thread1.join()
          req=req+1


    def writeRequestToTextBox(self):
        self.threadControl = threading.Thread(target=self.x8ThreadControl, args=(None,))
        self.threadControl.start()


    def handleHttpTrafficSmall(self, event):
        self.SELECT_MENU=1
        
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()

    def handleHttpTrafficLarge(self, event):
        self.SELECT_MENU=2
        
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()

    def handleHttpTrafficProxy(self, event):
        self.SELECT_MENU=3
        
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()
            
    def handleHttpTrafficDebug(self, event):
        self.SELECT_MENU=4
        
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()

try:
    FixBurpExceptions()
except:
    pass

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
