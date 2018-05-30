"""
Site Map to CSV - Burp Suite plugin

(Python 2.7 code meant for consumption by Burp Suite Jython)
"""

from burp import IBurpExtender
from burp import ITab
from burp import IHttpRequestResponse
from burp import IResponseInfo
from javax import swing
from javax.swing import JFileChooser
from javax.swing import BorderFactory
from javax.swing import JOptionPane
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout
from javax.swing.border import EmptyBorder
from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from java.awt import Color
from java.awt import Font
from java.awt import Dimension
from java.awt import GridLayout
from java.net import URL
import java.lang as lang
import os.path
import csv
import datetime

_hexdig = '0123456789ABCDEFabcdef'
_hextochr = dict((a + b, chr(int(a + b, 16)))
                 for a in _hexdig for b in _hexdig)

def unquote(s):
    """
    This is right from Python 2.7, credit to that.
    Can't import in Jython because urllib import error.

    unquote('abc%20def') -> 'abc def'
    """
    res = s.split('%')
    # fastpath
    if len(res) == 1:
        return s
    s = res[0]
    for item in res[1:]:
        try:
            s += _hextochr[item[:2]] + item[2:]
        except KeyError:
            s += '%' + item
        except UnicodeDecodeError:
            s += unichr(int(item[:2], 16)) + item[2:]
    return s

class BurpExtender(IBurpExtender, ITab):
    """
    Implement IBurpExtender
    """

    def registerExtenderCallbacks(self, callbacks):
        print('Loading Site Map to CSV ...')
        # Set up extension environment
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('Site Map to CSV')
        self.drawUI()
        self._callbacks.addSuiteTab(self)
        print('\nSite Map to CSV extension loaded successfully!')

    def drawUI(self):
        # Make a whole Burp Suite tab just for this plugin
        self.tab = swing.JPanel()
        # Draw title area
        self.uiLabel = swing.JLabel('Site Map to CSV Options')
        self.uiLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiLabel.setForeground(Color(235,136,0))
        # UI for high-level options
        self.uiScopeOnly = swing.JRadioButton('In-scope only', True)
        self.uiScopeAll = swing.JRadioButton('All (disregard scope)', False)
        self.uiScopeButtonGroup = swing.ButtonGroup()
        self.uiScopeButtonGroup.add(self.uiScopeOnly)
        self.uiScopeButtonGroup.add(self.uiScopeAll)
        # Draw areas in the tab to keep different UI commands separate
        self.uipaneA = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.uipaneA.setMaximumSize(Dimension(900,125))
        self.uipaneA.setDividerSize(2)
        self.uipaneB = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.uipaneB.setDividerSize(2)
        self.uipaneA.setRightComponent(self.uipaneB)
        self.uipaneA.setBorder(BorderFactory.createLineBorder(Color.black))
        # Fill in UI area for response code filters
        self.uiCodesPanel = swing.JPanel()
        self.uiCodesPanel.setPreferredSize(Dimension(200, 75))
        self.uiCodesPanel.setBorder(EmptyBorder(10,10,10,10))
        self.uiCodesPanel.setLayout(BorderLayout())
        self.uiCodesLabel = swing.JLabel('Response code filters')
        self.uiCodesLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiRcodePanel = swing.JPanel()
        self.uiRcodePanel.setLayout(GridLayout(1,1))
        self.uiRcode1xx = swing.JCheckBox('1XX  ', False)
        self.uiRcode2xx = swing.JCheckBox('2XX  ', True)
        self.uiRcode3xx = swing.JCheckBox('3XX  ', True)
        self.uiRcode4xx = swing.JCheckBox('4XX  ', True)
        self.uiRcode5xx = swing.JCheckBox('5XX     ', True)
        self.uiRcodePanel.add(self.uiRcode1xx)
        self.uiRcodePanel.add(self.uiRcode2xx)
        self.uiRcodePanel.add(self.uiRcode3xx)
        self.uiRcodePanel.add(self.uiRcode4xx)
        self.uiRcodePanel.add(self.uiRcode5xx)
        self.uiCodesPanel.add(self.uiCodesLabel,BorderLayout.NORTH)
        self.uiCodesPanel.add(self.uiRcodePanel,BorderLayout.WEST)
        self.uipaneA.setLeftComponent(self.uiCodesPanel)
        # Fill in UI area for initiating export to CSV
        self.uiExportPanel = swing.JPanel()
        self.uiExportPanel.setPreferredSize(Dimension(200, 75))
        self.uiExportPanel.setBorder(EmptyBorder(10,10,10,10))
        self.uiExportPanel.setLayout(BorderLayout())
        self.uiExportLabel = swing.JLabel('Export')
        self.uiExportLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiMustHaveResponse = swing.JRadioButton('Must have a response     ', True)
        self.uiAllRequests = swing.JRadioButton('All (overrides response code filters)     ', False)
        self.uiResponseButtonGroup = swing.ButtonGroup()
        self.uiResponseButtonGroup.add(self.uiMustHaveResponse)
        self.uiResponseButtonGroup.add(self.uiAllRequests)
        self.uiExportRun = swing.JButton('Export',actionPerformed=self.exportAndSaveCsv)
        self.uiExportButtonPanel = swing.JPanel()
        self.uiExportButtonPanel.add(self.uiExportRun)    
        self.uiExportPanel.add(self.uiExportLabel,BorderLayout.NORTH)
        self.uiExportPanel.add(self.uiMustHaveResponse,BorderLayout.WEST)
        self.uiExportPanel.add(self.uiAllRequests,BorderLayout.CENTER)
        self.uiExportPanel.add(self.uiExportButtonPanel,BorderLayout.SOUTH)
        self.uipaneB.setLeftComponent(self.uiExportPanel)
        # Common UI stuff
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)
        # Thank you to Smeege (https://github.com/SmeegeSec/Burp-Importer/) for helping me figure out how this works.
        # He in turn gave credit to Antonio Sanchez (https://github.com/Dionach/HeadersAnalyzer/)
        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.uiLabel)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(10,10,10)
                        .addComponent(self.uiScopeOnly)
                        .addGap(10,10,10)
                        .addComponent(self.uiScopeAll))
                    .addGap(15,15,15)
                    .addComponent(self.uipaneA))
                .addContainerGap(26, lang.Short.MAX_VALUE)))
        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15,15,15)
                .addComponent(self.uiLabel)
                .addGap(15,15,15)
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.uiScopeOnly)
                    .addComponent(self.uiScopeAll))
                .addGap(20,20,20)
                .addComponent(self.uipaneA)
                .addGap(20,20,20)
                .addGap(5,5,5)
                .addGap(20,20,20)))

    def getTabCaption(self):
        return 'Site Map to CSV'

    def getUiComponent(self):
        return self.tab

    def scopeOnly(self):
        if self.uiScopeOnly.isSelected():
            return True
        else:
            return False

    def exportAndSaveCsv(self, e):
        f, ok = self.openFile('csv', 'CSV files', 'wb')
        if ok:
            self.colNames = ('Request','Referer','Response Code','Redirects To')
            self.writer = csv.writer(f)
            self.writer.writerow(list(self.colNames))
            self.siteMapData = self._callbacks.getSiteMap(None)
            # Figure out response codes to include
            self.rcodes = []
            if self.uiRcode1xx.isSelected():
                self.rcodes += '1'
            if self.uiRcode2xx.isSelected():
                self.rcodes += '2'
            if self.uiRcode3xx.isSelected():
                self.rcodes += '3'
            if self.uiRcode4xx.isSelected():
                self.rcodes += '4'
            if self.uiRcode5xx.isSelected():
                self.rcodes += '5'
            for i in self.siteMapData:
                self.requestInfo = self._helpers.analyzeRequest(i)
                self.url = self.requestInfo.getUrl()
                if self.scopeOnly() and not(self._callbacks.isInScope(self.url)):
                    continue
                self.urlDecode = self.decodeUrl(self.url)
                self.response = i.getResponse()
                if self.response == None:
                    continue
                # Get Referer if there is one
                self.requestHeaders = self.requestInfo.getHeaders()
                self.referer = ''
                for j in self.requestHeaders:
                    if j.startswith('Referer:'):
                        self.fullReferer = j.split(' ')[1]
                        # Drop any query parameters
                        self.referer = self.fullReferer.split('?')[0] 
                # Get response code
                self.responseInfo = self._helpers.analyzeResponse(self.response)
                self.responseCode = self.responseInfo.getStatusCode()
                self.firstDigit = str(self.responseCode)[0]
                if self.firstDigit not in self.rcodes:
                    continue
                if self.firstDigit in ['1','2','4','5']:  # Return codes 1xx, 2xx, 4xx, 5xx
                    try:
                        self.writer.writerow([self.stripURLPort(self.urlDecode), self.decodeUrl(self.referer), str(self.responseCode)])
                    except:
                        self.printInfo('Error writing CSV row or parsing Referer to string')
                        continue
                elif self.firstDigit == '3':  # Return code 3xx Redirection
                    self.responseHeaders = self.responseInfo.getHeaders()
                    for j in self.responseHeaders:
                        if j.startswith('Location:'):
                            self.location = j.split(' ')[1]
                    self.writer.writerow([self.stripURLPort(self.urlDecode), self.decodeUrl(self.referer), str(self.responseCode), self.location])
            f.close()
            JOptionPane.showMessageDialog(self.tab,'Full export to CSV file complete.')

    def openFile(self, fileext, filedesc, fileparm):
        myFilePath = ''
        chooseFile = JFileChooser()
        myFilter = FileNameExtensionFilter(filedesc,[fileext])
        chooseFile.setFileFilter(myFilter)
        ret = chooseFile.showOpenDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            myFilePath = str(file.getCanonicalPath()).lower()
            if not myFilePath.endswith(fileext):
                myFilePath += '.' + fileext
            okWrite = JOptionPane.YES_OPTION
            if os.path.isfile(myFilePath):
                okWrite = JOptionPane.showConfirmDialog(self.tab,'File already exists. Ok to over-write?','',JOptionPane.YES_NO_OPTION)
                if okWrite == JOptionPane.NO_OPTION:
                    return
            j = True
            while j:
                try:
                    f = open(myFilePath,mode=fileparm)
                    j = False
                except IOError:
                    okWrite = JOptionPane.showConfirmDialog(self.tab,'File cannot be opened. Correct and retry?','',JOptionPane.YES_NO_OPTION)
                    if okWrite == JOptionPane.NO_OPTION:
                        return None, False
            return f, True

    def stripCRLF(self, link):
        link = link.rstrip('\r')
        link = link.rstrip('\n')
        return link

    def lstripWS(self, link):
        return link.lstrip()

    def stripURLPort(self, url):
        # Thanks to shpendk for this code(https://github.com/PortSwigger/site-map-fetcher/)
        return url.split(':')[0] + ':' + url.split(':')[1] + '/' + url.split(':')[2].split('/',1)[1]

    def printInfo(self,string):
        print(str(datetime.datetime.now()) + ' ' + string)

    def decodeUrl(self,u):
        # Yes it's not pretty but it seems to work.
        return self._helpers.urlDecode(unquote(unicode(u,'UTF-8',errors='replace')).decode('UTF-8','replace'))
