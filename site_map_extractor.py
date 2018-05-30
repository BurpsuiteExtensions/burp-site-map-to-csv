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
import java.lang as lang
import os.path
import csv

class BurpExtender(IBurpExtender, ITab):
    #
    # Implement IBurpExtender
    #

    tableData = []
    colNames = ()

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
        self.tab = swing.JPanel()
        self.uiLabel = swing.JLabel('Site Map to CSV Options')
        self.uiLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiLabel.setForeground(Color(235,136,0))

        self.uiScopeOnly = swing.JRadioButton('In-scope only', True)
        self.uiScopeAll = swing.JRadioButton('Everything', False)
        self.uiScopeButtonGroup = swing.ButtonGroup()
        self.uiScopeButtonGroup.add(self.uiScopeOnly)
        self.uiScopeButtonGroup.add(self.uiScopeAll)

        self.uipaneA = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.uipaneA.setMaximumSize(Dimension(900,125))
        self.uipaneA.setDividerSize(2)
        self.uipaneB = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.uipaneB.setDividerSize(2)
        self.uipaneA.setRightComponent(self.uipaneB)
        self.uipaneA.setBorder(BorderFactory.createLineBorder(Color.black))
        
        # UI for response code filtering
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
        self.uiCodesRun = swing.JButton('Run',actionPerformed=self.exportCodes)
        self.uiCodesSave = swing.JButton('Save Log to CSV File',actionPerformed=self.savetoCsvFile)
        self.uiCodesClear = swing.JButton('Clear Log')        
        self.uiCodesButtonPanel = swing.JPanel()
        self.uiCodesButtonPanel.add(self.uiCodesRun)
        self.uiCodesButtonPanel.add(self.uiCodesSave)
        self.uiCodesButtonPanel.add(self.uiCodesClear)
        self.uiRcodePanel.add(self.uiRcode1xx)
        self.uiRcodePanel.add(self.uiRcode2xx)
        self.uiRcodePanel.add(self.uiRcode3xx)
        self.uiRcodePanel.add(self.uiRcode4xx)
        self.uiRcodePanel.add(self.uiRcode5xx)
        self.uiCodesPanel.add(self.uiCodesLabel,BorderLayout.NORTH)
        self.uiCodesPanel.add(self.uiRcodePanel,BorderLayout.WEST)
        self.uiCodesPanel.add(self.uiCodesButtonPanel,BorderLayout.SOUTH)
        self.uipaneA.setLeftComponent(self.uiCodesPanel)

        # Option 3 UI for Export Sitemap
        self.uiExportPanel = swing.JPanel()
        self.uiExportPanel.setPreferredSize(Dimension(200, 75))
        self.uiExportPanel.setBorder(EmptyBorder(10,10,10,10))
        self.uiExportPanel.setLayout(BorderLayout())
        self.uiExportLabel = swing.JLabel('Export Site Map to File')
        self.uiExportLabel.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiMustHaveResponse = swing.JRadioButton('Must have a response     ', True)
        self.uiAllRequests = swing.JRadioButton('All (overrides response code filters)     ', False)
        self.uiResponseButtonGroup = swing.ButtonGroup()
        self.uiResponseButtonGroup.add(self.uiMustHaveResponse)
        self.uiResponseButtonGroup.add(self.uiAllRequests)
        self.uiExportRun = swing.JButton('Run')
        self.uiExportClear = swing.JButton('Clear Log')
        self.uiExportButtonPanel = swing.JPanel()
        self.uiExportButtonPanel.add(self.uiExportRun)
        self.uiExportButtonPanel.add(self.uiExportClear)        
        self.uiExportPanel.add(self.uiExportLabel,BorderLayout.NORTH)
        self.uiExportPanel.add(self.uiMustHaveResponse,BorderLayout.WEST)
        self.uiExportPanel.add(self.uiAllRequests,BorderLayout.CENTER)
        self.uiExportPanel.add(self.uiExportButtonPanel,BorderLayout.SOUTH)
        self.uipaneB.setLeftComponent(self.uiExportPanel)

        # UI Common Elements
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

    def exportCodes(self, e):
        self.blankLog()
        self.siteMapData = self._callbacks.getSiteMap(None)
        # response codes to be included
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

        self.colNames = ('Request','Referer','Response Code','Redirects To')
        self.tableData = []

        for i in self.siteMapData:
            self.requestInfo = self._helpers.analyzeRequest(i)
            self.url = self.requestInfo.getUrl()
            if self.scopeOnly() and not(self._callbacks.isInScope(self.url)):
                continue
            try:
                self.urlDecode = self._helpers.urlDecode(str(self.url))
            except:
                print('Error parsing URL')
                continue
            self.response = i.getResponse()
            if self.response == None:
                continue
            # Get referer if there is one
            self.requestHeaders = self.requestInfo.getHeaders()
            self.referer = ''
            for j in self.requestHeaders:
                if j.startswith('Referer:'):
                    self.fullReferer = j.split(' ')[1]
                    # drop the querystring parameter
                    self.referer = self.fullReferer.split('?')[0] 
            # Get response code
            self.responseInfo = self._helpers.analyzeResponse(self.response)
            self.responseCode = self.responseInfo.getStatusCode()
            self.firstDigit = str(self.responseCode)[0]
            if self.firstDigit not in self.rcodes:
                continue
            if self.firstDigit in ['1','2','4','5']:     # Return codes 1xx, 2xx, 4xx, 5xx
                try:
                    self.tableData.append([self.stripURLPort(self.urlDecode), str(self.referer), str(self.responseCode)])
                except:
                    print('Error writing Referer to table')
                    continue
            elif self.firstDigit == '3':   # Return code 3xx Redirection
                self.requestHeaders = self.requestInfo.getHeaders()
                self.responseHeaders = self.responseInfo.getHeaders()
                for j in self.responseHeaders:
                    if j.startswith('Location:'):
                        self.location = j.split(' ')[1]
                try:
                    self.tableData.append([self.stripURLPort(self.urlDecode), str(self.referer), str(self.responseCode), self.location])
                except:
                    print('Error writing Referer to table')
                    continue

        dataModel = DefaultTableModel(self.tableData, self.colNames)
        self.uiLogTable = swing.JTable(dataModel)
        self.uiLogPane.setViewportView(self.uiLogTable)

    def savetoCsvFile(self,e):
        if self.tableData == []:
            JOptionPane.showMessageDialog(self.tab,'The log contains no data.')
            return
        f, ok = self.openFile('csv', 'CSV files', 'wb')
        if ok:
            self.writer = csv.writer(f)
            self.writer.writerow(list(self.colNames))
            for i in self.tableData:
                self.writer.writerow(i)
            f.close()
            JOptionPane.showMessageDialog(self.tab,'The csv file was successfully written.')

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
