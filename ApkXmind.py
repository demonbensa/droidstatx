import os
import time
from datetime import datetime

from Configuration import Configuration
import xmind
from xmind.core.topic import TopicElement
from xmind.core.markerref import MarkerId

class ApkXmind:

    app = ""
    workbook = ""
    sheet = ""
    configuration = Configuration()

    def __init__(self, app):
        versionAlreadyExists = False
        self.app = app
        cwd = os.path.dirname(os.path.realpath(__file__)) + "/output_xmind/"
        print("[-]Generating Xmind")
        # load an existing file or create a new workbook if nothing is found
        self.workbook = xmind.load(cwd + app.getPackageName() + ".xmind")

        if len(self.workbook.getSheets()) == 1:
            if self.workbook.getPrimarySheet().getTitle() is None:
                self.sheet = self.workbook.getPrimarySheet()
                self.sheet.setTitle(app.getVersionCode())
            else:
                self.sheet = self.workbook.createSheet()
                self.sheet.setTitle(app.getVersionCode())
        else:
            self.sheet = self.workbook.createSheet()
            self.sheet.setTitle(app.getVersionCode())

        rootTopic = self.sheet.getRootTopic()
        rootTopic.setTitle(app.getPackageName())
        rootTopic.setStructureClass(self.configuration.geXmindTopicStructure())
        self.createTopics(rootTopic)
        self.save()

    def save(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        filename = self.app.getPackageName() + ".xmind"
        xmind.save(self.workbook, cwd + "/output_xmind/" + filename)
        print("Generated output_xmind/" + filename)

    def getRootTopic(self):
        return self.sheet.getRootTopic()

    def createSubTopic(self, topic, title):
        st = topic.addSubTopic()
        st.setTitle(title)
        return st

    def createSubTopics(self, topic, titles):
        for title in titles:
            st = topic.addSubTopic()
            st.setTitle(title)
        return topic

    def createTopics(self, root):
        informationGatheringTopic = root.addSubTopic()
        informationGatheringTopic.setTitle("Information Gathering")

        methodologyTopic = root.addSubTopic()
        methodologyTopic.setTitle("Methodology")

        # Properties Topic

        propertiesTopic = informationGatheringTopic.addSubTopic()
        propertiesTopic.setTitle("Properties")

        st = propertiesTopic.addSubTopic()
        st.setTitle("Version Name")
        st.addSubTopic().setTitle(self.app.getVersionName())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Version Code")
        st.addSubTopic().setTitle(self.app.getVersionCode())

        st = propertiesTopic.addSubTopic()
        st.setTitle("SHA 256")
        st.addSubTopic().setTitle(self.app.getSHA256())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Minimum SDK Version")
        st.addSubTopic().setTitle(self.app.getMinSDKVersion() + " ( " + self.app.getCodeName(self.app.getMinSDKVersion()) + ")")

        st = propertiesTopic.addSubTopic()
        st.setTitle("Target SDK Version")
        if self.app.getTargetSDKVersion() is None:
            st.addSubTopic().setTitle("Not defined")
        else:
            st.addSubTopic().setTitle(self.app.getTargetSDKVersion() + " ( " + self.app.getCodeName(self.app.getTargetSDKVersion()) + ")")

        st = propertiesTopic.addSubTopic()
        st.setTitle("Xamarin")
        sst = st.addSubTopic()
        sst.setTitle(self.app.isXamarin())

        if self.app.isXamarin() == "Yes":
            sst.addSubTopic().setTitle("Bundled?").addSubTopic().setTitle(self.app.isXamarinBundled())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Cordova")
        sst = st.addSubTopic()
        sst.setTitle(self.app.isCordova())

        if self.app.isCordova() == "Yes" and len(self.app.getCordovaPlugins()) > 0:
            plugins = sst.addSubTopic().setTitle("Plugins")
            self.createSubTopics(plugins, self.app.getCordovaPlugins())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Outsystems")
        st.addSubTopic().setTitle(self.app.isOutsystems())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Backup Enabled")
        st.addSubTopic().setTitle(self.app.isBackupEnabled())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Multiple DEX Classes")
        st.addSubTopic().setTitle(self.app.isMultiDex())

        st = propertiesTopic.addSubTopic()
        st.setTitle("Secret Codes")
        if len(self.app.getSecretCodes()) > 0:
            self.createSubTopics(st, self.app.getSecretCodes())
        else:
            st.addSubTopic().setTitle("No")

        # Permissions Topic

        permissionsTopic = informationGatheringTopic.addSubTopic()
        permissionsTopic.setTitle("Permissions")

        self.createSubTopics(permissionsTopic, self.app.getPermissions())

        if len(self.app.getPermissions()) > self.configuration.getXmindTopicFoldAt():
            permissionsTopic.setFolded()

        # Exported Components Topic

        exportedTopic = informationGatheringTopic.addSubTopic()
        exportedTopic.setTitle("Exported Components")

        subtopics = ["Activities", "Broadcast Receivers", "Content Providers", "Services"]
        self.createSubTopics(exportedTopic, subtopics)

        activitiesTopic = exportedTopic.getSubTopicByIndex(0)
        for activity in self.app.getExportedActivities():
            topicElement = activitiesTopic.addSubTopic()
            topicElement.setTitle(activity)
            if self.app.getComponentPermission(activity) != "":
                st = topicElement.addSubTopic()
                st.setTitle("Permission: " + self.app.getComponentPermission(activity))

            try:
                filters = self.app.getIntentFiltersList()[activity]
                i = 1
                for filter in filters:
                    st = topicElement.addSubTopic()
                    sst.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = st.addSubTopic().setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())

                    category = st.addSubTopic().setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())

                    data = st.addSubTopic().setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())

                    st.setFolded()
            except:
                pass

        if len(self.app.getExportedActivities()) > self.configuration.getXmindTopicFoldAt():
            activitiesTopic.setFolded()

        receiversTopic = exportedTopic.getSubTopicByIndex(1)
        for receiver in self.app.getExportedReceivers():
            topicElement = receiversTopic.addSubTopic()
            topicElement.setTitle(receiver)
            if self.app.getComponentPermission(receiver) != "":
                st = topicElement.addSubTopic()
                st.setTitle("Permission: " + self.app.getComponentPermission(receiver))

            try:
                filters = self.app.getIntentFiltersList()[receiver]
                i = 1
                for filter in filters:
                    st = topicElement.addSubTopic()
                    sst.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = st.addSubTopic().setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())

                    category = st.addSubTopic().setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())

                    data = st.addSubTopic().setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())

                    st.setFolded()
            except:
                pass

        if len(self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations()) > 0:
            st = receiversTopic.addSubTopic()
            st.setTitle("Dynamically Registered")
            self.createSubTopics(st, self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations())

            if len(self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations()) > self.configuration.getXmindTopicFoldAt():
                st.setFolded()

        if len(self.app.getExportedReceivers()) > self.configuration.getXmindTopicFoldAt():
            receiversTopic.setFolded()

        providersTopic = exportedTopic.getSubTopicByIndex(2)
        for provider in self.app.getExportedProviders():
            topicElement = providersTopic.addSubTopic()
            topicElement.setTitle(provider)
            if self.app.getComponentPermission(provider) != "":
                st = topicElement.addSubTopic()
                st.setTitle("Permission: " + self.app.getComponentPermission(provider))

            try:
                filters = self.app.getIntentFiltersList()[provider]
                i = 1
                for filter in filters:
                    st = topicElement.addSubTopic()
                    sst.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = st.addSubTopic().setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())

                    category = st.addSubTopic().setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())

                    data = st.addSubTopic().setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())

                    st.setFolded()
            except:
                pass

        if len(self.app.getExportedProviders()) > self.configuration.getXmindTopicFoldAt():
            providersTopic.setFolded()

        servicesTopic = exportedTopic.getSubTopicByIndex(3)
        for service in self.app.getExportedServices():
            topicElement = servicesTopic.addSubTopic()
            topicElement.setTitle(service)
            if self.app.getComponentPermission(service) != "":
                st = topicElement.addSubTopic()
                st.setTitle("Permission: " + self.app.getComponentPermission(service))

            try:
                filters = self.app.getIntentFiltersList()[service]
                i = 1
                for filter in filters:
                    st = topicElement.addSubTopic()
                    sst.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = st.addSubTopic().setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())

                    category = st.addSubTopic().setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())

                    data = st.addSubTopic().setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())

                    st.setFolded()
            except:
                pass

        if len(self.app.getExportedServices()) > self.configuration.getXmindTopicFoldAt():
            servicesTopic.setFolded()

        # Files Topic

        topicElement = informationGatheringTopic.addSubTopic()
        topicElement.setTitle("Files")
        topicElement.setPlainNotes("Excluded files/locations: " + self.configuration.getFileExclusions())
        fileTypes = ["Assets", "Libs", "Raw Resources", "Dex Classes", "Cordova Files", "Xamarin Assemblies", "Other"]
        self.createSubTopics(topicElement, fileTypes)

        self.createSubTopics(topicElement.getSubTopicByIndex(0), self.app.getAssets())
        if len(self.app.getAssets()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(0).setFolded()

        self.createSubTopics(topicElement.getSubTopicByIndex(1), self.app.getLibs())
        if len(self.app.getLibs()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(1).setFolded()

        self.createSubTopics(topicElement.getSubTopicByIndex(2), self.app.getRawResources())
        if len(self.app.getRawResources()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(2).setFolded()

        self.createSubTopics(topicElement.getSubTopicByIndex(3), self.app.getDexFiles())

        self.createSubTopics(topicElement.getSubTopicByIndex(4), self.app.getCordovaFiles())
        if len(self.app.getCordovaFiles()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(4).setFolded()

        self.createSubTopics(topicElement.getSubTopicByIndex(5), self.app.getXamarinAssemblies())
        if len(self.app.getXamarinAssemblies()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(5).setFolded()

        if len(self.app.getOtherFiles()) <= self.app.configuration.getMaxSubTopics():
            self.createSubTopics(topicElement.getSubTopicByIndex(6), self.app.getOtherFiles())
            if len(self.app.getOtherFiles()) > self.configuration.getXmindTopicFoldAt():
                topicElement.getSubTopicByIndex(6).setFolded()
        else:
            tooManySubTopicsElement = topicElement.getSubTopicByIndex(6).addSubTopic()
            tooManySubTopicsElement.setTitle("Too many files. Hit configured threshold.")

        # Object Usage Topic

        topicElement = informationGatheringTopic.addSubTopic()
        topicElement.setTitle("Object Usage")
        objectsSubTopics = ["WebViews loadUrl", "Cryptographic Functions", "Custom"]
        self.createSubTopics(topicElement, objectsSubTopics)

        self.createSubTopics(topicElement.getSubTopicByIndex(0), self.app.smaliChecks.getWebViewsLoadUrlUsageLocations())
        if len(self.app.smaliChecks.getWebViewsLoadUrlUsageLocations()) > self.configuration.getXmindTopicFoldAt():
            topicElement.getSubTopicByIndex(0).setFolded()

        encryptionSubTopic = topicElement.getSubTopicByIndex(1).addSubTopic()
        encryptionSubTopic.setTitle("Encryption")
        self.createSubTopics(encryptionSubTopic, self.app.smaliChecks.getEncryptionFunctionsLocations())
        if (len(self.app.smaliChecks.getEncryptionFunctionsLocations()) > self.configuration.getXmindTopicFoldAt()):
            encryptionSubTopic.setFolded()

        decryptionSubtopic = topicElement.getSubTopicByIndex(1).addSubTopic()
        decryptionSubtopic.setTitle("Decryption")
        self.createSubTopics(decryptionSubtopic, self.app.smaliChecks.getDecryptionFunctionsLocations())
        if (len(self.app.smaliChecks.getDecryptionFunctionsLocations()) > self.configuration.getXmindTopicFoldAt()):
            decryptionSubtopic.setFolded()

        undeterminedSubtopic = topicElement.getSubTopicByIndex(1).addSubTopic()
        undeterminedSubtopic.setTitle("Undetermined")
        self.createSubTopics(undeterminedSubtopic, self.app.smaliChecks.getUndeterminedCryptographicFunctionsLocations())
        if (len(self.app.smaliChecks.getUndeterminedCryptographicFunctionsLocations()) > self.configuration.getXmindTopicFoldAt()):
            undeterminedSubtopic.setFolded()

        if len(self.app.smaliChecks.getCustomChecksLocations()) > 0:
            for check in self.app.smaliChecks.getCustomChecksLocations():
                customCheckSubTopic = topicElement.getSubTopicByIndex(2).addSubTopic()
                customCheckSubTopic.setTitle(check)
                self.createSubTopics(customCheckSubTopic, self.app.smaliChecks.getCustomChecksLocations()[check])

                if len(self.app.smaliChecks.getCustomChecksLocations()[check]) > self.configuration.getXmindTopicFoldAt():
                    customCheckSubTopic.setFolded()

        # Improper Platform Usage

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Improper Platform Usage")
        ipSubTopics = ["Malicious interaction possible with exported components?"]
        self.createSubTopics(topicElement, ipSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-sensitive-functionality-exposure-through-ipc")

        if(len(self.app.smaliChecks.getVulnerableContentProvidersSQLiLocations()) > 0):
            contentProviderSQLi = topicElement.addSubTopic()
            contentProviderSQLi.addMarker('flag-yellow')
            contentProviderSQLi.setTitle("Possibility of SQL Injection in exported ContentProvider")
            self.createSubTopics(contentProviderSQLi, self.app.smaliChecks.getVulnerableContentProvidersSQLiLocations())

        if (len(self.app.smaliChecks.getVulnerableContentProvidersPathTraversalLocations()) > 0):
            contentProviderPathTraversal = topicElement.addSubTopic()
            contentProviderPathTraversal.addMarker('flag-yellow')
            contentProviderPathTraversal.setTitle("Possibility of Path Traversal in exported ContentProvider")
            self.createSubTopics(contentProviderPathTraversal, self.app.smaliChecks.getVulnerableContentProvidersPathTraversalLocations())

        debuggableEvidenceTopic = topicElement.addSubTopic()
        debuggableEvidenceTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master//Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#testing-if-the-app-is-debuggable")
        if self.app.isDebuggable() == "Yes":
            debuggableEvidenceTopic.setTitle("Application is debuggable")
            debuggableEvidenceTopic.addMarker('flag-red')
            debuggableEvidenceTopic.setURLHyperlink(
                "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#testing-if-the-app-is-debuggable")
        else:
            debuggableEvidenceTopic.setTitle("Application is not debuggable")
            debuggableEvidenceTopic.addMarker('flag-green')

        activitiesVulnerableToPreferences = topicElement.addSubTopic()
        activitiesVulnerableToPreferences.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-fragment-injection")
        if len(self.app.getActivitiesExtendPreferencesWithoutValidate()) != 0 and int(self.app.getMinSDKVersion()) < 19:
            activitiesVulnerableToPreferences.setTitle("Activities vulnerable to Fragment Injection")
            self.createSubTopics(activitiesVulnerableToPreferences, self.app.getActivitiesExtendPreferencesWithoutValidate())
            activitiesVulnerableToPreferences.addMarker('flag-red')
        if len(self.app.getActivitiesExtendPreferencesWithValidate()) != 0:
            activitiesVulnerableToPreferences.setTitle("Activities with possible Fragment Injection (isValidFragment in place)")
            self.createSubTopics(activitiesVulnerableToPreferences, self.app.getActivitiesExtendPreferencesWithValidate())
            activitiesVulnerableToPreferences.addMarker('flag-yellow')
        if len(self.app.getActivitiesExtendPreferencesWithoutValidate()) == 0 and len(self.app.getActivitiesExtendPreferencesWithValidate()) == 0:
            activitiesVulnerableToPreferences.setTitle("No activities vulnerable to Fragment Injection")
            activitiesVulnerableToPreferences.addMarker('flag-green')

        addJavascriptInterfaceTopic = topicElement.addSubTopic()
        if len(self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations()) != 0:
            if int(self.app.getMinSDKVersion()) <= 16:
                addJavascriptInterfaceTopic.setTitle("JavascriptInterface with RCE possibility")
                addJavascriptInterfaceTopic.addMarker('flag-red')
            else:
                addJavascriptInterfaceTopic.setTitle("JavascriptInterface available.")
                addJavascriptInterfaceTopic.addMarker('flag-yellow')
            self.createSubTopics(addJavascriptInterfaceTopic, self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations())
            if len(self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations()) > self.configuration.getXmindTopicFoldAt():
                addJavascriptInterfaceTopic.setFolded()
        else:
            addJavascriptInterfaceTopic.setTitle("No presence of JavascriptInterface")
            addJavascriptInterfaceTopic.addMarker('flag-green')
        addJavascriptInterfaceTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#determining-whether-java-objects-are-exposed-through-webviews")

        javascriptEnabledWebviewTopic = topicElement.addSubTopic()
        javascriptEnabledWebviewTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#determining-whether-java-objects-are-exposed-through-webviews")
        if len(self.app.smaliChecks.getJavascriptEnabledWebViews()) > 0:
            javascriptEnabledWebviewTopic.setTitle("WebView with Javascript enabled.")
            self.createSubTopics(javascriptEnabledWebviewTopic, self.app.smaliChecks.getJavascriptEnabledWebViews())
            javascriptEnabledWebviewTopic.addMarker('flag-yellow')
            if len(self.app.smaliChecks.getJavascriptEnabledWebViews()) > self.configuration.getXmindTopicFoldAt():
                javascriptEnabledWebviewTopic.setFolded()
        else:
            javascriptEnabledWebviewTopic.setTitle("No WebView with Javascript enabled.")
            javascriptEnabledWebviewTopic.addMarker('flag-green')

        fileAccessEnabledWebviewTopic = topicElement.addSubTopic()
        fileAccessEnabledWebviewTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-webview-protocol-handlers")
        if len(self.app.smaliChecks.getFileAccessEnabledWebViews()) > 0:
            fileAccessEnabledWebviewTopic.setTitle("WebView with fileAccess enabled.")
            self.createSubTopics(fileAccessEnabledWebviewTopic, self.app.smaliChecks.getFileAccessEnabledWebViews())
            if int(self.app.getMinSDKVersion()) < 16:
                fileAccessEnabledWebviewTopic.setPlainNotes("This app runs in versions bellow API 16 (Jelly Bean). If webview is opening local HTML files via file URL and loading external resources it might be possible to bypass Same Origin Policy and extract local files since AllowUniversalAccessFromFileURLs is enabled by default and there is not public API to disable it in this versions.")
                fileAccessEnabledWebviewTopic.addMarker('flag-yellow')
            else:
                fileAccessEnabledWebviewTopic.addMarker('flag-yellow')
            if len(self.app.smaliChecks.getFileAccessEnabledWebViews()) > self.configuration.getXmindTopicFoldAt():
                fileAccessEnabledWebviewTopic.setFolded()
        else:
            fileAccessEnabledWebviewTopic.setTitle("No WebView with fileAccess enabled.")
            fileAccessEnabledWebviewTopic.addMarker('flag-green')

        universalAccessEnabledWebviewTopic = topicElement.addSubTopic()
        if len(self.app.smaliChecks.getUniversalAccessFromFileURLEnabledWebviewsLocations()) > 0:
            self.createSubTopics(universalAccessEnabledWebviewTopic, self.app.smaliChecks.getUniversalAccessFromFileURLEnabledWebviewsLocations())
            universalAccessEnabledWebviewTopic.setTitle("WebView with Universal Access from File URLs enabled.")
            universalAccessEnabledWebviewTopic.addMarker('flag-yellow')
        else:
            universalAccessEnabledWebviewTopic.setTitle("No WebView with Universal Access from File URLs found.")
            universalAccessEnabledWebviewTopic.addMarker('flag-green')

        # Insecure Communication Topic

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Insecure Communication")
        icSubTopics = ["SSL Implementation", "Mixed Mode Communication?"]
        self.createSubTopics(topicElement, icSubTopics)
        sslSubTopics = ["Accepts self-sign certificates?", "Accepts wrong host name?", "Lack of Certificate Pinning?"]
        self.createSubTopics(topicElement.getSubTopicByIndex(0), sslSubTopics)

        trustManagerSubTopic = topicElement.addSubTopic()
        trustManagerSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate")
        if len(self.app.smaliChecks.getVulnerableTrustManagers()) != 0:
            trustManagerSubTopic.setTitle("Vulnerable Trust Manager:")
            trustManagerSubTopic.addMarker('flag-red')
            self.createSubTopics(trustManagerSubTopic, self.app.smaliChecks.getVulnerableTrustManagers())
        else:
            trustManagerSubTopic.setTitle("No vulnerable Trust Manager found.")
            trustManagerSubTopic.addMarker('flag-green')

        sslErrorBypassSubTopic = topicElement.addSubTopic()
        sslErrorBypassSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification")
        if len(self.app.smaliChecks.getVulnerableWebViewSSLErrorBypass()) != 0:
            sslErrorBypassSubTopic.setTitle("Webview with vulnerable SSL Implementation:")
            sslErrorBypassSubTopic.addMarker('flag-red')
            self.createSubTopics(sslErrorBypassSubTopic, self.app.smaliChecks.getVulnerableWebViewSSLErrorBypass())
        else:
            sslErrorBypassSubTopic.setTitle("No WebView with SSL Errror Bypass found.")
            sslErrorBypassSubTopic.addMarker('flag-green')

        vulnerableHostnameVerifiersSubTopic = topicElement.addSubTopic()
        vulnerableHostnameVerifiersSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification")
        if len(self.app.smaliChecks.getVulnerableHostnameVerifiers()) != 0:
            vulnerableHostnameVerifiersSubTopic.setTitle("Vulnerable HostnameVerifier found")
            vulnerableHostnameVerifiersSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableHostnameVerifiersSubTopic, self.app.smaliChecks.getVulnerableHostnameVerifiers())
        else:
            vulnerableHostnameVerifiersSubTopic.setTitle("No vulnerable HostnameVerifiers found.")
            vulnerableHostnameVerifiersSubTopic.addMarker('flag-green')

        vulnerableSetHostnameVerifiersSubTopic = topicElement.addSubTopic()
        vulnerableSetHostnameVerifiersSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification")
        if len(self.app.smaliChecks.getVulnerableSetHostnameVerifier()) != 0:
            vulnerableSetHostnameVerifiersSubTopic.setTitle("setHostnameVerifier call with ALLOW_ALL_HOSTNAMES_VERIFIER")
            vulnerableSetHostnameVerifiersSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableSetHostnameVerifiersSubTopic, self.app.smaliChecks.getVulnerableSetHostnameVerifier())
        else:
            vulnerableSetHostnameVerifiersSubTopic.setTitle("No vulnerable setHostnameVerifiers found.")
            vulnerableSetHostnameVerifiersSubTopic.addMarker('flag-green')

        vulnerableSocketsSubTopic = topicElement.addSubTopic()
        vulnerableSocketsSubTopic.setURLHyperlink("")
        if len(self.app.smaliChecks.getVulnerableSockets()) != 0:
            vulnerableSocketsSubTopic.setTitle(
                "Direct usage of Socket without HostnameVerifier")
            vulnerableSocketsSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableSocketsSubTopic, self.app.smaliChecks.getVulnerableSockets())
        else:
            vulnerableSocketsSubTopic.setTitle("No direct usage of Socket without HostnameVerifiers.")
            vulnerableSocketsSubTopic.addMarker('flag-green')

        networkSecurityConfig = topicElement.addSubTopic()
        networkSecurityConfig.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-security-configuration")
        if int(self.app.targetSDKVersion) >= 25:
            if self.app.hasNetworkSecurityConfig is True:
                networkSecurityConfig.setTitle("Usage of NetworkSecurityConfig file.")
                domains = self.app.getNetworkSecurityConfigDomains()
                for domain in domains:
                    domainTopic = networkSecurityConfig.addSubTopic()
                    domainTopic.setTitle(','.join(domain['domains']))

                    clearTextAllowedTopic = domainTopic.addSubTopic()
                    clearTextAllowedTopic.setTitle("Clear Text Allowed")
                    clearTextAllowedValueTopic = clearTextAllowedTopic.addSubTopic()
                    if str(domain['allowClearText']) == "True":
                        clearTextAllowedValueTopic.setTitle("Yes")
                        clearTextAllowedValueTopic.addMarker('flag-red')
                    else:
                        clearTextAllowedValueTopic.setTitle("No")
                        clearTextAllowedValueTopic.addMarker('flag-green')

                    allowUserCATopic = domainTopic.addSubTopic()
                    allowUserCATopic.setTitle("User CA Trusted")
                    allowUserCAValueTopic = allowUserCATopic.addSubTopic()
                    if str(domain['allowUserCA']) == "True":
                        allowUserCAValueTopic.setTitle("Yes")
                        allowUserCAValueTopic.addMarker('flag-red')
                    else:
                        allowUserCAValueTopic.setTitle("No")
                        allowUserCAValueTopic.addMarker('flag-green')

                    pinningTopic = domainTopic.addSubTopic()
                    pinningTopic.setTitle("Pinning Configured")
                    pinningValueTopic = pinningTopic.addSubTopic()
                    if str(domain['pinning']) == "True":
                        pinningValueTopic.setTitle("Yes")
                        pinningValueTopic.addMarker('flag-green')
                        pinningExpirationTopic = pinningTopic.addSubTopic()
                        pinningExpirationValueTopic = pinningExpirationTopic.addSubTopic()
                        pinningExpirationTopic.setTitle("Pinning Expiration")
                        if domain['pinningExpiration'] != '':
                            date_format = "%Y-%m-%d"
                            a = datetime.strptime(domain['pinningExpiration'], date_format)
                            b = datetime.strptime(time.strftime("%Y-%m-%d"), date_format)
                            days = (a - b).days
                            pinningExpirationValueTopic.setTitle(domain['pinningExpiration'])
                            if days <= 0:
                                pinningExpirationValueTopic.addMarker('flag-red')
                                pinningExpirationValueTopic.setPlainNotes('Certificate Pinning is disabled. The expiration date on the pin-set has been reached.')
                            elif days < 60:
                                pinningExpirationValueTopic.addMarker('flag-yellow')
                                pinningExpirationValueTopic.setPlainNotes(str(days) + ' days for Certificate Pinning to be disabled.')
                        else:
                            pinningExpirationValueTopic.setTitle("No expiration")

                    else:
                        pinningValueTopic.setTitle("No")
                        pinningValueTopic.addMarker('flag-yellow')

            else:
                networkSecurityConfig.setTitle("No usage of NetworkSecurityConfig file.")
                networkSecurityConfig.addMarker('flag-yellow')
        else:
            networkSecurityConfig.setTitle("NetworkSecurityConfig check ignored.")
            networkSecurityConfig.addMarker('flag-green')
            networkSecurityConfig.setPlainNotes("App is not targeting Android versions >= Nougat 7.0")

        certificatePinningTopic = topicElement.getSubTopicByIndex(0).addSubTopic()
        certificatePinningTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning")
        if len(self.app.smaliChecks.getOkHTTPCertificatePinningLocations()) > 0 or len(self.app.smaliChecks.getCustomCertificatePinningLocations()) > 0:
            certificatePinningTopic.setTitle("Possible Certificate Pinning Usage")
            certificatePinningTopic.addMarker('flag-green')
            if len(self.app.smaliChecks.getOkHTTPCertificatePinningLocations()) > 0:
                okHttpCertificatePinningTopic = certificatePinningTopic.addSubTopic()
                okHttpCertificatePinningTopic.setTitle("OkHTTP Certificate Pinning.")
                self.createSubTopics(okHttpCertificatePinningTopic, self.app.smaliChecks.getOkHTTPCertificatePinningLocations())

            if len(self.app.smaliChecks.getCustomCertificatePinningLocations()) > 0:
                customCertificatePinningTopic = certificatePinningTopic.addSubTopic()
                customCertificatePinningTopic.setTitle("Custom Certificate Pinning")
                self.createSubTopics(customCertificatePinningTopic, self.app.smaliChecks.getCustomCertificatePinningLocations())
        else:
            certificatePinningTopic.setTitle("No usage of Certificate Pinning")
            certificatePinningTopic.addMarker('flag-yellow')

        sslImplementationTopic = topicElement.getSubTopicByIndex(0)
        sslImplementationTopic.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate")
        sslImplementationTopic.getSubTopicByIndex(1).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification#hostname-verification")
        sslImplementationTopic.getSubTopicByIndex(2).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning")

        # Insecure Data Storage Topic

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Insecure Data Storage")
        idsSubTopics = [
            "Sensitive information stored in cleartext in sdcard/sandbox?",
            "Sensitive information saved to system logs?",
            "Background screenshot with sensitive information?"
        ]
        self.createSubTopics(topicElement, idsSubTopics)

        activitiesWithoutSecureFlagSubTopic = topicElement.addSubTopic()
        activitiesWithoutSecureFlagSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots")
        if len(self.app.getActivitiesWithoutSecureFlag()) != 0:
            activitiesWithoutSecureFlagSubTopic.setTitle("Activities without FLAG_SECURE or android:excludeFromRecents :")
            activitiesWithoutSecureFlagSubTopic.addMarker('flag-yellow')
            self.createSubTopics(activitiesWithoutSecureFlagSubTopic, self.app.getActivitiesWithoutSecureFlag())
            activitiesWithoutSecureFlagSubTopic.setFolded()
            if len(self.app.getActivitiesWithoutSecureFlag()) > self.configuration.getXmindTopicFoldAt():
                activitiesWithoutSecureFlagSubTopic.setFolded()
        else:
            activitiesWithoutSecureFlagSubTopic.setTitle("All activities have FLAG_SECURE or android:excludeFromRecents.")
            activitiesWithoutSecureFlagSubTopic.addMarker('flag-green')

        topicElement.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-local-storage-for-sensitive-data")
        topicElement.getSubTopicByIndex(1).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-logs-for-sensitive-data")
        topicElement.getSubTopicByIndex(2).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots")

        # Insufficient Cryptography Topic

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Insufficient Cryptography")
        icrSubTopics = ["Using weak algorithms/modes?", "Using hardcoded properties?"]
        self.createSubTopics(topicElement, icrSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        topicElement.getSubTopicByIndex(1).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md#verifying-the-configuration-of-cryptographic-standard-algorithms")

        AESTopic = topicElement.addSubTopic()
        AESTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        if len(self.app.smaliChecks.getAESwithECBLocations()) > 0:
            AESTopic.setTitle("Usage of AES with ECB Mode")
            self.createSubTopics(AESTopic, self.app.smaliChecks.getAESwithECBLocations())
            AESTopic.addMarker('flag-red')
        else:
            AESTopic.setTitle("No usage of AES with ECB Mode")
            AESTopic.addMarker('flag-green')

        DESTopic = topicElement.addSubTopic()
        DESTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        if len(self.app.smaliChecks.getDESLocations()) > 0:
            DESTopic.setTitle("Usage of DES or 3DES")
            self.createSubTopics(DESTopic, self.app.smaliChecks.getDESLocations())
            DESTopic.addMarker('flag-red')
        else:
            DESTopic.setTitle("No usage of DES or 3DES")
            DESTopic.addMarker('flag-green')

        keystoreTopic = topicElement.addSubTopic()
        if len(self.app.smaliChecks.getKeystoreLocations()) > 0:
            keystoreTopic.setTitle("Usage of Android KeyStore")
            keystoreTopic.addMarker('flag-green')
            self.createSubTopics(keystoreTopic, self.app.smaliChecks.getKeystoreLocations())
        else:
            keystoreTopic.setTitle("No usage of Android KeyStore")
            keystoreTopic.addMarker('flag-yellow')

        # Code Tampering Topic

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Code Tampering")
        ctSubTopics = ["Lack of root detection?", "Lack of hooking detection?"]
        self.createSubTopics(topicElement, ctSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection")
        topicElement.getSubTopicByIndex(1).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-detection-of-reverse-engineering-tools")

        # Reverse Engineering Topic

        topicElement = methodologyTopic.addSubTopic()
        topicElement.setTitle("Reverse Engineering")
        reSubTopics = ["Lack of code obfuscation?"]
        self.createSubTopics(topicElement, reSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-obfuscation")
