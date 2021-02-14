import json
import time,datetime

from core.models import action, webui
from core import helpers, auth, db, function, audit

from plugins.ibmXforce.models import ibmXforce
import base64, ast
import ipaddress, validators

import sys
from plugins.ibmXforce.includes import xForce


class _xForceReport(action._action):
    class _properties(webui._properties):
        def generate(self,classObject):

            formData = []
            observableList = ["Hash","Domain","IPV4 Address","IPV6 Address"]
            resultTypeList = ["current results only", "current + previous results"]
            formData.append({"type" : "input", "schemaitem" : "name", "textbox" : classObject.name})
            formData.append({"type" : "input", "schemaitem" : "apiKey", "textbox" : classObject.apiKey})
            formData.append({"type" : "input", "schemaitem" : "apiPass", "textbox" : classObject.apiPass})
            formData.append({"type" : "dropdown", "schemaitem" : "observabletype", "dropdown" : observableList,"current": classObject.observabletype})
            formData.append({"type" : "input", "schemaitem" : "observable", "textbox" : classObject.observable})
            formData.append({"type" : "dropdown", "schemaitem" : "resultType", "dropdown" : resultTypeList,"current": classObject.resultType})
            # formData.append({"type" : "datepicker", "schemaitem" : "testPicker", "datepicker" : classObject.testPicker}) 
            # formData.append({"type" : "checkbox", "schemaitem" : "overrideLastResult", "checked" : classObject.overrideLastResult, "tooltip" : "Override recent result default behaviour stops additional scans if recently queiried (uses additional API credits)"})
            # formData.append({"type" : "checkbox", "schemaitem" : "overrideLimit", "checked" : classObject.overrideLimit, "tooltip" : "Override default limit of 1 (uses additional API credits)"})
            formData.append({"type" : "json-input", "schemaitem" : "varDefinitions", "textbox" : classObject.varDefinitions})
            return formData

    # testPicker          = str()  #reenable
    name                = str()
    apiKey              = str()
    apiPass             = str()
    observabletype      = str()
    observable          = str()
    resultType          = str()
    # overrideLastResult  = bool() #renable
    # overrideLimit       = bool()

    # # # #
    # Checks user input is of correct type before sending to API
    # # # # 
    def isValidIp(self,observable):
        try:
            ipaddress.ip_address(observable)
            return True
        except:
            return False

    def isValidDomain(self,observable):
        if validators.domain(observable):
            return True
        else:
            return False

    def resultMessage(self,actionResult,Status,StatusCode,msg):
        actionResult["result"] = Status
        actionResult["rc"]     = StatusCode
        actionResult["msg"]    = msg

    def run(self,data,persistentData,actionResult):

        observableType  = helpers.evalString(self.observabletype,{"data" : data})
        observable      = helpers.evalString(self.observable,{"data" : data})
        resultType      = helpers.evalString(self.resultType,{"data" : data})
        apiKey          = helpers.evalString(self.apiKey,{"data" : data})
        
        #Helpers
        paramMap = {"current results only": "report", "current + previous results": "history"}
        if resultType != None:
            param = paramMap[resultType]

        # if observableType or observable or resultType == None:
        #     actionResult["result"]  = False
        #     actionResult["rc"]      = 400
        #     actionResult["message"] = "Parameters cannot be null"


        if self.apiPass.startswith("ENC"):
            apiPass = auth.getPasswordFromENC(self.apiPass)

        data_string     = f"{apiKey}:{apiPass}"
        data_bytes      = data_string.encode("ascii")
        token           = base64.b64encode(data_bytes).decode("ascii")


        xForceResults = ibmXforce._ibmXforce().query(query={ "observable" : observable })["results"] #, "queryType":  observableType })["results"] 
        # if observable != "":
        #     if not xForceResults:
                # ibmXforce._ibmXforce().new(f"{observable}") #Not working  ????

        appjson             = "application/json"

        proxies             = { "http" : "http://", "https" : "http://"}
        certPath            = "//"
        
        xForceClient        = xForce._IBMxForce(token,appjson,proxy=proxies,ca=certPath)
        # xForceClient        =  xForce._IBMxForce(token,appjson)
        
        if xForceClient != None:
            persistentData["xForce"]={}
            persistentData["xForce"]["client"] = xForceClient
        
        if observableType == "IPV4 Address" or observableType == "IPV6 Address":
            if self.isValidIp(observable):

                result = xForceClient.checkReuptationHistoryIP(param,observable)
                actionResult["xforceResults"] = result

                actionResult["result"] = True
                actionResult["rc"]     = 200                
            else:
                self.resultMessage(actionResult,False,400,"not valid IP")
        
        elif observableType == "Domain":
            
            if self.isValidDomain(observable): #if self.isValidDomain(observable):
                result = xForceClient.checkReuptationHistoryURL(param,observable)
                
                actionResult["xforceResults"] = result

                actionResult["result"] = True
                actionResult["rc"]     = 200                
            else:
                self.resultMessage(actionResult,False,400,"not valid domain")

        elif observableType == "Hash":
                result = xForceClient.checkMalwareFileHash(observable)     

                if result != None:
                    actionResult["xforceResults"]   = result
                    actionResult["result"]          = True
                    actionResult["rc"]              = 200    
                else:
                    self.resultMessage(actionResult,False,400,"an Error has occured")
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiPass" and not value.startswith("ENC "):
            self.apiPass = "ENC {0}".format(auth.getENCFromPassword(value))                      
            return True
        return super(_xForceReport, self).setAttribute(attr,value,sessionData=sessionData)

class _xForceGetUsage(action._action):
    class _properties(webui._properties):
        def generate(self,classObject):

            formData = []
            formData.append({"type" : "checkbox", "schemaitem" : "usePersistentData", "checked" : classObject.usePersistentData, "tooltip" : "Use previously created obj to not supply credentials"})
            formData.append({"type" : "checkbox", "schemaitem" : "useThreshold", "checked" : classObject.useThreshold, "tooltip" : "If enabled - prohibits API use if threshold exceeded"})
            formData.append({"type" : "input", "schemaitem" : "threshold", "textbox" : classObject.threshold})
            formData.append({"type" : "input", "schemaitem" : "apiKey", "textbox" : classObject.apiKey})
            formData.append({"type" : "input", "schemaitem" : "apiPass", "textbox" : classObject.apiPass})            
            return formData
    
    usePersistentData   = bool()
    useThreshold        = bool()
    threshold           = int()
    apiKey              = str()
    apiPass             = str()

    # can be tweaked to have success messages also
    def resultMessage(self,actionResult,Status,StatusCode,msg):
        actionResult["result"] = Status
        actionResult["rc"]     = StatusCode
        actionResult["msg"]    = msg

    def run(self,data,persistentData,actionResult):

        apiKey          = helpers.evalString(self.apiKey,{"data" : data})

        if self.apiPass.startswith("ENC"):
            apiPass = auth.getPasswordFromENC(self.apiPass)

        #Use previous class obj in flow
        if self.usePersistentData == True:
            if "xForce" in persistentData:
                if "client" in persistentData["xForce"]:
                    xForceClient                            = persistentData["xForce"]["client"] 
                    creditsRemaining                        = xForceClient.checkApiUsage()
                    freeCreditsRemaining                    = creditsRemaining[0]["quotaRemaining"]
                    if self.useThreshold == True:
                        if self.threshold != None:
                            if self.threshold > int(freeCreditsRemaining):
                                actionResult["data"]["xforceCredits"]   = freeCreditsRemaining
                                actionResult["data"]["xforceAPIUsage"]  = creditsRemaining
                                self.resultMessage(actionResult,False,308,"User specified threshold hit - exiting")
                                return actionResult
                        else:
                            self.resultMessage(actionResult,False,308,"Threshold enabled but max number not supplied - exiting")
                            return actionResult
                    actionResult["data"]["xforceCredits"]   = freeCreditsRemaining          
                    actionResult["data"]["xforceAPIUsage"]  = creditsRemaining          
                    actionResult["result"]                  = True
                    actionResult["rc"]                      = 200                
            #Could not find config
            else: 
                self.resultMessage(actionResult,False,400,"Could not find condig")

        # Using User supplied conf
        else: 
            try:
                if self.apiPass == "" or apiKey == "":
                    self.resultMessage(actionResult,False,400,"Please supply credentials")
                else:
                    data_string         = f"{apiKey}:{apiPass}"
                    data_bytes          = data_string.encode("ascii")
                    token               = base64.b64encode(data_bytes).decode("ascii")

                    appjson             = "application/json"
                    xForceClient        =  xForce._IBMxForce(token,appjson)
                    
                    creditsRemaining    = xForceClient.checkApiUsage()

                    if int(threshold) < int(creditsRemaining):
                        actionResult["data"]["xforceCredits"]   = creditsRemaining
                        self.resultMessage(actionResult,False,308,"User specified threshold hit - exiting")

                        return actionResult
                    actionResult["data"]["xforceCredits"]   = creditsRemaining
                    actionResult["result"] = True
                    actionResult["rc"]     = 200
                
            except Exception as e:
                line_number = sys.exc_info()[-1].tb_lineno
                print(f"(xForce Action) Exception has been raised on Line :  {line_number}\nWith the following message: {e}")										                        
                self.resultMessage(actionResult,False,400,"Could not check API")
    


        return actionResult     

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiPass" and not value.startswith("ENC "):
            self.apiPass = "ENC {0}".format(auth.getENCFromPassword(value))
            return True
        return super(_xForceGetUsage, self).setAttribute(attr,value,sessionData=sessionData)        

class _xForceGlpiEnrichment(action._action):
    class _properties(webui._properties):
        def generate(self,classObject):

            formData = []
            resultTypeList = ["current results only", "current + previous results"]
            formData.append({"type" : "input", "schemaitem" : "name", "textbox" : classObject.name})
            formData.append({"type" : "input", "schemaitem" : "apiKey", "textbox" : classObject.apiKey})
            formData.append({"type" : "input", "schemaitem" : "apiPass", "textbox" : classObject.apiPass})
            formData.append({"type" : "input", "schemaitem" : "observable", "textbox" : classObject.observable})
            formData.append({"type" : "dropdown", "schemaitem" : "resultType", "dropdown" : resultTypeList,"current": classObject.resultType})
            formData.append({"type" : "json-input", "schemaitem" : "varDefinitions", "textbox" : classObject.varDefinitions})
            return formData

    name                = str()
    apiKey              = str()
    apiPass             = str()
    observable          = str()
    resultType          = str()

    def isValidIp(self,observable):
        try:
            ipaddress.ip_address(observable)
            return True
        except:
            return False

    def isValidDomain(self,observable):
        if validators.domain(observable):
            return True
        else:
            return False

    def resultMessage(self,actionResult,Status,StatusCode,msg):
        actionResult["result"] = Status
        actionResult["rc"]     = StatusCode
        actionResult["msg"]    = msg

    def run(self,data,persistentData,actionResult):

        observable      = helpers.evalString(self.observable,{"data" : data})
        resultType      = helpers.evalString(self.resultType,{"data" : data})
        apiKey          = helpers.evalString(self.apiKey,{"data" : data})
        #Helpers
        paramMap = {"current results only": "report", "current + previous results": "history"}
        if resultType != None:
            param = paramMap[resultType]


        if self.apiPass.startswith("ENC"):
            apiPass = auth.getPasswordFromENC(self.apiPass)

        data_string     = f"{apiKey}:{apiPass}"
        data_bytes      = data_string.encode("ascii")
        token           = base64.b64encode(data_bytes).decode("ascii")

        appjson             = "application/json"
        proxies             = { "http" : "http://", "https" : "http://"}
        certPath            = "/"
        
        xForceClient        = xForce._IBMxForce(token,appjson,proxy=proxies,ca=certPath)
        # xForceClient        =  xForce._IBMxForce(token,appjson)

        if xForceClient != None:
            persistentData["xForce"]={}
            persistentData["xForce"]["client"] = xForceClient

        try:
            if self.isValidIp(observable):
                result = xForceClient.checkReuptationHistoryIP(param,observable)
                
                actionResult["xforceResults"] = result
                actionResult["result"] = True
                actionResult["rc"]     = 200                
            elif self.isValidDomain(observable): #if self.isValidDomain(observable):
                result = xForceClient.checkReuptationHistoryURL(param,observable)
                
                actionResult["xforceResults"] = result
                actionResult["result"] = True
                actionResult["rc"]     = 200                
            else:
                result = xForceClient.checkMalwareFileHash(observable)     

                # could be an invalid type returned
                if result != None:
                    actionResult["xforceResults"]   = result
                    actionResult["result"]          = True
                    actionResult["rc"]              = 200    
        except Exception as e:
            line_number = sys.exc_info()[-1].tb_lineno
            print(f"(xForce Action) Exception has been raised on Line :  {line_number}\nWith the following message: {e}")										
    
            self.resultMessage(actionResult,False,400,f"an Error has occured\n{e}")
        
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiPass" and not value.startswith("ENC "):
            self.apiPass = "ENC {0}".format(auth.getENCFromPassword(value))                      
            return True
        return super(_xForceGlpiEnrichment, self).setAttribute(attr,value,sessionData=sessionData)


class _xForcePremiumCnC(action._action):
    class _properties(webui._properties):
        def generate(self,classObject):

            formData = []
            formData.append({"type" : "input", "schemaitem" : "name", "textbox" : classObject.name})
            formData.append({"type" : "input", "schemaitem" : "apiKey", "textbox" : classObject.apiKey})
            formData.append({"type" : "input", "schemaitem" : "apiPass", "textbox" : classObject.apiPass})
            formData.append({"type" : "json-input", "schemaitem" : "varDefinitions", "textbox" : classObject.varDefinitions})
            return formData

    name                = str()
    apiKey              = str()
    apiPass             = str()


    def resultMessage(self,actionResult,Status,StatusCode,msg):
        print("in ResCatch")
        actionResult["result"] = Status
        actionResult["rc"]     = StatusCode
        actionResult["msg"]    = msg

    def run(self,data,persistentData,actionResult):

        apiKey          = helpers.evalString(self.apiKey,{"data" : data})
        #Helpers
        if self.apiPass.startswith("ENC"):
            apiPass = auth.getPasswordFromENC(self.apiPass)

        data_string     = f"{apiKey}:{apiPass}"
        data_bytes      = data_string.encode("ascii")
        token           = base64.b64encode(data_bytes).decode("ascii")

        appjson             = "application/json"
        proxies             = { "http" : "http://", "https" : "http://"}
        certPath            = "/"
        
        xForceClient        = xForce._IBMxForce(token,appjson,proxy=proxies,ca=certPath)
        # xForceClient        =  xForce._IBMxForce(token,appjson)

        # scanResults = gvmscan._gvmscan().query(query={ "gvmTarget" : scanName })["results"]
        xForceThreatIntel = ibmXforce._ibmXforceThreatIntel().query(query={ "intelSource" : "command_and_control_IPV4" })["results"]
        if not xForceThreatIntel:
            document = { "intelSource" : "command_and_control_IPV4" }
            ibmXforce._ibmXforceThreatIntel()._dbCollection.insert_one(document)




        if xForceClient != None:
            persistentData["xForce"]={}
            persistentData["xForce"]["client"] = xForceClient

        try:
            response = xForceClient.premiumFetchCNCData()
            # response = "IP_List"
            epochTime           = time.time()
            queryDate           = datetime.datetime.now()

    
            if "IP_List" in response:                
                ipList              = response["IP_List"]
                indicatorCount      = response["indicatorCount"]
                
                if "data" in xForceThreatIntel[0]:

                    currentIndicators   = set(xForceThreatIntel[0]["data"])
                    newIndicators       = set(ipList)

                    difference          = newIndicators.difference(currentIndicators)
                    combinedIndicators  = currentIndicators.union(newIndicators) 

                    ibmXforce._ibmXforceThreatIntel().api_update(query={  "intelSource" : "command_and_control_IPV4" },update={ "$set" : {  "data": list(combinedIndicators), "queryDateHumanReadible": f"{queryDate}","queryDate": f"{epochTime}" }})            


                    actionResult["xforceResults"]       = list(combinedIndicators)
                    actionResult["xforceCNCnewIOCs"]    = len(difference)
                    actionResult["result"] = True
                    actionResult["rc"]     = 200 



                #IPV4 Intel Is Null - populate
                else:
                    ibmXforce._ibmXforceThreatIntel().api_update(query={  "intelSource" : "command_and_control_IPV4" },update={ "$set" : {  "data": ipList, "queryDateHumanReadible": f"{queryDate}","queryDate": f"{epochTime}" }})
                    
                    actionResult["xforceResults"] = ipList
                    actionResult["result"] = True
                    actionResult["rc"]     = 200 

   


                
        except Exception as e:
            line_number = sys.exc_info()[-1].tb_lineno
            print(f"(xForce Action) Exception has been raised on Line :  {line_number}\nWith the following message: {e}")										
    
            self.resultMessage(actionResult,False,400,f"an Error has occured\n{e}")            
        
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiPass" and not value.startswith("ENC "):
            self.apiPass = "ENC {0}".format(auth.getENCFromPassword(value))                      
            return True
        return super(_xForcePremiumCnC, self).setAttribute(attr,value,sessionData=sessionData)