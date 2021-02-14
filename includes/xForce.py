import requests, base64, json
import sys
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class REQException(Exception):
    pass

class _IBMxForce():
    DOMAIN          = "exchange.xforce.ibmcloud.com"
    API_Endpoint    = "api"

    def __init__(self,token,outputFormat,ca=None,proxy={ "http" : None, "https" : None }):
        self.token          = token
        self.outputFormat   = outputFormat
        self.headers        = {"Authorization": f"Basic {token} ", "Accept": f"{outputFormat}"}
        self.proxies = proxy
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def _handle_http_codes(self,response):
        '''
            # # # # # # #-# # # # # # #
            # Handle HTTP Status Codes
            # # # # # # #-# # # # # # #
        '''
        _status_code = response.status_code		

        if _status_code == 200:
            msg = f"API has returned: {response.status_code}"
            return _status_code, response
            
        if _status_code == 401:
            msg = (f"Token is not authorized to perform this function: {response.status_code}")
            return _status_code,msg

        if _status_code == 404:
            msg = (f"The resource was not found: {response.status_code}")
            return _status_code,msg

        if _status_code == 429:
            msg = (f"Too many requests have been sent to the service: {response.status_code}")
            return _status_code,msg

        if _status_code == 441:
            msg = (f"Incorrectly parsed request: {response.status_code}")
            return _status_code,msg

        if _status_code == 500:
            msg = (f"Internal Server Error: {response.status_code}")
            return _status_code,msg

        if _status_code == 503:
            msg = (f"Server Is unavailable at this time: {response.status_code}")
            return _status_code,msg
        else:
            msg = "Unhandled Error Code"
            return _status_code,msg


    def apiCall(self,endpoint,**kwargs):
        params = ""
        for key,value in kwargs.items():
            params += f"&{key}={value}"
        
        # can also do __class__.DOMAIN
        url                         = f"https://{self.DOMAIN}/{self.API_Endpoint}/{endpoint}?{params}"
        if self.ca:
            _status_code,response = self._handle_http_codes(requests.get(url,headers=self.headers,proxies=self.proxies,verify=False, timeout=38)) #whilst in office
            # _status_code, response      = self._handle_http_codes(requests.get(url,headers=self.headers,proxies=self.proxies, timeout=38))
        else:
            _status_code, response      = self._handle_http_codes(requests.get(url,headers=self.headers, timeout=20))
        # print(url)
        
        if _status_code == 200:
            return response
        else:
            # will switch this to the action result which will be passed back to user
            REQException(response)


    def checkApiUsage(self,**kwargs):
        '''
            Checks remaining quota 
        '''
        endpoint = "all-subscriptions/usage"
        response = self.apiCall(endpoint).json()
        
        checkPremium = False
        apiUsage     = []
        if "premium" in kwargs:
            checkPremium = kwargs.get("premium")


        if len(response) > 0:   #len is 3 
            for item in response:
                # print("\n",item)

                
                if "usageData" in item:
                    if "entitlement" in item["usageData"]:
                        subscription        = item["subscriptionType"]
                        subscriptionType    = item["usageData"]["type"]     #premium / free

                        quotaUsed           = item["usageData"]["usage"][0]["usage"]
                        monthlyQuota        = item["usageData"]["entitlement"]
                        quotaRemaining      = int(monthlyQuota) - int(quotaUsed)
                        usagePeriod         = item["usageData"]["usage"][0]["cycle"]

                        apiUsage.append({ "subscription": subscription, "subscriptionType": subscriptionType, "quotaUsed": quotaUsed, "monthlyQuota":monthlyQuota, "quotaRemaining": quotaRemaining, "usagePeriod": usagePeriod})                      

        return apiUsage   #quotaRemaining


    #Need to complete this one
    def checkReuptationHistoryURL(self,param,observable):
        '''
            The /url/ queries retrieve url address, geolocation, risk ratings and content categorization for IP addresses and subnets.

            Report keeps only current reports
            History includes deleted reports
            Malware includes an additional key: malware_extended
            
            Skipped:
            Networks assigned to asn 
            IPs by category
        '''

        result       = {}
        knownBadHost = False        #if more than 2 entries in history becomes true
        isMalicious  = False

        if param == "history":
            qString = f"history/{observable}"   #reputation report 
        elif param == "report":
            qString = f"{observable}"           #report for an IP
        elif param == "malware":
            qString = f"malware/{observable}"   #malware associated with IP


        endpoint = f"url/{qString}"
        response = self.apiCall(endpoint)
        

        if response != None:     
            
            #Cats not consistent and was a pain to prse
            result = response.json()

        else:
            result = "No results were returned"

        return result


    def checkReuptationHistoryIP(self,param,observable):
        '''
            The /ipr/ queries retrieve IP address, geolocation, risk ratings and content categorization for IP addresses and subnets.

            Report keeps only current reports
            History includes deleted reports
            Malware includes an additional key: malware_extended
            
            Skipped:
            Networks assigned to asn 
            IPs by category
        '''

        result       = {}
        knownBadHost = False        #if more than 2 entries in history becomes true
        isMalicious  = False

        if param == "history":
            qString = f"history/{observable}"   #reputation report 
        elif param == "report":
            qString = f"{observable}"           #report for an IP
        elif param == "malware":
            qString = f"malware/{observable}"   #malware associated with IP


        endpoint = f"ipr/{qString}"
        response = self.apiCall(endpoint).json()                     

        # Parsing differs based on req
        if param == "history" or param == "report":
            highestScore            = 0
            previousreportedCats    = []
            currentReports          = []

            if len(response["history"]) > 0:
                for entry in response["history"]:

                    if "deleted" not in entry:  #Latest Entries  - not deleted                   
                        if len(entry["cats"]) > 0:  #Summary Key + Adding categories if not emoty
                            isMalicious                     = True
                            result["latestCategories"]      = entry["cats"]

                        result["latestReportDate"]  = entry["created"]
                        result["latestGeolocation"] = entry["geo"]
                        result["latestCIDRReport"]  = entry["ip"] 
                        result["risk"]              = entry["score"]
                        currentReports.append({ "created": entry["created"], "geolocation": entry["geo"], "cidr": entry["ip"], "risk": entry["score"], "cats": entry["cats"]})

                    # Highest Score reported
                    if  float(entry["score"]) > float(highestScore):
                        highestScore = entry["score"]

                    

                    #Previous Categories Reported
                    if len(entry["cats"]) > 0:
                        previousreportedCats.append({ "created": entry["created"], "cats": entry["cats"] })        
            #
            result["isMaliciousPreviously"]         = knownBadHost
            result["isMaliciousCurrently"]          = isMalicious
            result["HighestReportedScore"]          = highestScore
            result["CurrentRepots"]                 = currentReports            
            if len(previousreportedCats) > 0:
                result["previousOffenseCategories"] = previousreportedCats    
                knownBadHost                        = True    
        
        elif param == "malware":
            if len(response["malware"]) > 0:
                
                print("No Samples To test")


        return result        

    def checkMalwareFileHash(self,observable):

        endpoint = f"malware/{observable}"
        response = self.apiCall(endpoint).json()

        result       = {}
        if "malware" in response:
            base        = response["malware"]["origins"]["external"]
            risk        = response["malware"]["risk"]
            
            result["malwareInfo"]   = base
            result["risk"]          = risk

        return result   

    def premiumFetchCNCData(self):
        
        # endpoint = f"malware/{observable}"
        endpoint = "xfti/c2server/ipv4"
        response = self.apiCall(endpoint).json()

        result       = {}

        result["IP_List"]         = response["data"]
        result["indicatorCount"]  = response["IndicatorCount"]

        return result      
