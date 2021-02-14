import time

from core import db, audit

# # Initialize
dbCollectionName        = "xForce"
TICollectionName        = "xForceThreatIntel"

class _ibmXforce(db._document):
    observable = str()
    queryType  = str()
    # queryDate  = str()

    _dbCollection = db.db[dbCollectionName]

    def new(self, observable): #, queryType): #,queryDate):
        self.observable = observable
        # self.queryType = queryType
        # self.queryDate = queryDate

        return super(_ibmXforce, self).new()
    
    # def updateRecord(self, ip, up):
    #     audit._audit().add("xForce","history",{"endDate" : int(time.time())})    

class _ibmXforceThreatIntel(db._document):
    intelSource = dict()
    data        = list()
    queryDate   = str()
    _dbCollection = db.db[TICollectionName]

    def new(self, intelSource):
        self.intelSource = intelSource

        return super(_ibmXforceThreatIntel, self).new()
