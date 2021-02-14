from core import plugin, model

class _ibmXforce(plugin._plugin):
    version = 0.3 

    def install(self):
        # Register models
        model.registerModel("xForcePremiumCnC","_xForcePremiumCnC","_action","plugins.ibmXforce.models.action")     
        model.registerModel("xForceGlpiEnrichment","_xForceGlpiEnrichment","_action","plugins.ibmXforce.models.action")
        model.registerModel("xForceReport","_xForceReport","_action","plugins.ibmXforce.models.action")
        model.registerModel("xForceGetUsage","_xForceGetUsage","_action","plugins.ibmXforce.models.action")
        
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("xForcePremiumCnC","_xForcePremiumCnC","_action","plugins.ibmXforce.models.action")     
        model.deregisterModel("xForceGlpiEnrichment","_xForceGlpiEnrichment","_action","plugins.ibmXforce.models.action")
        model.deregisterModel("xForceReport","_xForceReport","_trigger","plugins.ibmXforce.models.trigger")
        model.deregisterModel("xForceGetUsage","_xForceGetUsage","_action","plugins.ibmXforce.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        if self.version < 0.4:
            model.registerModel("xForcePremiumCnC","_xForcePremiumCnC","_action","plugins.ibmXforce.models.action")        
        if self.version < 0.3:
            model.registerModel("xForceGlpiEnrichment","_xForceGlpiEnrichment","_action","plugins.ibmXforce.models.action")
        if self.version < 0.2:
            model.registerModel("xForceReport","_xForceReport","_action","plugins.ibmXforce.models.action")
            model.registerModel("xForceGetUsage","_xForceGetUsage","_action","plugins.ibmXforce.models.action")

