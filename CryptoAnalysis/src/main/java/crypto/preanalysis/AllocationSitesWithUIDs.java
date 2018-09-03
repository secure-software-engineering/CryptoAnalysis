package crypto.preanalysis;

import boomerang.jimple.Statement;

public class AllocationSitesWithUIDs {

    private Statement allocationSiteForCallSite;
    private int callSiteUID;
    private String callSiteVariableName;
    private Statement allocationSiteForParameter;
    private int parameterUID;
    private String parameterVariableName;

    public AllocationSitesWithUIDs(Statement allocationSiteForCallSite, int callSiteUID, String callSiteVariableName, Statement allocationSiteForParameter, int parameterUID, String parameterVariableName) {
        this.allocationSiteForCallSite = allocationSiteForCallSite;
        this.callSiteUID = callSiteUID;
        this.allocationSiteForParameter = allocationSiteForParameter;
        this.parameterUID = parameterUID;
        this.callSiteVariableName = callSiteVariableName;
        this.parameterVariableName = parameterVariableName;
    }

    public Statement getAllocationSiteForCallSite() {
        return allocationSiteForCallSite;
    }

    public int getCallSiteUID() {
        return callSiteUID;
    }

    public Statement getAllocationSiteForParameter() {
        return allocationSiteForParameter;
    }

    public int getParameterUID() {
        return parameterUID;
    }

    public String getCallSiteVariableName() {
        return callSiteVariableName;
    }

    public String getParameterVariableName() {
        return parameterVariableName;
    }
}
