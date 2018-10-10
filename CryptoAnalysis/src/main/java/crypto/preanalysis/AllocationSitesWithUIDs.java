package crypto.preanalysis;

import boomerang.jimple.Statement;

public class AllocationSitesWithUIDs {


    private AllocationSiteWithUID callSite;
    private AllocationSiteWithUID parameterAllocSite;

    /*private Statement allocationSiteForCallSite;
    private int callSiteUID;
    private String callSiteVariableName;
    private Statement allocationSiteForParameter;
    private int parameterUID;
    private String parameterVariableName;*/

    public AllocationSitesWithUIDs(Statement allocationSiteForCallSite, int callSiteUID, String callSiteVariableName, Statement allocationSiteForParameter, int parameterUID, String parameterVariableName) {
        this.callSite = new AllocationSiteWithUID(allocationSiteForCallSite, callSiteUID, callSiteVariableName);
        this.parameterAllocSite = new AllocationSiteWithUID(allocationSiteForParameter, parameterUID, parameterVariableName);

        /*this.allocationSiteForCallSite = allocationSiteForCallSite;
        this.callSiteUID = callSiteUID;
        this.allocationSiteForParameter = allocationSiteForParameter;
        this.parameterUID = parameterUID;
        this.callSiteVariableName = callSiteVariableName;
        this.parameterVariableName = parameterVariableName;*/
    }

    public Statement getAllocationSiteForCallSite() {
        return callSite.getAallocationSite();
    }

    public int getCallSiteUID() {
        return callSite.getAllocationSiteUID();
    }

    public String getCallSiteVariableName() {
        return callSite.getAllocationSiteVariableName();
    }

    public Statement getAllocationSiteForParameter() {
        return parameterAllocSite.getAallocationSite();
    }

    public int getParameterUID() {
        return parameterAllocSite.getAllocationSiteUID();
    }

    public String getParameterVariableName() {
        return parameterAllocSite.getAllocationSiteVariableName();
    }

    public AllocationSiteWithUID getCallSite() {
        return callSite;
    }

    public AllocationSiteWithUID getParameterAllocSite() {
        return parameterAllocSite;
    }
}
