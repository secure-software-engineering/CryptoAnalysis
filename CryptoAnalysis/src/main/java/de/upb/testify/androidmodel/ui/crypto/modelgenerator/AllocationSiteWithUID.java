package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import boomerang.jimple.Statement;

public class AllocationSiteWithUID {

    private Statement allocationSite;
    private int allocationSiteUID;
    private String allocationSiteVariableName;

    public AllocationSiteWithUID(Statement allocationSite, int allocationSiteUID, String allocationSiteVariableName) {
        this.allocationSite = allocationSite;
        this.allocationSiteUID = allocationSiteUID;
        this.allocationSiteVariableName = allocationSiteVariableName;
    }

    public Statement getAallocationSite() {
        return allocationSite;
    }

    public int getAllocationSiteUID() {
        return allocationSiteUID;
    }

    public String getAllocationSiteVariableName() {
        return allocationSiteVariableName;
    }

}
