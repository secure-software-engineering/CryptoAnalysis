package test;

import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.analysis.IAnalysisSeed;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.preanalysis.AllocationSitesWithUIDs;
import soot.SceneTransformer;
import soot.jimple.internal.JAssignStmt;
import test.core.selfrunning.ImprecisionException;

import java.util.*;

public class UIExtractionFrameworkBasedOnUPTF extends UsagePatternTestingFramework {

    @Override
    protected SceneTransformer createAnalysisTransformer() throws ImprecisionException {
        SceneTransformer transformerFromSuperClass = super.createAnalysisTransformer();

        /*List<IAnalysisSeed> listOfAnalysisSeeds = super.scanner.getListOfAnalysisSeeds();

        List<AllocationSitesWithUIDs> dataUIClassHierarchy = getHierarchyRelationshipData(listOfAnalysisSeeds);

        for (AllocationSitesWithUIDs allocationSitesWithUIDs : dataUIClassHierarchy) {
            System.out.println("callsite id : " + Integer.toString(allocationSitesWithUIDs.getCallSiteUID()) + " ; variable name : " + allocationSitesWithUIDs.getCallSiteVariableName() + " ; callsite : " + allocationSitesWithUIDs.getAllocationSiteForCallSite());
            System.out.println("allocationsite id : " + Integer.toString(allocationSitesWithUIDs.getParameterUID())  + " ; variable name : " + allocationSitesWithUIDs.getParameterVariableName()+ " ; allocationsite : " + allocationSitesWithUIDs.getAllocationSiteForParameter());
        }*/


        return transformerFromSuperClass;
    }

    private void writeDotFile(List<AllocationSitesWithUIDs> dataUIClassHierarchy){

        Map<String, String> nodes = new HashMap<>();
        Map<String, Map.Entry<String, String>> edges = new HashMap<>();

        for (AllocationSitesWithUIDs allocationSitesWithUIDs : dataUIClassHierarchy) {
            nodes.put(allocationSitesWithUIDs.getAllocationSiteForCallSite().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"","")
                    ,allocationSitesWithUIDs.getAllocationSiteForCallSite().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"",""));
            nodes.put(allocationSitesWithUIDs.getAllocationSiteForParameter().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"","")
                    ,allocationSitesWithUIDs.getAllocationSiteForParameter().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"",""));
            edges.put(allocationSitesWithUIDs.getAllocationSiteForCallSite().toString().replace(" ","_").replace("=","").replace("$","_")
                            + allocationSitesWithUIDs.getAllocationSiteForParameter().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"",""),
                    new AbstractMap.SimpleEntry<>(allocationSitesWithUIDs.getAllocationSiteForCallSite().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"","")
                            ,allocationSitesWithUIDs.getAllocationSiteForParameter().toString().replace(" ","_").replace("=","").replace("$","_").replace("\"","")));
        }


        StringBuilder builder = new StringBuilder();
        builder.append("digraph G { \n");
        builder.append(" rankdir=LR;\n");
        builder.append(" node[shape=box];\n");

        for (Map.Entry<String, String> stringStringEntry : nodes.entrySet()) {
            builder.append(stringStringEntry.getKey());
            builder.append(" ");
            builder.append("[label=\"");
            builder.append(stringStringEntry.getValue());
            builder.append("\"]");
            builder.append(";\n");
        }

        for (Map.Entry<String, Map.Entry<String, String>> stringEntryEntry : edges.entrySet()) {
            Map.Entry<String, String> single = stringEntryEntry.getValue();

            builder.append(single.getKey());
            builder.append(" -> ");
            builder.append(single.getValue());
            builder.append("[label=\"");
            builder.append(stringEntryEntry.getKey());
            builder.append("\"]");
            builder.append(";\n");
        }


        builder.append("}");
        System.out.println(builder.toString());
    }


    private List<AllocationSitesWithUIDs> getHierarchyRelationshipData(List<IAnalysisSeed> analysisSeeds){

        List<AllocationSitesWithUIDs> androidUIClassHierarchy = new ArrayList<>(); // parent, child

        for (IAnalysisSeed analysisSeed : analysisSeeds) {
            if (analysisSeed instanceof AnalysisSeedWithSpecification){
                for (Map.Entry<CallSiteWithParamIndex, ExtractedValue> entry : ((AnalysisSeedWithSpecification) analysisSeed).getParameterAnalysis().getCollectedValues().entries()) {
                    String callSiteVariableName = "";
                    String parameterVariableName = "";
                    if(analysisSeed.stmt().getUnit().get() instanceof JAssignStmt){
                        callSiteVariableName = ((JAssignStmt)analysisSeed.stmt().getUnit().get()).leftBox.getValue().toString();
                    }
                    if(entry.getValue().stmt().getUnit().get() instanceof JAssignStmt){
                        parameterVariableName = ((JAssignStmt) entry.getValue().stmt().getUnit().get()).leftBox.getValue().toString();
                    }


                    androidUIClassHierarchy.add(new AllocationSitesWithUIDs(analysisSeed.stmt(),analysisSeed.stmt().hashCode(),callSiteVariableName,entry.getValue().stmt(),entry.getValue().stmt().hashCode(),parameterVariableName));
                }

            }
        }
        writeDotFile(androidUIClassHierarchy);
        return androidUIClassHierarchy;
    }
}
