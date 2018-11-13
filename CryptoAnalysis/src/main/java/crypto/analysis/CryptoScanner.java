package crypto.analysis;

import java.io.StringWriter;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;

import boomerang.Query;
import boomerang.debugger.Debugger;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.Utils;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.preanalysis.*;
import crypto.predicates.PredicateHandler;
import crypto.rules.CryptSLRule;
import crypto.typestate.CryptSLMethodToSootMethod;
import heros.utilities.DefaultValueMap;
import ideal.IDEALSeedSolver;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import sync.pds.solver.nodes.Node;
import typestate.TransitionFunction;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

public abstract class CryptoScanner {

	public static boolean APPLICATION_CLASS_SEEDS_ONLY = false;
	private final LinkedList<IAnalysisSeed> worklist = Lists.newLinkedList();
	private final List<ClassSpecification> specifications = Lists.newLinkedList();
	private final PredicateHandler predicateHandler = new PredicateHandler(this);
	private CrySLResultsReporter resultsAggregator = new CrySLResultsReporter();
	private Map<IAnalysisSeed, BaseObject> mapOfBaseObjects;
	private int counterForIDs;
    private List<IAnalysisSeed> listOfAnalysisSeeds;

	

	private DefaultValueMap<Node<Statement,Val>, AnalysisSeedWithEnsuredPredicate> seedsWithoutSpec = new DefaultValueMap<Node<Statement,Val>, AnalysisSeedWithEnsuredPredicate>() {

		@Override
		protected AnalysisSeedWithEnsuredPredicate createItem(Node<Statement,Val> key) {
			return new AnalysisSeedWithEnsuredPredicate(CryptoScanner.this, key);
		}
	};
	private DefaultValueMap<AnalysisSeedWithSpecification, AnalysisSeedWithSpecification> seedsWithSpec = new DefaultValueMap<AnalysisSeedWithSpecification, AnalysisSeedWithSpecification>() {

		@Override
		protected AnalysisSeedWithSpecification createItem(AnalysisSeedWithSpecification key) {
			return new AnalysisSeedWithSpecification(CryptoScanner.this, key.stmt(),key.var(), key.getSpec());
		}
	};
	private int solvedObject;
	private Stopwatch analysisWatch;

	public abstract BiDiInterproceduralCFG<Unit, SootMethod> icfg();

	public CrySLResultsReporter getAnalysisListener() {
		return resultsAggregator;
	};

	public abstract boolean isCommandLineMode();


	public CryptoScanner(List<CryptSLRule> specs) {
		CryptSLMethodToSootMethod.reset();
		for (CryptSLRule rule : specs) {
			specifications.add(new ClassSpecification(rule, this));
		}
	}

	


	public void scan() {
		getAnalysisListener().beforeAnalysis();
		analysisWatch = Stopwatch.createStarted();
		initialize();
		long elapsed = analysisWatch.elapsed(TimeUnit.SECONDS);
		System.out.println("Discovered "+worklist.size() + " analysis seeds within " + elapsed + " seconds!");

		//List<AllocationSitesWithUIDs> dataForUIClassHeirarchy = new ArrayList<>();
		listOfAnalysisSeeds = new ArrayList<>();
		while (!worklist.isEmpty()) {
			IAnalysisSeed curr = worklist.poll();
            listOfAnalysisSeeds.add(curr);
			getAnalysisListener().discoveredSeed(curr);
			curr.execute();
			estimateAnalysisTime();
		}

        mapOfBaseObjects = new HashMap<>();
		counterForIDs = 0;

        for (IAnalysisSeed analysisSeed : listOfAnalysisSeeds) {
            BaseObject baseObjectForSeed = baseObjectForSeed(analysisSeed);
			//counterForIDs = counterForIDs + 1;
            //mapOfBaseObjects.put(analysisSeed, new BaseObject(analysisSeed.stmt(), counterForIDs, ""));

        }
        
		
        /*List<AllocationSitesWithUIDs> dataUIClassHierarchy = getHierarchyRelationshipData(listOfAnalysisSeeds);

		for (AllocationSitesWithUIDs allocationSitesWithUIDs : dataUIClassHierarchy) {
			System.out.println("callsite id : " + Integer.toString(allocationSitesWithUIDs.getCallSiteUID()) + " ; variable name : " + allocationSitesWithUIDs.getCallSiteVariableName() + " ; callsite : " + allocationSitesWithUIDs.getAllocationSiteForCallSite());
			System.out.println("allocationsite id : " + Integer.toString(allocationSitesWithUIDs.getParameterUID())  + " ; variable name : " + allocationSitesWithUIDs.getParameterVariableName()+ " ; allocationsite : " + allocationSitesWithUIDs.getAllocationSiteForParameter());
		}*/

//		IDebugger<TypestateDomainValue<StateNode>> debugger = debugger();
//		if (debugger instanceof CryptoVizDebugger) {
//			CryptoVizDebugger ideVizDebugger = (CryptoVizDebugger) debugger;
//			ideVizDebugger.addEnsuredPredicates(this.existingPredicates);
//		}

        BaseObjects baseObjects = new BaseObjects();
        baseObjects.setBaseObjects(new ArrayList<>());
        for (BaseObject value : mapOfBaseObjects.values()) {
            baseObjects.getBaseObjects().add(value);
        }


        //baseObjects.setBaseObjects((List)mapOfBaseObjects.values());

        StringWriter forString = new StringWriter();
        try {
            JAXBContext context = JAXBContext.newInstance(BaseObjects.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(baseObjects, forString);
        } catch (JAXBException e) {
            e.printStackTrace();
        }


        System.out.println(forString.toString());

       /* for (Object o : mapOfBaseObjects.keySet().toArray()) {
            System.out.println(mapOfBaseObjects.get(o).returnXMLNode());
        }*/


        //System.out.println(mapOfBaseObjects.get(mapOfBaseObjects.keySet().toArray()[0]).returnXMLNode());
		predicateHandler.checkPredicates();
		
		getAnalysisListener().afterAnalysis();
		elapsed = analysisWatch.elapsed(TimeUnit.SECONDS);
		System.out.println("Static Analysis took "+elapsed+ " seconds!");
//		debugger().afterAnalysis();
	}



    // should the param here be alloc site?
	private BaseObject baseObjectForSeed(IAnalysisSeed analysisSeedParam){
        if(mapOfBaseObjects.containsKey(analysisSeedParam)){
            return mapOfBaseObjects.get(analysisSeedParam);
        } else{
            // unique ids for each new base object.
            counterForIDs = counterForIDs + 1;

            CryptSLRule ruleFromAnalysisSeedParam = ((AnalysisSeedWithSpecification) analysisSeedParam).getSpec().getRule();
            SootClass sootClassVarForAnalysisSeedParam = Scene.v().forceResolve(Utils.getFullyQualifiedName(ruleFromAnalysisSeedParam), SootClass.HIERARCHY);
            // The first parameter is the allocation site, 2nd is the unique id, and the third is the rule name.
            BaseObject tmpBaseObject = new BaseObject(analysisSeedParam.stmt(), counterForIDs, ruleFromAnalysisSeedParam.getClassName(), sootClassVarForAnalysisSeedParam, analysisSeedParam.stmt().getMethod().toString().replace("<","").replace(">",""));
            //BaseObject tmpBaseObject = new BaseObject(analysisSeedParam.stmt(), counterForIDs, analysisSeedParam.toString());
			mapOfBaseObjects.put(analysisSeedParam, tmpBaseObject);
            // go through the parameters
            if (analysisSeedParam instanceof AnalysisSeedWithSpecification){
                for (Map.Entry<CallSiteWithParamIndex, ExtractedValue> entry : ((AnalysisSeedWithSpecification) analysisSeedParam).getParameterAnalysis().getCollectedValues().entries()) {
                    for (IAnalysisSeed analysisSeed : listOfAnalysisSeeds) {
                        if (analysisSeed.stmt().equals(entry.getValue().stmt())){
                            /*if (mapOfBaseObjects.containsKey(analysisSeed)){

                            }*/
                            // Change the first parameter to the name of the type of parameter.
                            mapOfBaseObjects.get(analysisSeedParam).getMapOfParameters().put(analysisSeed.toString(),baseObjectForSeed(analysisSeed));
                            //tmpBaseObject.getMapOfParameters().put(analysisSeed.toString(),baseObjectForSeed(analysisSeed));
                        }
                    }


                    

                }
            }


            // call baseObjectForSeed for each parameter pass alloc site
            // add base object to the map

        }
        return null;
    }
	/*private void writeDotFile(List<AllocationSitesWithUIDs> dataUIClassHierarchy){

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

    public Map<Integer, TreeNode<AllocationSiteWithUID>> createXMLFile(List<AllocationSitesWithUIDs> dataUIClassHierarchy){


		// The set of allocation sites with a custom assigned UID.
		Map<Integer, TreeNode<AllocationSiteWithUID>> mapOfAllocationSites = new HashMap<>();


		int count = 0;
		// Get all of the unique allocation sites.
		for (AllocationSitesWithUIDs alloc : dataUIClassHierarchy) {

            if (!mapOfAllocationSites.keySet().contains(alloc.getCallSite().getAllocationSiteUID())){

				mapOfAllocationSites.put(alloc.getCallSite().getAllocationSiteUID(), new TreeNode<>(alloc.getCallSite()));
			}
			if (!mapOfAllocationSites.keySet().contains(alloc.getParameterAllocSite().getAllocationSiteUID())){
				mapOfAllocationSites.put(alloc.getParameterAllocSite().getAllocationSiteUID(), new TreeNode<>(alloc.getParameterAllocSite()));
			}
		}

		for (AllocationSitesWithUIDs alloc : dataUIClassHierarchy) {
			if (mapOfAllocationSites.containsKey(alloc.getCallSite().getAllocationSiteUID())){
				mapOfAllocationSites.get(alloc.getCallSite().getAllocationSiteUID()).addChild(alloc.getParameterAllocSite());
			}
		}

		return mapOfAllocationSites;


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
		createXMLFile(androidUIClassHierarchy);
        return androidUIClassHierarchy;
    }*/

	private void estimateAnalysisTime() {
		int remaining = worklist.size();
		solvedObject++;
		if(remaining != 0) {
			Duration elapsed = analysisWatch.elapsed();
			Duration estimate = elapsed.dividedBy(solvedObject);
			Duration remainingTime = estimate.multipliedBy(remaining);
			System.out.println(String.format("Analysis Time: %s", elapsed));
			System.out.println(String.format("Estimated Time: %s", remainingTime));
			System.out.println(String.format("Analyzed Objects: %s of %s", solvedObject, remaining + solvedObject));
			System.out.println(String.format("Percentage Completed: %s\n", ((float)Math.round((float)solvedObject*100 / (remaining + solvedObject)))/100));
		}
	}

	private void initialize() {
        // This tree is required to identify the correct valid rule for a given soot class.
        RuleTree.createTree(specifications);
		for (ClassSpecification spec : getClassSpecifictions()) {
			spec.checkForForbiddenMethods();
			if (!isCommandLineMode() && !spec.isLeafRule())
				continue;

			for (Query seed : spec.getInitialSeeds()) {
				if(!spec.getRule().getClassName().equals("javax.crypto.SecretKey")) {
					getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(this, seed.stmt(),seed.var(),spec));
				}
			}
		}
	}

	public List<ClassSpecification> getClassSpecifictions() {
		return specifications;
	}

	protected void addToWorkList(IAnalysisSeed analysisSeedWithSpecification) {
		worklist.add(analysisSeedWithSpecification);
	}

	public AnalysisSeedWithEnsuredPredicate getOrCreateSeed(Node<Statement,Val> factAtStatement) {
		boolean addToWorklist = false;
		if (!seedsWithoutSpec.containsKey(factAtStatement))
			addToWorklist = true;

		AnalysisSeedWithEnsuredPredicate seed = seedsWithoutSpec.getOrCreate(factAtStatement);
		if (addToWorklist)
			addToWorkList(seed);
		return seed;
	}

	public AnalysisSeedWithSpecification getOrCreateSeedWithSpec(AnalysisSeedWithSpecification factAtStatement) {
		boolean addToWorklist = false;
		if (!seedsWithSpec.containsKey(factAtStatement))
			addToWorklist = true;
		AnalysisSeedWithSpecification seed = seedsWithSpec.getOrCreate(factAtStatement);
		if (addToWorklist)
			addToWorkList(seed);
		return seed;
	}


	
	public Debugger<TransitionFunction> debugger(IDEALSeedSolver<TransitionFunction> solver, IAnalysisSeed analyzedObject) {
		return new Debugger<>();
	}

	public PredicateHandler getPredicateHandler() {
		return predicateHandler;
	}

	public Collection<AnalysisSeedWithSpecification> getAnalysisSeeds() {
		return this.seedsWithSpec.values();
	}
}
