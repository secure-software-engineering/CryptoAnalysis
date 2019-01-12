package crypto.analysis;

import de.upb.testify.androidmodel.ui.crypto.modelgenerator.ObjectModel;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.RuleTree;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;

import heros.utilities.DefaultValueMap;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.xml.bind.JAXBException;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;

import boomerang.Query;
import boomerang.debugger.Debugger;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.predicates.PredicateHandler;
import crypto.rules.CryptSLRule;
import crypto.typestate.CryptSLMethodToSootMethod;
import ideal.IDEALSeedSolver;
import sync.pds.solver.nodes.Node;
import typestate.TransitionFunction;

public abstract class CryptoScanner {

	public static boolean APPLICATION_CLASS_SEEDS_ONLY = false;
	private final LinkedList<IAnalysisSeed> worklist = Lists.newLinkedList();
	private final List<ClassSpecification> specifications = Lists.newLinkedList();
	private final PredicateHandler predicateHandler = new PredicateHandler(this);
	private CrySLResultsReporter resultsAggregator = new CrySLResultsReporter();

	private DefaultValueMap<Node<Statement, Val>, AnalysisSeedWithEnsuredPredicate> seedsWithoutSpec = new DefaultValueMap<Node<Statement, Val>, AnalysisSeedWithEnsuredPredicate>() {

		@Override
		protected AnalysisSeedWithEnsuredPredicate createItem(Node<Statement, Val> key) {
			return new AnalysisSeedWithEnsuredPredicate(CryptoScanner.this, key);
		}
	};
	private DefaultValueMap<AnalysisSeedWithSpecification, AnalysisSeedWithSpecification> seedsWithSpec = new DefaultValueMap<AnalysisSeedWithSpecification, AnalysisSeedWithSpecification>() {

		@Override
		protected AnalysisSeedWithSpecification createItem(AnalysisSeedWithSpecification key) {
			return new AnalysisSeedWithSpecification(CryptoScanner.this, key.stmt(), key.var(), key.getSpec());
		}
	};
	private int solvedObject;
	private Stopwatch analysisWatch;

	public abstract BiDiInterproceduralCFG<Unit, SootMethod> icfg();

	public CrySLResultsReporter getAnalysisListener() {
		return resultsAggregator;
  }

  public abstract boolean isCommandLineMode();

	public abstract boolean rulesInSrcFormat();

	public CryptoScanner() {
		CryptSLMethodToSootMethod.reset();
	}

	public void scan(List<CryptSLRule> specs) {

		for (CryptSLRule rule : specs) {
			specifications.add(new ClassSpecification(rule, this));
		}
		getAnalysisListener().beforeAnalysis();
		analysisWatch = Stopwatch.createStarted();
		initialize();
		long elapsed = analysisWatch.elapsed(TimeUnit.SECONDS);
		System.out.println("Discovered " + worklist.size() + " analysis seeds within " + elapsed + " seconds!");

		//List<AllocationSitesWithUIDs> dataForUIClassHeirarchy = new ArrayList<>();
		while (!worklist.isEmpty()) {
			IAnalysisSeed curr = worklist.poll();
			getAnalysisListener().discoveredSeed(curr);
			curr.execute();
			estimateAnalysisTime();
		}

    ObjectModel objectModel = new ObjectModel();
    objectModel.addObjectsBySeed(getAnalysisSeeds());
    try {
      objectModel.toXml(System.out);
    } catch (JAXBException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
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



        //baseObjects.setBaseObjects((List)mapOfBaseObjects.values());


       /* for (Object o : mapOfBaseObjects.keySet().toArray()) {
            System.out.println(mapOfBaseObjects.get(o).returnXMLNode());
        }*/


        //System.out.println(mapOfBaseObjects.get(mapOfBaseObjects.keySet().toArray()[0]).returnXMLNode());
		predicateHandler.checkPredicates();

		getAnalysisListener().afterAnalysis();
		elapsed = analysisWatch.elapsed(TimeUnit.SECONDS);
		System.out.println("Static Analysis took " + elapsed + " seconds!");
//		debugger().afterAnalysis();
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
		if (remaining != 0) {
//			Duration elapsed = analysisWatch.elapsed();
//			Duration estimate = elapsed.dividedBy(solvedObject);
//			Duration remainingTime = estimate.multipliedBy(remaining);
//			System.out.println(String.format("Analysis Time: %s", elapsed));
//			System.out.println(String.format("Estimated Time: %s", remainingTime));
			System.out.println(String.format("Analyzed Objects: %s of %s", solvedObject, remaining + solvedObject));
			System.out.println(String.format("Percentage Completed: %s\n",
					((float) Math.round((float) solvedObject * 100 / (remaining + solvedObject))) / 100));
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
				if (!spec.getRule().getClassName().equals("javax.crypto.SecretKey")) {
					getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(this, seed.stmt(), seed.var(), spec));
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

	public Debugger<TransitionFunction> debugger(IDEALSeedSolver<TransitionFunction> solver,
			IAnalysisSeed analyzedObject) {
		return new Debugger<>();
	}

	public PredicateHandler getPredicateHandler() {
		return predicateHandler;
	}

	public Collection<AnalysisSeedWithSpecification> getAnalysisSeeds() {
		return this.seedsWithSpec.values();
	}
}
