package crypto.typestate;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Sets;

import boomerang.WeightedForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import crypto.analysis.CryptoScanner;
import crypto.rules.CryptSLMethod;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.NewExpr;
import soot.jimple.Stmt;
import sync.pds.solver.nodes.Node;
import typestate.TransitionFunction;
import typestate.finiteautomata.ITransition;
import typestate.finiteautomata.MatcherTransition;
import typestate.finiteautomata.State;
import typestate.finiteautomata.TypeStateMachineWeightFunctions;

public class FiniteStateMachineToTypestateChangeFunction extends TypeStateMachineWeightFunctions {

	private Collection<RefType> analyzedType = Sets.newHashSet();

	private SootBasedStateMachineGraph fsm;

	public FiniteStateMachineToTypestateChangeFunction(SootBasedStateMachineGraph fsm) {
		for(MatcherTransition trans : fsm.getAllTransitions()){
			this.addTransition(trans);
		}
		for(SootMethod m : fsm.initialTransitonLabel()){
			if(m.isConstructor()){
				analyzedType.add(m.getDeclaringClass().getType());
			}
		}
		this.fsm = fsm;
	}


	@Override
	public Collection<WeightedForwardQuery<TransitionFunction>> generateSeed(SootMethod method, Unit unit, Collection<SootMethod> optional) {
		Set<WeightedForwardQuery<TransitionFunction>> out = new HashSet<>();
		if(CryptoScanner.APPLICATION_CLASS_SEEDS_ONLY && !method.getDeclaringClass().isApplicationClass()){
			return out;
		}
		if(fsm.seedIsConstructor()){
			if(unit instanceof AssignStmt){
				AssignStmt as = (AssignStmt) unit;
				if(as.getRightOp() instanceof NewExpr){
					NewExpr newExpr = (NewExpr) as.getRightOp();
					Type type = newExpr.getType();
					// check if there is an immediate super class.
                    //if(analyzedType.contains(type) || analyzedType.contains(((RefType)type).getSootClass().getSuperclass().getType())){
					if(analyzedType.contains(type)){
						AssignStmt stmt = (AssignStmt) unit;
						out.add(createQuery(unit,method,new AllocVal(stmt.getLeftOp(), method, as.getRightOp())));
					}
                    for (RefType refType : analyzedType) {
					    // it seems classes are sub-classes to themselves
                        if(!(refType.getSootClass().equals(((RefType)type).getSootClass())) &&  Scene.v().getFastHierarchy().isSubclass(((RefType)type).getSootClass(),refType.getSootClass())){
                            //generate the current statement as a seed, because you want to track this object.
                            AssignStmt stmt = (AssignStmt) unit;
                            out.add(createQuery(unit,method,new AllocVal(stmt.getLeftOp(), method, as.getRightOp())));
                        }
                    }

                }
			}
		}
		if (!(unit instanceof Stmt) || !((Stmt) unit).containsInvokeExpr())
			return out;
		InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
		SootMethod calledMethod = invokeExpr.getMethod();
		if (!fsm.initialTransitonLabel().contains(calledMethod) || calledMethod.isConstructor())
			return out;
		if (calledMethod.isStatic()) {
			if(unit instanceof AssignStmt){
				AssignStmt stmt = (AssignStmt) unit;
				out.add(createQuery(stmt,method,new AllocVal(stmt.getLeftOp(), method, stmt.getRightOp())));
			}
		} else if (invokeExpr instanceof InstanceInvokeExpr){
			InstanceInvokeExpr iie = (InstanceInvokeExpr) invokeExpr;
			out.add(createQuery(unit,method,new AllocVal(iie.getBase(), method,iie)));
		}
		return out;
	}

	private WeightedForwardQuery<TransitionFunction> createQuery(Unit unit, SootMethod method, AllocVal allocVal) {
		return new WeightedForwardQuery<TransitionFunction>(new Statement((Stmt)unit,method), allocVal, fsm.getInitialWeight(new Statement((Stmt)unit,method)));
	}


	@Override
	protected State initialState() {
		throw new RuntimeException("Should never be called!");
	}
	
	
}
