package crypto.typestate;

import de.upb.testify.androidmodel.ui.crypto.modelgenerator.RuleTree;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import boomerang.WeightedForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import soot.RefType;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;

import boomerang.WeightedForwardQuery;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import crypto.analysis.ClassSpecification;
import crypto.analysis.CryptoScanner;
import typestate.TransitionFunction;
import typestate.finiteautomata.MatcherTransition;
import typestate.finiteautomata.State;
import typestate.finiteautomata.TypeStateMachineWeightFunctions;

public class FiniteStateMachineToTypestateChangeFunction extends TypeStateMachineWeightFunctions {

	private RefType analyzedType = null;

	private SootBasedStateMachineGraph fsm;

	public FiniteStateMachineToTypestateChangeFunction(SootBasedStateMachineGraph fsm) {
		for(MatcherTransition trans : fsm.getAllTransitions()){
			this.addTransition(trans);
		}
		for(SootMethod m : fsm.initialTransitonLabel()){
			if(m.isConstructor()){
				if (analyzedType == null){
					analyzedType = m.getDeclaringClass().getType();
				} else {
					// This code was added to detect unidentified outlying cases affected by the changes made for issue #47.
					if (analyzedType != m.getDeclaringClass().getType()){
                        try {
                            throw new Exception("The type of m.getDeclaringClass() does not appear to be consistent across fsm.initialTransitonLabel().");
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
				}
			}
		}
		this.fsm = fsm;
	}


	@Override
	public Collection<WeightedForwardQuery<TransitionFunction>> generateSeed(SootMethod method, Unit unit) {
		Set<WeightedForwardQuery<TransitionFunction>> out = new HashSet<>();
		if (!(unit instanceof Stmt) || !((Stmt) unit).containsInvokeExpr())
			return out;
		InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
		SootMethod calledMethod = invokeExpr.getMethod();
		if (!fsm.initialTransitonLabel().contains(calledMethod))
			return out;
		if (calledMethod.isStatic()) {
			if(unit instanceof AssignStmt){
				AssignStmt stmt = (AssignStmt) unit;
				out.add(createQuery(stmt,method,new AllocVal(stmt.getLeftOp(), method, stmt.getRightOp(), new Statement(stmt,method))));
			}
		} else if (invokeExpr instanceof InstanceInvokeExpr){
			InstanceInvokeExpr iie = (InstanceInvokeExpr) invokeExpr;
			out.add(createQuery(unit,method,new AllocVal(iie.getBase(), method,iie, new Statement((Stmt) unit,method))));
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

    /**
     * Overloaded method of the overridden generateSeed() method. The current class specification is required to identify
     * the valid rule for the given allocation site.
     * @param method
     * @param unit
     * @param optional
     * @param currentSpecification The specification that is currently under consideration in the CryptoScanner loop.
     * @return
     */
    /* The merge appears to have not removed this method.
    public Collection<WeightedForwardQuery<TransitionFunction>> generateSeed(SootMethod method, Unit unit, Collection<SootMethod> optional, ClassSpecification currentSpecification) {
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

          if (analyzedType.equals(type)
              // current specification can be null if the call to this method came from the overloaded method.
              || (currentSpecification != null
                  // Check if the class specification under consideration is the same as the valid one for the
                  // soot class under consideration.
                  && currentSpecification.equals(RuleTree.getRule(((RefType) type).getSootClass())))) {
                        AssignStmt stmt = (AssignStmt) unit;
                        out.add(createQuery(unit,method,new AllocVal(stmt.getLeftOp(), method, as.getRightOp(), new Statement(stmt, method))));
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
                out.add(createQuery(stmt,method,new AllocVal(stmt.getLeftOp(), method, stmt.getRightOp(), new Statement(stmt,method))));
            }
        } else if (invokeExpr instanceof InstanceInvokeExpr){
            InstanceInvokeExpr iie = (InstanceInvokeExpr) invokeExpr;
            out.add(createQuery(unit,method,new AllocVal(iie.getBase(), method,iie, new Statement((Stmt) unit,method))));
        }
        return out;
    }*/
}
