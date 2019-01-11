package test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.Lists;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;

import crypto.rules.CryptSLMethod;
import crypto.rules.CryptSLRule;
import crypto.rules.StateMachineGraph;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import test.assertions.Assertions;

public class MockedUsagePatternTestingFramework extends UsagePatternTestingFramework {
    private String[] classesToMock;
    @Override
  protected List<CryptSLRule> getRules(boolean srcFormat) {

        if (getClassesToMock() == null){
      return super.getRules(srcFormat);
        }
        List<CryptSLRule> listOfMockedRules = Lists.newArrayList();

        for (String className : getClassesToMock()) {
            listOfMockedRules.add(getMockedRule(className));
        }

        return listOfMockedRules;
    }

    /**
     * Generate a mocked class for the given class name. mockito used for mocking.
     * @param className
     * @return The mocked class
     */
    private CryptSLRule getMockedRule(String className){
        // Mocked class
        CryptSLRule mockedRule = mock(CryptSLRule.class);
        // State machine graph is required to get the method name from the initial transition, creating a valid graph to
        // allow the creation of a class specification.
        StateMachineGraph smg = new StateMachineGraph();
        StateNode initNode = new StateNode("-1",true,false);
        smg.addNode(initNode);
        StateNode secondNode = new StateNode("0", false,true);
        smg.addNode(secondNode);
        // A list of methods is required to be passed to the edge.
        CryptSLMethod mockedCryptSLMethod = mock(CryptSLMethod.class);
        List<CryptSLMethod> listOfMethods = new ArrayList<>();
        listOfMethods.add(mockedCryptSLMethod);
        // Name of the method that will be mocked. wait() should always be available.
        when(mockedCryptSLMethod.getMethodName()).thenReturn(className + ".wait()");
        smg.addEdge(new TransitionEdge(listOfMethods,initNode,secondNode));
        // The usage pattern that will be mocked.
        when(mockedRule.getUsagePattern()).thenReturn(smg);
        // For debugging
        when(mockedRule.getClassName()).thenReturn(className);

        return mockedRule;
    }

    @Override
    protected void extractBenchmarkMethods(SootMethod m, Set<Assertion> queries, Set<SootMethod> visited){
        if (!m.hasActiveBody() || visited.contains(m))
            return;
        visited.add(m);
        Body activeBody = m.getActiveBody();

        for (Unit u : activeBody.getUnits()) {
            if (!(u instanceof Stmt))
                continue;

            Stmt stmt = (Stmt) u;
            if (!(stmt.containsInvokeExpr()))
                continue;
            InvokeExpr invokeExpr = stmt.getInvokeExpr();
            if (!invokeExpr.getMethod().getDeclaringClass().toString().equals(Assertions.class.getName()))
                continue;

            String invocationName = invokeExpr.getMethod().getName();
            if(invocationName.startsWith("classesToMock")){
                Value param = invokeExpr.getArg(0);
                if (!(param instanceof StringConstant))
                    continue;
                StringConstant classesToMock = (StringConstant) param;
                setClassesToMock(classesToMock.value.replace(" ","").split(","));
            }
        }
    }

    /**
     * @return The list of classes from the benchmark method to be mocked
     */
    public String[] getClassesToMock() {
        return classesToMock;
    }

    /**
     * @param classesToMock List of classes from the benchmark method to be mocked
     */
    public void setClassesToMock(String[] classesToMock) {
        this.classesToMock = classesToMock;
    }
}
