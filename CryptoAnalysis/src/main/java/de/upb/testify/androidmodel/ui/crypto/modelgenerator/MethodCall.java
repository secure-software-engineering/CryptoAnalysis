package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import boomerang.jimple.Statement;
import crypto.analysis.AnalysisSeedWithSpecification;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.StatementXmlAdapter;
import de.upb.testify.soot.IMethodContainer;
import soot.SootMethod;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class MethodCall implements IMethodContainer {

    private Statement callSite;
    private Map<AnalysisSeedWithSpecification, BaseObject> params;

    // For serialization.
    public MethodCall() {
    }

    public MethodCall(Statement callSite) {
        this.callSite = callSite;
        this.params = new HashMap<>();
    }
    @XmlElement
    @XmlJavaTypeAdapter(StatementXmlAdapter.class)
    public Statement getCallSite() {
        return callSite;
    }

    public Map<AnalysisSeedWithSpecification, BaseObject> getParams() {
        return params;
    }

    protected void addParameter(AnalysisSeedWithSpecification paramsSeed, BaseObject baseObjectForSeed) {
        // TODO params need to have an index telling their position in a call
        // TODO also, parameters should be bound to methods and a base object can have more than one method call right?
        params.put(paramsSeed, baseObjectForSeed);
    }

    @XmlElement
    @XmlIDREF
    public Collection<BaseObject> getParameters() {
        return params.values();
    }

    @Override
    public SootMethod getMethod() {
        return callSite.getMethod();
    }
}
