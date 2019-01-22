package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import boomerang.jimple.Statement;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import crypto.analysis.AnalysisSeedWithSpecification;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.MethodCallAdapter;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.StatementXmlAdapter;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Collection;

public class MethodCall {

    private Statement callSite;
    private Multimap<AnalysisSeedWithSpecification, BaseObject> params;

    // For serialization.
    public MethodCall() {
    }

    public MethodCall(Statement callSite) {
        this.callSite = callSite;
        this.params = ArrayListMultimap.create();
    }
    @XmlElement
    @XmlJavaTypeAdapter(StatementXmlAdapter.class)
    public Statement getCallSite() {
        return callSite;
    }

    public Multimap<AnalysisSeedWithSpecification, BaseObject> getParams() {
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
}
