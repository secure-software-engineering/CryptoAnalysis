package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.Multimaps;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlRootElement;

import soot.Scene;
import soot.SootClass;

import boomerang.jimple.Statement;
import crypto.Utils;
import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.rules.CryptSLRule;

@XmlRootElement(name = "ObjectModel")
// @XmlAccessorType(XmlAccessType.FIELD)
public class ObjectModel {

  private final Map<AnalysisSeedWithSpecification, BaseObject> baseObjects;

  public ObjectModel() {
    baseObjects = new HashMap<>();
  }

  public Collection<BaseObject> getObjects() {
    return baseObjects.values();
  }

  public void addObjectsBySeed(Collection<AnalysisSeedWithSpecification> analysisSeeds) {
    ImmutableListMultimap<Statement, AnalysisSeedWithSpecification> stmtToSeed
        = Multimaps.index(analysisSeeds, AnalysisSeedWithSpecification::stmt);
    for (AnalysisSeedWithSpecification analysisSeed : analysisSeeds) {
      baseObjectForSeed(analysisSeed, stmtToSeed);
    }
  }

  private BaseObject baseObjectForSeed(AnalysisSeedWithSpecification analysisSeed,
      ImmutableListMultimap<Statement, AnalysisSeedWithSpecification> stmtToSeed) {
    BaseObject result = baseObjects.get(analysisSeed);

    if (result != null) {
      return result;
    }

    CryptSLRule ruleFromAnalysisSeedParam = analysisSeed.getSpec().getRule();
    SootClass sootClassVarForAnalysisSeedParam
        = Scene.v().forceResolve(Utils.getFullyQualifiedName(ruleFromAnalysisSeedParam), SootClass.HIERARCHY);

    // The first parameter is the allocation site, 2nd is the unique id, and the third is the rule name.
    BaseObject baseObjectForSeed = new BaseObject(analysisSeed.stmt(), ruleFromAnalysisSeedParam.getClassName(),
        sootClassVarForAnalysisSeedParam, analysisSeed.stmt().getMethod());

    baseObjects.put(analysisSeed, baseObjectForSeed);

    // go through the parameters
    for (Map.Entry<CallSiteWithParamIndex, ExtractedValue> param : analysisSeed.getParameterAnalysis().getCollectedValues()
        .entries()) {

      for (AnalysisSeedWithSpecification paramsSeed : stmtToSeed.get(param.getValue().stmt())) {
        // Change the first parameter to the name of the type of parameter.
        baseObjectForSeed.getMapOfParameters().put(paramsSeed.toString(), baseObjectForSeed(paramsSeed, stmtToSeed));
      }
    }

    return baseObjectForSeed;
  }

  public void toXml(OutputStream out) throws JAXBException, IOException {
    try (OutputStreamWriter writer = new OutputStreamWriter(out)) {
      JAXBContext context = JAXBContext.newInstance(ObjectModel.class);
      Marshaller marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.marshal(this, writer);
    }
  }
}
