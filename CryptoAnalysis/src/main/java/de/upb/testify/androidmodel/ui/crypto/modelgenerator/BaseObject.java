package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.SootClassXmlAdapter;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.SootMethodXmlAdapter;
import de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml.StatementXmlAdapter;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import java.util.Collection;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import soot.SootClass;
import soot.SootMethod;

import boomerang.jimple.Statement;
import crypto.analysis.AnalysisSeedWithSpecification;

public class BaseObject {

  private static int ID_COUNTER = 0;

  private Statement allocationSite;
  private SootClass sootClass;
  private int id;
  private String rule;
  private Multimap<AnalysisSeedWithSpecification, BaseObject> params;
  private SootMethod method;

  /**
   * Used for serialization
   */
  protected BaseObject() {

  }

  public BaseObject(Statement allocationSite, String rule, SootClass sootClass, SootMethod method) {
    this.allocationSite = allocationSite;
    this.id = nextID();
    this.rule = rule;
    params = ArrayListMultimap.create();
    this.sootClass = sootClass;
    this.method = method;
  }

  private static int nextID() {
    return ID_COUNTER++;
  }

  protected void addParameter(AnalysisSeedWithSpecification paramsSeed, BaseObject baseObjectForSeed) {
    params.put(paramsSeed, baseObjectForSeed);
  }

  @XmlElement
  @XmlIDREF
  public Collection<BaseObject> getParameters() {
    return params.values();
  }

  @XmlElement
  @XmlJavaTypeAdapter(StatementXmlAdapter.class)
  public Statement getAllocationSite() {
    return allocationSite;
  }

  @XmlElement
  @XmlJavaTypeAdapter(SootClassXmlAdapter.class)
  public SootClass getSootClass() {
    return sootClass;
  }

  // Using ID to create a reference to the sub base objects.
  @XmlAttribute
  @XmlID
  public String getId() {
    return Integer.toString(id); // XML ID attribute requires the value to be string.
  }

  @XmlAttribute
  public String getRule() {
    return rule;
  }

  @XmlElement
  @XmlJavaTypeAdapter(SootMethodXmlAdapter.class)
  public SootMethod getMethod() {
    return method;
  }
}
