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

  @XmlElement
  @XmlJavaTypeAdapter(StatementXmlAdapter.class)
  public Statement getAllocationSite() {
    return allocationSite;
  }

  // TODO manuel: As far as I understand, method,class and params belong to a call on this BaseObject
  // There should really be another class for methodcalls which the BaseObject has a list of. This class should than
  // reference the called method and its parameters. class does not need to be saved separately, since the method already
  // know the class it belongs to

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

  @XmlElement
  @XmlJavaTypeAdapter(SootClassXmlAdapter.class)
  public SootClass getSootClass() {
    return sootClass;
  }

  @XmlElement
  @XmlJavaTypeAdapter(SootMethodXmlAdapter.class)
  public SootMethod getMethod() {
    return method;
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
}
