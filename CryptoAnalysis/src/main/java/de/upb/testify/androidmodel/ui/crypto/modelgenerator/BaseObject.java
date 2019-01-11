package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlRootElement;

import soot.SootClass;
import soot.SootMethod;

import boomerang.jimple.Statement;

@XmlRootElement(name = "BaseObject")
// @XmlAccessorType(XmlAccessType.FIELD)
public class BaseObject {

  private static int ID_COUNTER = 0;

  private Statement allocationSite;
  private SootClass sootClass;
  private int id;
  private String ruleName;
  private Multimap<String, BaseObject> mapOfParameters;
  private SootMethod method;

  public BaseObject(Statement allocationSite, String ruleName, SootClass sootClass, SootMethod method) {
    this.allocationSite = allocationSite;
    this.id = nextID();
    this.ruleName = ruleName;
    mapOfParameters = ArrayListMultimap.create();
    this.sootClass = sootClass;
    this.method = method;
  }

  // FIXME For testing
  public BaseObject(Statement allocationSite, String ruleName) {
    this.allocationSite = allocationSite;
    this.id = nextID();
    this.ruleName = ruleName;
    mapOfParameters = ArrayListMultimap.create();
  }

  private static int nextID() {
    return ID_COUNTER++;
  }

  // @XmlElement
  public Multimap<String, BaseObject> getMapOfParameters() {
    return mapOfParameters;
  }

  @XmlElement
  @XmlIDREF
  public List<BaseObject> getMapOfParametersForXMLBaseObject() {

    List<BaseObject> combinedList = new ArrayList<>();
    for (String s : mapOfParameters.keySet()) {

      for (Object o : mapOfParameters.get(s).toArray()) {
        if (o != null) {
          combinedList.add((BaseObject) o);
        }
      }

      // combinedList.addAll();
    }

    return combinedList;
  }

  /*
   * public void setMapOfParameters(Multimap<String, BaseObject> mapOfParameters) { this.mapOfParameters = mapOfParameters; }
   */

  public Statement getAllocationSite() {
    return allocationSite;
  }

  @XmlElement
  public String getAllocationSiteString() {
    return allocationSite.toString().replace("<", "").replace(">", "");
  }

  public SootClass getSootClass() {
    return sootClass;
  }

  @XmlAttribute
  public String getSootClassString() {
    return sootClass.toString();
  }

  // Using ID to create a reference to the sub base objects.
  @XmlAttribute
  @XmlID
  public String getId() {
    return Integer.toString(id); // XML ID attribute requires the value to be string.
  }

  @XmlAttribute
  public String getRuleName() {
    return ruleName;
  }

  // public getMapOfParametersString

  public String returnXMLNode() {
    StringWriter forString = new StringWriter();
    try {
      JAXBContext context = JAXBContext.newInstance(BaseObject.class);
      Marshaller marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.marshal(this, forString);
    } catch (JAXBException e) {
      e.printStackTrace();
    }
    return forString.toString();
  }

  @XmlAttribute
  public SootMethod getMethod() {
    return method;
  }
}
