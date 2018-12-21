package crypto.preanalysis;

import boomerang.jimple.Statement;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import soot.SootClass;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.*;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;


@XmlRootElement(name = "BaseObject")
//@XmlAccessorType(XmlAccessType.FIELD)
public class BaseObject {

    // allocation site
    private Statement allocationSite;
    // soot class
    private SootClass sootClass;
    // id
    private int id;
    // rule name
    private String ruleName;

    // map of parameters
    private Multimap<String, BaseObject> mapOfParameters;

    // name of the method
    private String methodName;
    // default constructor required for the xml conversion
    public BaseObject() {
    }

    public BaseObject(Statement allocationSite, int id, String ruleName, SootClass sootClass, String methodName) {
        this.allocationSite = allocationSite;
        this.id = id;
        this.ruleName = ruleName;
        mapOfParameters = ArrayListMultimap.create();
        this.sootClass = sootClass;
        this.methodName = methodName;
    }
    // For testing
    public BaseObject(Statement allocationSite, int id, String ruleName) {
        this.allocationSite = allocationSite;
        this.id = id;
        this.ruleName = ruleName;
        mapOfParameters = ArrayListMultimap.create();
    }

    //@XmlElement
    public Multimap<String, BaseObject> getMapOfParameters() {
        return mapOfParameters;
    }

    @XmlElement
    @XmlIDREF
    public List<BaseObject> getMapOfParametersForXMLBaseObject() {

        List<BaseObject> combinedList = new ArrayList<>();
        for (String s : mapOfParameters.keySet()) {

            for (Object o : mapOfParameters.get(s).toArray()) {
                if (o != null){
                    combinedList.add((BaseObject)o);
                }
            }


            //combinedList.addAll();
        }


        return combinedList;
    }

    /*public void setMapOfParameters(Multimap<String, BaseObject> mapOfParameters) {
        this.mapOfParameters = mapOfParameters;
    }*/


    public Statement getAllocationSite() {
        return allocationSite;
    }
    @XmlElement
    public String getAllocationSiteString(){
        return allocationSite.toString().replace("<","").replace(">","");
    }

    public SootClass getSootClass() {
        return sootClass;
    }
    @XmlAttribute
    public String getSootClassString(){
        return sootClass.toString();
    }
    // Using ID to create a reference to the sub base objects.
    @XmlAttribute
    @XmlID
    public String getId() {
        return Integer.toString(id); //XML ID attribute requires the value to be string.
    }
    @XmlAttribute
    public String getRuleName() {
        return ruleName;
    }

    //public getMapOfParametersString

    public String returnXMLNode(){
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
    public String getMethodName() {
        return methodName;
    }
}
