package crypto.preanalysis;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name = "BaseObjects")
//@XmlAccessorType(XmlAccessType.FIELD)
public class BaseObjects {

    //@XmlElement(name = "BaseObject")
    private List<BaseObject> listOfBaseObjects = null;

    public List<BaseObject> getBaseObjects() {
        return listOfBaseObjects;
    }

    public void setBaseObjects(List<BaseObject> baseObjects) {
        this.listOfBaseObjects = baseObjects;
    }
}
