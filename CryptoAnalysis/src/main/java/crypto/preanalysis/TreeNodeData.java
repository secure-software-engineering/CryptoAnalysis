package crypto.preanalysis;

import crypto.analysis.ClassSpecification;
import soot.SootClass;

public class TreeNodeData {
    private SootClass sootClass;
    private ClassSpecification classSpecification;

    /**
     * @param sootClassParam
     * @param classSpecificationParam
     */
    public TreeNodeData(SootClass sootClassParam, ClassSpecification classSpecificationParam) {
        setSootClass(sootClassParam);
        setClassSpecification(classSpecificationParam);
    }

    /**
     * @return The soot class
     */
    public SootClass getSootClass() {
        return sootClass;
    }

    /**
     * @param sootClass
     */
    private void setSootClass(SootClass sootClass) {
        this.sootClass = sootClass;
    }

    /**
     * @return The class specification
     */
    public ClassSpecification getClassSpecification() {
        return classSpecification;
    }

    /**
     * @param classSpecification
     */
    private void setClassSpecification(ClassSpecification classSpecification) {
        this.classSpecification = classSpecification;
    }
}
