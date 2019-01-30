package de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml;

import boomerang.jimple.Statement;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

public class StatementContents {
    private Statement statement;

    public StatementContents(Statement statement) {
        this.statement = statement;
    }

    @XmlElement
    public String getMethodString() {
        return  StringEscapeUtils.escapeXml10(statement.getMethod().getSignature());
    }

    @XmlElement
    public String getStatementString() {
        return  StringEscapeUtils.escapeXml10(statement.getUnit().toString());
    }
    @XmlAttribute
    public String getStatementToString() {
        return  StringEscapeUtils.escapeXml10(statement.toString());
    }
}
