package de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml;

import javax.xml.bind.annotation.adapters.XmlAdapter;

import boomerang.jimple.Statement;
import org.apache.commons.lang3.StringEscapeUtils;

public class StatementXmlAdapter extends XmlAdapter<StatementContents, Statement> {

  @Override
  public Statement unmarshal(StatementContents statementContents) throws Exception {
    throw new UnsupportedOperationException();
  }

  @Override
  public StatementContents marshal(Statement statement) throws Exception {
    StatementContents contents = new StatementContents(statement);
    //return StringEscapeUtils.escapeXml10(v.toString());
    return contents;
  }
}
