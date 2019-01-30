package de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml;

import org.apache.commons.lang3.StringEscapeUtils;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class StatementContentAdapter extends XmlAdapter {
    @Override
    public Object unmarshal(Object o) throws Exception {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object marshal(Object o) throws Exception {
        return StringEscapeUtils.escapeXml10(o.toString());
    }
}
