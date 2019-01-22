package de.upb.testify.androidmodel.ui.crypto.modelgenerator.toXml;

import org.apache.commons.lang3.StringEscapeUtils;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class MethodCallAdapter extends XmlAdapter {
    @Override
    public Object unmarshal(Object v) throws Exception {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object marshal(Object v) throws Exception {
        return StringEscapeUtils.escapeXml10(v.toString());
    }
}
