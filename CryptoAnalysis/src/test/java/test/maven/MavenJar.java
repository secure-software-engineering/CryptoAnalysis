package test.maven;

import java.util.List;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

public class MavenJar {
	String groupId, artifactId, version;
	Table<String, Class<?>, Integer> errorTable;
	public static final String FP = "false_positive", TP =  "true_postive", FN = "false_negative";
	
	public MavenJar(String grpId, String artId, String ver) {
		groupId = grpId;
		artifactId = artId;
		version = ver;
		errorTable = HashBasedTable.create();
	}
	
	public void addErrors(String errorMethod, Class<?> errorType, List<String> errorDesc) {
		errorTable.put(errorMethod, errorType, errorDesc.size());
	}
}
