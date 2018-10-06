package test.maven;

import java.util.List;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

public class MavenJar {
	String groupId, artifactId, version;
	Table<String, Class<?>, Integer> errorTable;
	public static enum findingType {
		TRUE_POSITIVE {
			public String toString() {
				return "TruePositive";
			}
		},
		FALSE_POSITIVE {
			public String toString() {
				return "FalsePositive";
			}
		},
		FALSE_NEGATIVE {
			public String toString() {
				return "FalseNegative";
			}
		}
	};
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
