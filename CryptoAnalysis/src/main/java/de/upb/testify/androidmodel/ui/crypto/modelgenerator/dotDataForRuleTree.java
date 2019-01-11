package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;

/**
 * For verifying the rule tree
 */
public class dotDataForRuleTree {

    private Map<String, String> nodes;
    private Map<String, Map.Entry<String, String>> edges;

    public dotDataForRuleTree() {
        setNodes(new HashMap<>());
        setEdges(new HashMap<>());
    }

    /**
     * @param root The root node for the rule tree
     */
    private void getNodesAndEdges(TreeNode<TreeNodeData> root) {
        getNodes().put(root.getData().getSootClass().getName().replace(".", ""),
                root.getData().getSootClass().getName().replace(".", ""));
        for (TreeNode<TreeNodeData> child : root.getChildren()) {
            getNodes().put(child.getData().getSootClass().getName().replace(".", ""),
                    child.getData().getSootClass().getName().replace(".", ""));
            getEdges().put(root.getData().getSootClass().getName().replace(".", "") +
                    child.getData().getSootClass().getName().replace(".", ""),
                    new AbstractMap.SimpleEntry<>(root.getData().getSootClass().getName().replace(".", ""),
                            child.getData().getSootClass().getName().replace(".", "")));

            getNodesAndEdges(child);
        }
    }

    /**
     * Generate the dot file data for the given rule tree
     */
    public void createDotFile(TreeNode<TreeNodeData> root) {
        getNodesAndEdges(root);

        StringBuilder builder = new StringBuilder();
        builder.append("digraph G { \n");
        builder.append(" rankdir=LR;\n");
        builder.append(" node[shape=box];\n");

        for (String s : getNodes().keySet()) {
            builder.append(s);
            builder.append(" ");
            builder.append("[label=\"");
            builder.append(getNodes().get(s));
            builder.append("\"]");
            builder.append(";\n");
        }

        for (String s : getEdges().keySet()) {
            Map.Entry<String, String> single = getEdges().get(s);

            builder.append(single.getKey());
            builder.append(" -> ");
            builder.append(single.getValue());
            builder.append("[label=\"");
            builder.append(s);
            builder.append("\"]");
            builder.append(";\n");
        }


        builder.append("}");
        System.out.println(builder.toString());
    }

    /**
     * @return nodes of the dot file
     */
    private Map<String, String> getNodes() {
        return nodes;
    }

    /**
     * @param nodes empty list for the nodes of the dot file
     */
    private void setNodes(Map<String, String> nodes) {
        this.nodes = nodes;
    }

    /**
     * @return edges of the dot file
     */
    private Map<String, Map.Entry<String, String>> getEdges() {
        return edges;
    }

    /**
     * @param edges empty list for the edges of the dot file
     */
    private void setEdges(Map<String, Map.Entry<String, String>> edges) {
        this.edges = edges;
    }


}
