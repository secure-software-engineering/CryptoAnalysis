package crypto.preanalysis;

import crypto.Utils;
import crypto.analysis.ClassSpecification;
import soot.Scene;
import soot.SootClass;

import java.util.*;

public final class RuleTree {

    private static TreeNode<TreeNodeData> objectNode; // A single root node expected
    private static Map<TreeNode<TreeNodeData>, Integer> listOfSuperClasses; // Map<Node, Depth>

    /**
     * Create a rule tree from the given ClassSpecifications
     * @param specifications The specifications read from the CryptoScanner
     * @return The rule tree
     */
    public static void createTree(List<ClassSpecification> specifications) {
        if (specifications.size() > 0) {
            List<TreeNode<TreeNodeData>> listOfTreeNodes = new ArrayList<>();

            // This loop is needed to id the Object rule to avoid multiple apexes for the tree
            for (ClassSpecification specification : specifications) {
                // Create TreeNodeData with the class and specification for each specification.
                SootClass classFromClassSpecification = Scene.v().forceResolve(Utils.getFullyQualifiedName(specification.getRule()), SootClass.HIERARCHY);
                listOfTreeNodes.add(new TreeNode<>(new TreeNodeData(classFromClassSpecification, specification)));
                if (Utils.getFullyQualifiedName(specification.getRule()).equals("java.lang.Object")) {
                    // set the pseudo rule for the class Object to be used as a root node for the rule tree.
                    setObjectNode(new TreeNode<>(new TreeNodeData(classFromClassSpecification, specification)));
                }
            }

            if (getObjectNode() != null) {
                for (TreeNode<TreeNodeData> treeNode : listOfTreeNodes) {
                    insertNode(treeNode, getObjectNode());
                }
            }
        }

        // Test verification
        // dotDataForRuleTree dot = new dotDataForRuleTree();
        // dot.createDotFile(RuleTree.objectNode);
    }

    /**
     * Recursive insertion of a given rule node in the rule tree
     * @param nodeUnderConsideration
     * @param rootNode The current root node.
     * @return Whether the insertion was successful
     */
    private static boolean insertNode(TreeNode<TreeNodeData> nodeUnderConsideration, TreeNode<TreeNodeData> rootNode) {
        // Skip if the node under consideration and root node are the same.
        if (!nodeUnderConsideration.getData().getSootClass().equals(rootNode.getData().getSootClass())) {
            // Check if the node under consideration is a sub class of the current root node.
            if (Scene.v().getOrMakeFastHierarchy().isSubclass(nodeUnderConsideration.getData().getSootClass(), rootNode.getData().getSootClass())) {
                // If it is go deeper into the current tree.
                for (TreeNode<TreeNodeData> child : rootNode.getChildren()) {
                    // The current root node is now the child of the earlier parent node. Break the recursion if the insertion was successful.
                    if (insertNode(nodeUnderConsideration, child)) {
                        return true;
                    }
                }

                // After traversal through the children, if insertion is unsuccessful, or if there are no children, add the node as a child.
                if (!rootNode.getChildren().contains(nodeUnderConsideration)) {
                    rootNode.addChild(nodeUnderConsideration.getData());
                    return true;
                }

            }// If the above check is not true, check if the hierarchy is the other way around.
            else if (Scene.v().getOrMakeFastHierarchy().isSubclass(rootNode.getData().getSootClass(), nodeUnderConsideration.getData().getSootClass())) {
                // Add the node under consideration as a child to the root node. And remove the root node from the children of its parent.
                TreeNode<TreeNodeData> parent = rootNode.getParent();
                parent.getChildren().add(nodeUnderConsideration);
                parent.getChildren().remove(rootNode);

                // check the former siblings of the exchanged sub class, if they are sub classes to the new super class, add them as children.
                ListIterator<TreeNode<TreeNodeData>> treeNodeListIterator = parent.getChildren().listIterator();
                while (treeNodeListIterator.hasNext()) {
                    TreeNode<TreeNodeData> child = treeNodeListIterator.next();
                    System.out.println("child: " + child.getData().getClassSpecification().toString() + "  parent: " + parent.getData().getClassSpecification().toString());
                    if (child.getData().getSootClass() != nodeUnderConsideration.getData().getSootClass()) {
                        if (Scene.v().getOrMakeFastHierarchy().isSubclass(child.getData().getSootClass(), nodeUnderConsideration.getData().getSootClass())) {
                            treeNodeListIterator.remove();
                            insertNode(child, nodeUnderConsideration);
                        }
                    }

                }


                // In case the node under consideration has children.
                for (TreeNode<TreeNodeData> child : nodeUnderConsideration.getChildren()) {
                    if (insertNode(child, nodeUnderConsideration)) {
                        return true; // the recursion must break here.
                    }
                }

                if (!nodeUnderConsideration.getChildren().contains(rootNode)) {
                    nodeUnderConsideration.addChild(rootNode.getData());
                    return true;
                }

            } // If both the above conditions fail, the higher node will get the node under consideration as a child.
            else {
                return false;
            }
        } else {
            return false;
        }

        // Should be unreachable.
        return false;
    }

    /**
     * Return the correct rule for the given soot class
     * @param sootClass
     * @return Correct rule
     */
    public static ClassSpecification getRule(SootClass sootClass) {
        setListOfSuperClasses(new HashMap<>());

        // Begin search from the root node.
        getSuperClasses(getObjectNode(), sootClass);

        // Temp storage to hold the valid rule.
        Map.Entry<TreeNode<TreeNodeData>, Integer> validRule = new AbstractMap.SimpleEntry<TreeNode<TreeNodeData>, Integer>(null, -1);

        for (Map.Entry<TreeNode<TreeNodeData>, Integer> treeNodeStringEntry : listOfSuperClasses.entrySet()) {
            if (validRule.getValue() < treeNodeStringEntry.getValue()) {
                validRule = treeNodeStringEntry;
            }
        }

        return validRule.getKey().getData().getClassSpecification();
    }

    /**
     * Recursive traversal of the rule tree to id the correct rule for the given soot class
     * @param node The current root node
     * @param sootClass
     */
    private static void getSuperClasses(TreeNode<TreeNodeData> node, SootClass sootClass) {
        // If the given soot class is the same as the one in the current node, this is the rule we are looking for.
        // This should also mean this addition to the listOfSuperClasses should yield the deepest depth.
        if (sootClass.equals(node.getData().getSootClass())) {
            getListOfSuperClasses().put(node, node.getDepth());
        } // If not, check if the given soot class is a sub class. If yes add to the listOfSuperClasses along with the depth, and delve further into the tree.
        else if (Scene.v().getOrMakeFastHierarchy().isSubclass(sootClass, node.getData().getSootClass())) {
            getListOfSuperClasses().put(node, node.getDepth());
            for (TreeNode<TreeNodeData> child : node.getChildren()) {
                getSuperClasses(child, sootClass);
            }
        }

    }

    /**
     * @return The rule tree
     */
    private static TreeNode<TreeNodeData> getObjectNode() {
        return RuleTree.objectNode;
    }

    /**
     * Set the root node for the rule tree
     * @param objectNode
     */
    private static void setObjectNode(TreeNode<TreeNodeData> objectNode) {
        RuleTree.objectNode = objectNode;
    }

    /**
     * @return the list of super classes to the given soot class
     */
    private static Map<TreeNode<TreeNodeData>, Integer> getListOfSuperClasses() {
        return RuleTree.listOfSuperClasses;
    }

    /**
     * @param listOfSuperClasses
     */
    private static void setListOfSuperClasses(Map<TreeNode<TreeNodeData>, Integer> listOfSuperClasses) {
        RuleTree.listOfSuperClasses = listOfSuperClasses;
    }

}