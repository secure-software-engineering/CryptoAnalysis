package de.upb.testify.androidmodel.ui.crypto.modelgenerator;

import java.util.ArrayList;
import java.util.List;

public class TreeNode<T> {

    private T data;
    private TreeNode<T> parent;
    private List<TreeNode<T>> children;

    /**
     * @return This node is a root if it does not have a parent
     */
    public boolean isRoot() {
        return getParent() == null;
    }

    public TreeNode(T data) {
        setData(data);
        setChildren(new ArrayList<>());
    }

    /**
     * @param child
     */
    public void addChild(T child) {
        TreeNode<T> childNode = new TreeNode<T>(child);
        childNode.setParent(this);
        getChildren().add(childNode);
    }

    /**
     * To id the correct rule to be returned
     * @return
     */
    public int getDepth() {
        if (this.isRoot()) {
            return 0;
        } else {
            return getParent().getDepth() + 1;
        }

    }

    /**
     * @return The data associated to the node
     */
    public T getData() {
        return data;
    }

    /**
     * @param data
     */
    private void setData(T data) {
        this.data = data;
    }

    /**
     * @return the parent of this node
     */
    public TreeNode<T> getParent() {
        return parent;
    }

    /**
     * @param parent
     */
    private void setParent(TreeNode<T> parent) {
        this.parent = parent;
    }

    /**
     * @return Get a list of the children of this node
     */
    public List<TreeNode<T>> getChildren() {
        return children;
    }

    /**
     * @param children
     */
    private void setChildren(List<TreeNode<T>> children) {
        this.children = children;
    }

}