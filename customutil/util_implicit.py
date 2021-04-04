import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information, util_explicit
from networkx.drawing.nx_pydot import graphviz_layout

def find_implicit(super_dep_graph, post_dom_tree, cfg_node, lowAddresses, high_addrs):
    high_addrs = find_high_node_addrs(super_dep_graph, post_dom_tree, cfg_node, high_addrs)
    for path in util_explicit.find_explicit(super_dep_graph, lowAddresses, high_addrs):
        yield path

#Find all high context node instruction addresses:
def find_high_node_addrs(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
    addrs = []
    for n in find_high_nodes(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
        addrs.extend(n.instruction_addrs)
    return addrs

#Test if branch node creates a high context
def test_high_branch_context(super_dep_graph, cfg_node, high_addrs):
    branch_ins = cfg_node.instruction_addrs[len(cfg_node.instruction_addrs)-1]
    explicit_paths = list(util_explicit.find_explicit(super_dep_graph, [branch_ins], high_addrs))
    return len(explicit_paths) > 0 

def test_high_loop_context(super_dep_graph, cfg, loop, high_addrs):
    loop_block_addrs = map(lambda n: n.addr, loop.body_nodes)
    for block_addr in loop_block_addrs:
        cfg_node = util_information.find_cfg_node(cfg, block_addr)
        if test_high_branch_context(super_dep_graph, cfg_node, high_addrs):
            return True
    return False
    
#Pure side-effect; resultlist accumulates the nodes
#TODO: This should not take a blacklist with the initial node (see find_high_nodes)
def accumulate_nodes(cfg_node, blacklist, resultlist):
    blacklist.append(cfg_node)
    resultlist.append(cfg_node)
    for child in cfg_node.successors:
        if child in blacklist:
            continue
        accumulate_nodes(child, blacklist, resultlist)

#Find all high branches recursively in cfg starting from given node
def find_high_branches(super_dep_graph, post_dom_tree, cfg_node, high_addrs, blacklist=[]):
    if cfg_node in blacklist:
        return []
    blacklist.append(cfg_node)
    if isinstance(cfg_node, angr.utils.graph.TemporaryNode):
        return []
    targets = cfg_node.successors
    if len(targets) == 0:
        return []
    if len(targets) == 1:
        return find_high_branches(super_dep_graph, post_dom_tree, targets[0], high_addrs, blacklist)
    high = test_high_branch_context(super_dep_graph, cfg_node, high_addrs)
    if not high:
        leftHighs = find_high_branches(super_dep_graph, post_dom_tree, targets[0], high_addrs, blacklist)
        rightHighs = find_high_branches(super_dep_graph, post_dom_tree, targets[1], high_addrs, blacklist)
        return leftHighs + rightHighs
    dominator, subjects = find_branch_pdom(post_dom_tree, targets[0], targets[1])
    if dominator == None: #No post-domintor
        #Find lowest common ancestor of subjects
        dominator = nx.algorithms.lowest_common_ancestor(post_dom_tree, subjects[0], subjects[1])
    branch = ImplicitBranch(cfg_node, subjects, dominator)
    rec = find_high_branches(super_dep_graph, post_dom_tree, dominator, high_addrs, blacklist)
    return [branch] + rec

#Find all high nodes recursively in cfg starting from given node
def find_high_nodes(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
    acc_high_nodes = []
    for branch in find_high_branches(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
        high_nodes = []
        blacklist = [cfg_node, branch.dominator]
        for subject in branch.subjects:
            accumulate_nodes(subject, blacklist, high_nodes)
            acc_high_nodes.extend(high_nodes)
    return acc_high_nodes

def find_branch_pdom(post_dom_tree, node1, node2):
    try:
        path = nx.dijkstra_path(post_dom_tree,node1,node2)
        #Node1 postdominates Node2
        return (node1, [node2])
    except:
        pass #No path

    try:
        path = nx.dijkstra_path(post_dom_tree,node2,node1)
        #Node2 postdominates Node1
        return (node2, [node1])
    except:
        pass #No path

    #No postdominance
    return (None, [node1, node2])

class ImplicitBranch:
    def __init__(self, branch, subjects, dominator):
        self.branch = branch
        self.subjects = subjects
        self.dominator = dominator
    
    def __repr__(self):
        return "<Branch: " + str(self.branch) + ", subjects: " + str(self.subjects) + ", dominator: " + str(self.dominator) + ">"