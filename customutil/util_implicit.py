import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information, util_explicit, util_rda
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_graph_implicit(rda_graph, post_dom_tree, start_node):
    branches = find_branches(post_dom_tree, start_node)
    branch_ins_to_nodes_map = {branch.branch_ins: find_branch_nodes(branch) for branch in branches}
    change = True
    while(change):
        change = False
        for branch in branches:
            if __enrich_rda_graph_implicit__(rda_graph, branch_ins_to_nodes_map, branch):
                change = True

def __enrich_rda_graph_implicit__(rda_graph, branch_ins_to_nodes_map, branch):
    change = False
    for branch_ins_rda_node in util_rda.find_rda_graph_nodes(rda_graph, branch.branch_ins):
        if not branch_ins_rda_node:
            continue
        if branch_ins_rda_node.branch_sec_class >= branch_ins_rda_node.sec_class:
            continue
        branch_ins_rda_node.branch_sec_class = branch_ins_rda_node.sec_class
        for node in branch_ins_to_nodes_map[branch.branch_ins]:
            for ins in node.instruction_addrs:
                for ins_rda_node in util_rda.find_rda_graph_nodes(rda_graph, ins):
                    if not ins_rda_node:
                        continue
                    rda_graph.add_edge(branch_ins_rda_node,ins_rda_node,type=1) #Implicit edge
                    util_rda.elevate_implicit(rda_graph, ins_rda_node, branch_ins_rda_node)
        change = True
    return change

# def find_implicit(super_dep_graph, post_dom_tree, cfg_node, lowAddresses, high_addrs):
#     branch_addrs = find_high_node_addrs(super_dep_graph, post_dom_tree, cfg_node, high_addrs)
#     for high_addrs, branch in branch_addrs:
#         for path in util_explicit.find_explicit(super_dep_graph, lowAddresses, high_addrs):
#             yield ImplicitLeakPath(path)

#find possible implicit information flows using the enriched rda graph
def find_implicit(rda_graph, subject_addrs=None, subject_security_class=1):
    for n in rda_graph.nodes:
        if ((n.codeloc and n.codeloc.ins_addr in subject_addrs) if subject_addrs else n.given_sec_class == subject_security_class)\
            and subject_security_class < n.implicit_sec_class:
            source, inters = util_rda.get_intermediates(n.implicit_source)
            yield ImplicitLeak(source, inters, n)

#Test if branch node creates a high context
def test_high_branch_context(rda_graph, cfg_node, high_addrs):
    branch_ins = get_branch_ins(cfg_node)
    for branch_ins_rda_node in util_rda.find_rda_graph_nodes(rda_graph, branch_ins):
        if branch_ins_rda_node.sec_class == 2:
            return True
    return False

def get_branch_ins(cfg_node):
    return cfg_node.instruction_addrs[len(cfg_node.instruction_addrs)-1]

def test_high_loop_context(rda_graph, cfg, loop, high_addrs):
    loop_block_addrs = map(lambda n: n.addr, loop.body_nodes)
    for block_addr in loop_block_addrs:
        cfg_node = util_information.find_cfg_node(cfg, block_addr)
        if test_high_branch_context(rda_graph, cfg_node, high_addrs):
            return True
    return False
    
#Pure side-effect; resultlist accumulates the nodes
#TODO: This should not take a blacklist with the initial node (see find_high_branch_nodes)
def accumulate_nodes(cfg_node, blacklist, resultlist):
    blacklist.append(cfg_node)
    resultlist.append(cfg_node)
    for child in cfg_node.successors:
        if child in blacklist:
            continue
        accumulate_nodes(child, blacklist, resultlist)

#Find all high branches recursively in cfg starting from given node
def find_high_branches(rda_graph, post_dom_tree, cfg_node, high_addrs, blacklist=[]):
    filter = lambda n: test_high_branch_context(rda_graph, n, high_addrs)
    return find_branches(post_dom_tree, cfg_node, blacklist, filter)

def find_branches(post_dom_tree, cfg_node, blacklist=[], filter=None):
    if cfg_node in blacklist:
        return []
    blacklist.append(cfg_node)
    if isinstance(cfg_node, angr.utils.graph.TemporaryNode):
        return []
    targets = cfg_node.successors
    if len(targets) == 0:
        return []
    if len(targets) == 1:
        return find_branches(post_dom_tree, targets[0], blacklist, filter)
    is_included = filter(cfg_node) if filter else True
    if not is_included:
        left = find_branches(post_dom_tree, targets[0], blacklist, filter)
        right = find_branches(post_dom_tree, targets[1], blacklist, filter)
        return left + right
    dominator, subjects = find_branch_pdom(post_dom_tree, targets[0], targets[1])
    if dominator == None: #No post-domintor
        #Find lowest common ancestor of subjects
        dominator = nx.algorithms.lowest_common_ancestor(post_dom_tree, subjects[0], subjects[1])
    branch = Branch(cfg_node, subjects, dominator)
    rec = find_branches(post_dom_tree, dominator, blacklist, filter)
    return [branch] + rec

#Find all high nodes recursively in cfg starting from given node
#Returns list of (Node[], Branch)
def find_high_branch_nodes(rda_graph, post_dom_tree, cfg_node, high_addrs):
    high_branches = find_high_branches(rda_graph, post_dom_tree, cfg_node, high_addrs)
    return find_branches_nodes(high_branches, [cfg_node])

def find_branches_nodes(branches, blacklist=[]):
    acc_nodes = []
    for branch in branches:
        nodes = find_branch_nodes(branch, blacklist)
        acc_nodes.append((nodes,branch))
    return acc_nodes

def find_branch_nodes(branch, blacklist=[]):
    nodes = []
    bblacklist = blacklist.copy()
    bblacklist.append(branch.dominator)
    for subject in branch.subjects:
        accumulate_nodes(subject, bblacklist, nodes)
    return nodes

#Find all high context node instruction addresses
#Returns list of (int[], Branch)
def find_high_node_addrs(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
    branch_addrs = []
    for high_nodes, branch in find_high_branch_nodes(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
        ins = []
        for high_node in high_nodes:
            ins.extend(high_node.instruction_addrs)
        branch_addrs.append((ins, branch))
    return branch_addrs

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

class Branch:
    def __init__(self, branch, subjects, dominator):
        self.branch = branch
        self.branch_ins = get_branch_ins(branch)
        self.subjects = subjects #Immediate post-dominated successors of the branch node
        self.dominator = dominator
    
    def __repr__(self):
        return "<Branch on " + str(hex(self.branch_ins)) + " in " + str(hex(self.branch.addr)) + ", subjects: " + str(list(map(lambda n: hex(n.addr), self.subjects))) + ", dominator: " + str(hex(self.dominator.addr)) + ">"

class ImplicitLeak():
    def __init__(self, source, inters, subject):
        self.source = source
        self.inters = inters
        self.subject = subject

    def __repr__(self):
        throughStr = ""
        if len(self.inters) > 0:
            throughStr += " through "
            throughStr += str(list(map(lambda n: self.__simple_node_repr__(n), self.inters)))
            throughStr += " "
        return "<ImplicitLeak: from " + self.__simple_node_repr__(self.source) + throughStr + " to " + self.__simple_node_repr__(self.subject) + ">"

    def __simple_node_repr__(self, node):
        return str(node.codeloc)

    def paths(self, rda_graph):
        return nx.all_simple_paths(rda_graph, self.source, self.subject)

    def print_path(self, rda_graph):
        print(next(self.paths(rda_graph)))