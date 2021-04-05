import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information, util_explicit
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_implicit(rda_graph, post_dom_tree, start_node):
    branches = find_branches(post_dom_tree, start_node)
    pass
    # subject_nodes = list(find_rda_graph_nodes(rda_graph, subject_addrs))
    # for subject_node in subject_nodes:
    #     subject_node.given_sec_class = 1
    #     subject_node.sec_class = 1
    #     descendants = networkx.descendants(rda_graph, subject_node)
    #     for des in descendants:
    #         des.sec_class = 1
    # high_nodes = list(find_rda_graph_nodes(rda_graph, high_addrs))
    # for high_node in high_nodes:
    #     high_node.given_sec_class = 2
    #     high_node.sec_class = 2
    #     descendants = networkx.descendants(rda_graph, high_node)
    #     for des in descendants:
    #         des.sec_class = 2

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
            yield ImplicitLeak(n.implicit_source, n)

#Test if branch node creates a high context
def test_high_branch_context(rda_graph, cfg_node, high_addrs):
    branch_ins = get_branch_ins(cfg_node)
    explicit_paths = list(util_explicit.find_explicit(rda_graph, subject_addrs=branch_ins)
    return len(explicit_paths) > 0

def get_branch_ins(cfg_node):
    return cfg_node.instruction_addrs[len(cfg_node.instruction_addrs)-1]

def test_high_loop_context(super_dep_graph, cfg, loop, high_addrs):
    loop_block_addrs = map(lambda n: n.addr, loop.body_nodes)
    for block_addr in loop_block_addrs:
        cfg_node = util_information.find_cfg_node(cfg, block_addr)
        if test_high_branch_context(super_dep_graph, cfg_node, high_addrs):
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
def find_high_branches(super_dep_graph, post_dom_tree, cfg_node, high_addrs, blacklist=[]):
    # if cfg_node in blacklist:
    #     return []
    # blacklist.append(cfg_node)
    # if isinstance(cfg_node, angr.utils.graph.TemporaryNode):
    #     return []
    # targets = cfg_node.successors
    # if len(targets) == 0:
    #     return []
    # if len(targets) == 1:
    #     return find_high_branches(super_dep_graph, post_dom_tree, targets[0], high_addrs, blacklist)
    # high = test_high_branch_context(super_dep_graph, cfg_node, high_addrs)
    # if not high:
    #     leftHighs = find_high_branches(super_dep_graph, post_dom_tree, targets[0], high_addrs, blacklist)
    #     rightHighs = find_high_branches(super_dep_graph, post_dom_tree, targets[1], high_addrs, blacklist)
    #     return leftHighs + rightHighs
    # dominator, subjects = find_branch_pdom(post_dom_tree, targets[0], targets[1])
    # if dominator == None: #No post-domintor
    #     #Find lowest common ancestor of subjects
    #     dominator = nx.algorithms.lowest_common_ancestor(post_dom_tree, subjects[0], subjects[1])
    # branch = Branch(cfg_node, subjects, dominator)
    # rec = find_high_branches(super_dep_graph, post_dom_tree, dominator, high_addrs, blacklist)
    # return [branch] + rec
    filter = lambda n: test_high_branch_context(super_dep_graph, n, high_addrs)
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
    is_included = filter(cfg_node)
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
def find_high_branch_nodes(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
    # acc_high_nodes = []
    # for branch in find_high_branches(super_dep_graph, post_dom_tree, cfg_node, high_addrs):
    #     high_nodes = []
    #     blacklist = [cfg_node, branch.dominator]
    #     for subject in branch.subjects:
    #         accumulate_nodes(subject, blacklist, high_nodes)
    #         acc_high_nodes.append((high_nodes,branch))
    # return acc_high_nodes
    high_branches = find_high_branches(super_dep_graph, post_dom_tree, cfg_node, high_addrs)
    return find_branch_nodes(high_branches, [cfg_node])

def find_branch_nodes(branches, blacklist=[]):
    acc_nodes = []
    for branch in branches:
        nodes = []
        bblacklist = blacklist.copy()
        bblacklist.append(branch.dominator)
        for subject in branch.subjects:
            accumulate_nodes(subject, bblacklist, nodes)
            acc_nodes.append((nodes,branch))
    return acc_nodes

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
        self.subjects = subjects
        self.dominator = dominator
    
    def __repr__(self):
        return "<Branch on " + str(hex(branch_ins)) + " in " + str(self.branch.addr) + ", subjects: " + str(list(map(lambda n: hex(n.addr), self.subjects))) + ", dominator: " + str(self.dominator.addr) + ">"

class ImplicitLeak(util_explicit.ExplicitLeak):
    def __init__(self, source, subject):
        util_explicit.ExplicitLeak.__init__(self, source, subject)

    def __repr__(self):
        return "<ImplicitLeak: from " + self.__simple_node_repr__(self.source) + " to " + self.__simple_node_repr__(self.subject) + ">"

    def __simple_node_repr__(self, node):
        return str(node.codeloc)

    def paths(self, rda_graph):
        return nx.all_simple_paths(rda_graph, self.source, self.subject)

    def print_path(self, rda_graph):
        print(next(self.paths(rda_graph)))