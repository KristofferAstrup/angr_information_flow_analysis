import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information, util_explicit, util_rda
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_graph_implicit(rda_graph, cdg, function_addrs):
    change = True
    while(change):
        change = False
        for branching in find_branchings(cdg, function_addrs):
            if __enrich_rda_graph_implicit__(rda_graph, branching):
                change = True

def __enrich_rda_graph_implicit__(rda_graph, branching):
    change = False
    for branch_ins_rda_node in util_rda.find_rda_graph_nodes(rda_graph, branching.branch_ins):
        if not branch_ins_rda_node:
            continue
        if branch_ins_rda_node.branching_sec_class >= branch_ins_rda_node.sec_class:
            continue
        branch_ins_rda_node.branching_sec_class = branch_ins_rda_node.sec_class
        for node in branching.subjects:
            for ins in node.instruction_addrs:
                for ins_rda_node in util_rda.find_rda_graph_nodes(rda_graph, ins):
                    if not ins_rda_node:
                        continue
                    rda_graph.add_edge(branch_ins_rda_node,ins_rda_node,type=1) #Implicit edge
                    util_rda.elevate_implicit(rda_graph, ins_rda_node, branch_ins_rda_node)
        change = True
    return change

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
   
#Iterator for all branches with high branching instruction
def find_high_branchings(rda_graph, cdg, function_addrs, high_addrs):
    for branching in find_branchings(cdg, function_addrs):
        if test_high_branch_context(rda_graph, branching.node, high_addrs):
            yield n

#iterator for all branches through CDG
def find_branchings(cdg, function_addrs):
    for n in cdg.graph.nodes:
        if not n.function_address in function_addrs:
            continue
        successors = list(cdg.graph.successors(n))
        if len(successors) < 1:
            continue
        yield Branching(n, successors)

# def find_branches_old(post_dom_tree, cfg_node, blacklist=[], filter=None):
#     if cfg_node in blacklist:
#         return []
#     blacklist.append(cfg_node)
#     if isinstance(cfg_node, angr.utils.graph.TemporaryNode):
#         return []
#     targets = cfg_node.successors
#     if len(targets) == 0:
#         return []
#     if len(targets) == 1:
#         return find_branches(post_dom_tree, targets[0], blacklist, filter)
#     is_included = filter(cfg_node) if filter else True
#     if not is_included:
#         left = find_branches(post_dom_tree, targets[0], blacklist, filter)
#         right = find_branches(post_dom_tree, targets[1], blacklist, filter)
#         return left + right
#     dominator, subjects = find_branch_pdom(post_dom_tree, targets[0], targets[1])
#     if dominator == None: #No post-domintor
#         #Find lowest common ancestor of subjects
#         dominator = nx.algorithms.lowest_common_ancestor(post_dom_tree, subjects[0], subjects[1])
#     branch = Branch(cfg_node, subjects, dominator)
#     rec = find_branches(post_dom_tree, dominator, blacklist, filter)
#     return [branch] + rec

class Branching:
    def __init__(self, node, subjects):
        self.node = node
        self.branch_ins = get_branch_ins(node)
        self.subjects = subjects #Nodes control dependent on the branching node
    
    def __repr__(self):
        return "<Branching on " + str(hex(self.branch_ins)) + " in " + str(hex(self.node.addr)) + ", subjects: " + str(list(map(lambda n: hex(n.addr), self.subjects))) + ">"

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