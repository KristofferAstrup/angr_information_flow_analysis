import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import copy
from information_flow_analysis import information, explicit, rda
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_graph_implicit(rda_graph, cdg, function_addrs):
    enriched_blocks = []
    change = True
    while(change):
        change = False
        for branching in find_branchings(cdg, function_addrs):
            branching_enriched_blocks = __enrich_rda_graph_implicit__(rda_graph, branching)
            if len(branching_enriched_blocks) > 0:
                change = True
                enriched_blocks.extend(branching_enriched_blocks)
    return enriched_blocks

def __enrich_rda_graph_implicit__(rda_graph, branching):
    enriched_blocks = []
    for branch_ins_rda_node in rda.find_rda_graph_nodes(rda_graph, branching.branch_ins):
        if not branch_ins_rda_node:
            continue
        if branch_ins_rda_node.branching_sec_class >= branch_ins_rda_node.sec_class:
            continue
        branch_ins_rda_node.branching_sec_class = branch_ins_rda_node.sec_class
        for node in branching.subjects:
            enriched_blocks.append((branch_ins_rda_node.sec_class, node))
            for ins in node.instruction_addrs:
                for ins_rda_node in rda.find_rda_graph_nodes(rda_graph, ins):
                    if not ins_rda_node:
                        continue
                    rda_graph.add_edge(branch_ins_rda_node,ins_rda_node,type=1) #Implicit edge
                    rda.elevate_implicit(rda_graph, ins_rda_node, branch_ins_rda_node)
    return enriched_blocks

def check_addr_high(rda_graph, addr):
    for n in rda.find_rda_graph_nodes(rda_graph, addr):
        if n.sec_class == 2:
            return True
    return False

def check_node_high(node):
    return node.sec_class == 2

#find possible implicit information flows using the enriched rda graph
def find_implicit(rda_graph, subject_addrs=None, subject_security_class=1):
    for n in rda_graph.nodes:
        if ((n.codeloc and n.codeloc.ins_addr in subject_addrs) if subject_addrs else n.given_sec_class == subject_security_class)\
            and subject_security_class < n.implicit_sec_class:
            source, inters = rda.get_intermediates(n.implicit_source)
            yield ImplicitLeak(source, inters, n)

#Test if branch node creates a high context
def test_high_branch_context(rda_graph, cfg_node, high_addrs):
    branch_ins = get_branch_ins(cfg_node)
    for branch_ins_rda_node in rda.find_rda_graph_nodes(rda_graph, branch_ins):
        if branch_ins_rda_node.sec_class == 2:
            return True
    return False

def get_branch_ins(cfg_node):
    return cfg_node.instruction_addrs[len(cfg_node.instruction_addrs)-1]

def test_high_loop_context(rda_graph, cfg, loop, high_addrs):
    loop_block_addrs = map(lambda n: n.addr, loop.body_nodes)
    for block_addr in loop_block_addrs:
        cfg_node = information.find_cfg_node(cfg, block_addr)
        if test_high_branch_context(rda_graph, cfg_node, high_addrs):
            return True
    return False
   
#Iterator for all branches with high branching instruction
def find_high_branchings(rda_graph, cdg, function_addrs, high_addrs):
    for branching in find_branchings(cdg, function_addrs):
        if test_high_branch_context(rda_graph, branching.node, high_addrs):
            yield branching

#iterator for all branches through CDG
def find_branchings(cdg, function_addrs):
    for n in cdg.graph.nodes:
        if not n.function_address in function_addrs:
            continue
        successors = list(cdg.graph.successors(n))
        if len(successors) < 1:
            continue
        if len(n.successors) < 2: #Note: this is CFG successors
            continue
        yield Branching(n, successors)

class BranchRecord:
    def __init__(self, block_addr, depth, id):
        self.block_addr = block_addr
        self.depth = depth
        self.id = id
    def __eq__(self, other):
        return self.id == other.id

class BranchRecordPlugin(angr.SimStatePlugin):
    NAME = 'branch_record_plugin'

    def __init__(self, records):
        self.records = copy.deepcopy(records)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return BranchRecordPlugin(self.records)

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