import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information, util_rda
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_graph_explicit(rda_graph, high_addrs, subject_addrs):
    high_addrs = list(filter(lambda a: not a in rda_graph.enriched_class_addrs[2], high_addrs))
    subject_addrs = list(filter(lambda a: not a in rda_graph.enriched_class_addrs[1], subject_addrs))

    for subject_addr in subject_addrs:
        rda_graph.enriched_class_addrs[1].append(subject_addr)
        node = find_rda_graph_node(rda_graph, subject_addr)
        if not node:
            continue
        util_rda.elevate_explicit(rda_graph, node, 1)

    for high_addr in high_addrs:
        rda_graph.enriched_class_addrs[2].append(high_addr)
        node = find_rda_graph_node(rda_graph, high_addr)
        if not node:
            continue
        util_rda.elevate_explicit(rda_graph, node, 2)

def get_super_dep_graph(proj, function_addrs):
    cfg = proj.analyses.CFGFast() #adds info to kb
    rda_dep_graph = dep_graph.DepGraph()
    for func_addr in function_addrs:
        func = proj.kb.functions.function(addr=func_addr)
        if func == None:
            print('Warning: ' + str(hex(func_addr)) + ' did not map to any function through kb!')
            continue
        rda = proj.analyses.ReachingDefinitions(
            subject = func,
            cc = func.calling_convention if func.calling_convention else None,
            dep_graph = rda_dep_graph,
            observe_all=True
        )
        rda_dep_graph = rda.dep_graph
    return rda_dep_graph

def find_rda_graph_nodes(rda_graph, ins_addrs):
    for ins_addr in ins_addrs:
        n = find_rda_graph_node(rda_graph, ins_addr)
        if n:
            yield n

def find_rda_graph_node(rda_graph, ins_addr):
    for n in rda_graph.nodes:
        if n.codeloc and n.codeloc.ins_addr == ins_addr:
            return n
    return None
       
#find possible explicit information flows using the enriched rda graph
def find_explicit(rda_graph, subject_addrs=None, subject_security_class=1):
    for n in rda_graph.nodes:
        if ((n.codeloc and n.codeloc.ins_addr in subject_addrs) if subject_addrs else n.given_sec_class == subject_security_class)\
            and subject_security_class < n.explicit_sec_class:
            yield ExplicitLeak(n.explicit_source, n)

class ExplicitLeak:
    def __init__(self, source, subject):
        self.source = source
        self.subject = subject
    
    def __repr__(self):
        return "<ExplicitLeak: from " + self.__simple_node_repr__(self.source) + " to " + self.__simple_node_repr__(self.subject) + ">"

    def __simple_node_repr__(self, node):
        return str(node.codeloc)

    def paths(self, rda_graph):
        return nx.all_simple_paths(rda_graph, self.source, self.subject)

    def print_path(self, rda_graph):
        print(next(self.paths(rda_graph)))