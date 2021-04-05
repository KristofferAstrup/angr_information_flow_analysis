import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information
from networkx.drawing.nx_pydot import graphviz_layout

def enrich_rda_explicit(rda_graph, high_addrs, subject_addrs):
    subject_nodes = list(find_rda_graph_nodes(rda_graph, subject_addrs))
    for subject_node in subject_nodes:
        subject_node.given_sec_class = 1
        subject_node.sec_class = 1
        descendants = networkx.descendants(rda_graph, subject_node)
        for des in descendants:
            des.sec_class = 1
    high_nodes = list(find_rda_graph_nodes(rda_graph, high_addrs))
    for high_node in high_nodes:
        high_node.given_sec_class = 2
        high_node.sec_class = 2
        descendants = networkx.descendants(rda_graph, high_node)
        for des in descendants:
            des.sec_class = 2

#Capture all relevant functions (main and all post main in cdg)
#inclusive
def get_unique_reachable_function_addresses(cfg, start_node):
    function_addrs = []
    for n in nx.descendants(cfg.graph, start_node):
        if not n.function_address in function_addrs:
            function_addrs.append(n.function_address)
    return function_addrs

#Create rda foreach function
#Create new super graph containing all rda graphs
def get_super_dep_graph_with_linking(proj, cfg, cdg, start_node, func_addrs=None):
    if not func_addrs:
        func_addrs = get_unique_reachable_function_addresses(cfg, start_node)
    dep_graph = get_super_dep_graph(proj, func_addrs)
    link_externals_to_earliest_definition(dep_graph, cdg, [start_node])
    return dep_graph

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
        for n in rda_graph.nodes():
            if n.codeloc and n.codeloc.ins_addr == ins_addr:
                yield n      
       
#find possible paths using the super rda dependence graph
def find_explicit(rda, lowAddresses, highAddresses):
    low_nodes = list(find_rda_graph_nodes(rda.graph, lowAddresses))
    high_nodes = list(find_rda_graph_nodes(rda.graph, highAddresses))
    for high_node in high_nodes:
        for low_node in low_nodes:
            try:
                path = nx.dijkstra_path(rda.graph, high_node, low_node)
                yield ExplicitLeakPath(high_node, low_node, path)
            except:
                pass #No path

def link_externals_to_earliest_definition(super_dep_graph, cdg, cdg_end_nodes):
    leafs = get_leafs(super_dep_graph.graph)
    externals = get_externals(super_dep_graph)
    for external in externals:
        for nn in list(nx.all_neighbors(super_dep_graph.graph, external)):
            cdg_node = util_information.find_cdg_node(cdg, nn.codeloc.block_addr)
            if not cdg_node:
                continue
            matches = find_earliest_matching_definition(external, nn, leafs, cdg_end_nodes, cdg_node)
            for match in matches:
                super_dep_graph.graph.add_edge(match, nn)

#external is the target external node from which the target is child
#the target is the node to which we want to link, we need to know it's block_addr
#leafs are the end-nodes of the super_dep_graph
#the cdg_node is currently inspected node
def find_earliest_matching_definition(external, target, leafs, cdg_end_nodes, cdg_node):
    if cdg_node.block and target.codeloc.block_addr != cdg_node.block.addr:
        for leaf in leafs:
            if leaf.codeloc and leaf.codeloc.block_addr == cdg_node.block.addr:
                if leaf.atom == external.atom:
                    return [leaf]
    if cdg_node in cdg_end_nodes:
        return []
    caller_blocks = cdg_node.predecessors
    matches = []
    for caller_block in caller_blocks:
        matches += find_earliest_matching_definition(external, target, leafs, cdg_end_nodes, caller_block)
    return matches

def get_externals(super_dep_graph):
    for n in super_dep_graph.graph.nodes:
        if isinstance(n.codeloc, angr.analyses.reaching_definitions.external_codeloc.ExternalCodeLocation):
            yield n

def get_leafs(graph):
    leaf_nodes = [node for node in graph.nodes() if graph.in_degree(node)!=0 and graph.out_degree(node)==0]
    return leaf_nodes

class ExplicitLeakPath:
    def __init__(self, high_node, low_node, path):
        self.high_node = high_node,
        self.low_node = low_node
        self.path = path
    
    def __repr__(self):
        return "<ExplicitLeakPath: From " + __simple_node_repr__(self.high_node) + "to" + __simple_node_repr__(self.low_node) + ">"

    def __simple_node_repr__(node):
        return str(self.high_node.code_loc)

    def print_path(self):
        print(self.path)