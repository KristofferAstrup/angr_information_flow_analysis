import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from customutil import util_information
from networkx.drawing.nx_pydot import graphviz_layout

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
        #print(hex(func_addr))
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

def find_dep_graph_nodes(super_dep_graph, ins_addrs):
    for ins_addr in ins_addrs:
        for n in super_dep_graph.graph.nodes():
            if n.codeloc and n.codeloc.ins_addr == ins_addr:
                yield n
       
#find possible paths using the super rda dependence graph
def find_explicit(super_dep_graph, lowAddresses, highAddresses):
    low_nodes = list(find_dep_graph_nodes(super_dep_graph, lowAddresses))
    high_nodes = list(find_dep_graph_nodes(super_dep_graph, highAddresses))
    for high_node in high_nodes:
        for low_node in low_nodes:
            try:
                yield nx.dijkstra_path(super_dep_graph.graph, high_node, low_node)
            except:
                pass #No path
    # print("Low")
    # print(low_nodes)
    # print("High")
    # print(high_nodes)

    # for n in ddg.data_graph.nodes(data=True):
    #     if n[0].location.ins_addr in lowAddresses and not isinstance(n[0].variable, SimConstantVariable):
    #         if(n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist):
    #             continue
    #         targetNodes.append(n[0])

    # for n in ddg.data_graph.nodes(data=True):
    #     if n[0].location.ins_addr in highAddresses and not isinstance(n[0].variable, SimConstantVariable):
    #         if n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist:
    #             continue
    #         sub = ddg.data_sub_graph(n[0], simplified=False)
    #         for targetNode in targetNodes:
    #             try:
    #                 yield nx.dijkstra_path(sub,n[0],targetNode)
    #             except:
    #                 pass #No path

#Augment super graph with edges: 
#Foreach external(argument-input) try to find a source/caller(argument-output)
#   Find the block of the external node in the CDG (or call-graph)
#   Foreach block caller:
#       If the caller block has a end-node node in it's rsa that corresponds to the external node:
#           Add edge from this node to the external node
#       If not, recursively repeat with the caller blocks callers
def link_externals_to_earliest_definition(super_dep_graph, cdg, cdg_end_nodes):
    leafs = get_leafs(super_dep_graph.graph)
    externals = get_externals(super_dep_graph)
    for external in externals:
        for nn in list(nx.all_neighbors(super_dep_graph.graph, external)):
            cdg_node = util_information.find_cdg_node(cdg, nn.codeloc.block_addr)
            matches = find_earliest_matching_definition(external, nn, leafs, cdg_end_nodes, cdg_node)
            # print('------------')
            # print(external)
            # print(nn)
            # print('----')
            for match in matches:
                # print(match)
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