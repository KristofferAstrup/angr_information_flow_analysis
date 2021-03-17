import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from networkx.drawing.nx_pydot import graphviz_layout

# def find_procedure_nodes(proj, ddg, sim_proc_name, regBlacklist=None):
#     if regBlacklist == None:
#         regBlacklist = [proj.arch.ip_offset]
#     for n in ddg.data_graph.nodes(data=True):
#         if not isinstance(n[0].variable, SimConstantVariable)\
#         and n[0].location\
#         and n[0].location.sim_procedure\
#         and n[0].location.sim_procedure.display_name == sim_proc_name:
#             if(n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist):
#                 continue
#             yield n[0]

# def find_ddg_program_arg_nodes(proj, ddg, addr=None):
#     if addr == None:
#         addr = proj.entry
#     arg_regs = proj.arch.argument_registers
#     ent_reg_vals = proj.arch.entry_register_values
#     reg_names = ['argv', 'argc']
#     reg_offs = []
#     for p, v in ent_reg_vals.items():
#         if v in reg_names:
#             off, size = proj.arch.registers[p]
#             reg_offs.append(off)
#             print(v + " -> " + p + ": " + str(off))
#     for n in ddg.data_graph.nodes(data=True):
#         if n[0].location.sim_procedure and n[0].location.sim_procedure.display_name == '__libc_start_main': #n[0].location.block_addr == addr:# and isinstance(n[0].variable, SimRegisterVariable):
#             if isinstance(n[0].variable, SimConstantVariable):
#                 continue
#             try:
#                 if n[0].variable.reg and n[0].variable.reg in reg_offs:
#                     yield n[0]
#             except:
#                 pass

# def find_ddg_nodes(ddg, ins_addr):
#     for n in ddg.data_graph.nodes:
#         if n.location and n.location.ins_addr == ins_addr:
#             yield n

# def get_all_ancestors_of_ddg_ins(ddg, nodes):
#     ancestors = []
#     for n in nodes:
#         ancestors += nx.ancestors(ddg.data_graph, n)
#     return ancestors

# def clear_constant_ddg_nodes(ddg):
#     constant_nodes = []
#     for n in ddg.data_graph.nodes(data=True):
#         if isinstance(n[0].variable, SimConstantVariable):
#             constant_nodes.append(n[0])
#     ddg.data_graph.remove_nodes_from(constant_nodes)

# def filter_ddg_node_whitelist(ddg, node_whitelist):
#     filtered_nodes = []
#     for n in ddg.data_graph.nodes:
#         if n in node_whitelist:
#             continue
#         filtered_nodes.append(n)
#     ddg.data_graph.remove_nodes_from(filtered_nodes)

# def filter_ddg_block_whitelist(ddg, block_addr_whitelist):
#     filtered_nodes = []
#     for n in ddg.data_graph.nodes:
#         if n.location.sim_procedure:
#             continue
#         if n.location and n.location.block_addr in block_addr_whitelist:
#             continue
#         filtered_nodes.append(n)
#     ddg.data_graph.remove_nodes_from(filtered_nodes)

def cfg_emul(proj, simgr, state):
    return proj.analyses.CFGEmulated(
        keep_state=True, 
        normalize=True, 
        starts=[simgr.active[0].addr],
        initial_state=state,
        context_sensitivity_level=5,
        resolve_indirect_jumps=True
    )

def find_cdg_block_nodes(cdg, block_addr):
    for n in cdg.graph.nodes(data=True):
        if n[0].block and n[0].block.addr == block_addr:
            yield n

def find_all_descendants_block_address(cfg, cdg_node):
    for n in nx.descendants(cfg.graph, cdg_node):
        if n.block:
            yield n.block.addr

def link_similar_mem(ddg):
    groupedNodes = {}
    for n in ddg.data_graph.nodes(data=True):
        if isinstance(n[0].variable, SimMemoryVariable) and (not n[0].location.sim_procedure):
            groupedNodes.setdefault(str(hex(n[0].location.ins_addr)), []).append(n[0])
    for k in groupedNodes:
        if(len(groupedNodes[k]) < 2):
            continue
        print(k)
        print(groupedNodes[k])

def link_similar_ins_regs(ddg):
    groupedRegNodes = {}
    for n in ddg.data_graph.nodes(data=True):
        if isinstance(n[0].variable, SimRegisterVariable):
            area = n[0].location.sim_procedure.display_name if n[0].location.sim_procedure else str(hex(n[0].location.ins_addr))
            key = str(n[0].variable.reg)+":"+area
            groupedRegNodes.setdefault(key, []).append(n[0])
    for k in groupedRegNodes:
        nodes = groupedRegNodes[k]
        for i in range(len(nodes)):
            if i==0:
                continue
            ddg.data_graph.add_edge(nodes[i-1], nodes[i])
            ddg.data_graph.add_edge(nodes[i], nodes[i-1])

def get_ddg_reg_var(ddg, ins_addr, reg_offset):
    for n in ddg.data_graph.nodes(data=True):
        if n[0].location and n[0].location.ins_addr and\
            n[0].location.ins_addr == ins_addr and\
            isinstance(n[0].variable, SimRegisterVariable):
            if n[0].variable.reg == reg_offset:
                return n
    return None

def get_arg_regs(proj):
    for arg_reg_offset in proj.arch.argument_registers:
        for k in proj.arch.registers:
            offset, size = proj.arch.registers[k]
            if offset == arg_reg_offset:
                yield {"name": k, "offset": offset, "size": size}

def get_sim_proc_reg_args(proj, sim_proc_name):
    for k in proj._sim_procedures:
        if proj._sim_procedures[k].display_name == sim_proc_name:
            return proj._sim_procedures[k].cc.args

def get_sim_proc_addr(proj, sim_proc_name):
    for k in proj._sim_procedures:
        if proj._sim_procedures[k].display_name == sim_proc_name:
            return proj._sim_procedures[k].addr
    return None

def get_sim_proc_function_wrapper_addrs(proj, sim_proc_name):
    sim_addr = get_sim_proc_addr(proj, sim_proc_name)
    if sim_addr != None:
        for l in proj.kb.callgraph.in_edges(sim_addr):
            f, t = l
            yield f

def get_function_node(cdg, function_addr):
    for n in cdg.graph.nodes():
        if n.addr == function_addr:
            return n
    return None

def get_final_ins_for_cdg_node(cdg_node):
    return cdg_node.instruction_addrs[len(cdg_node.instruction_addrs)-1]

def find_implicit_high_ins_addr(proj, cdg, ddg, cdg_node, highAddresses=[], regBlacklist=None):
    targets = cdg_node[0].successors
    if len(targets) < 2:
        if len(targets) == 1:
            return find_implicit_high_ins_addr(proj, cdg, ddg, targets, highAddresses, regBlacklist)
        return []
    isHigh = test_high_branch_context(proj, cdg, ddg, cdg_node, highAddresses, regBlacklist=None)
    if not isHigh:
        return []

    #Naive approach for now, simply mark first branch block instructions as high (taking the addrs from the longer block)
    implicit_highs = []
    start_index = 0
    for i in range(min(len(targets[0].instruction_addrs),len(targets[1].instruction_addrs))):
        if list(reversed(targets[0].instruction_addrs))[i] == list(reversed(targets[1].instruction_addrs))[i]:
            start_index += 1
    for target in targets:
        for i in range(start_index, len(target.instruction_addrs)):
            implicit_highs.append(list(reversed(target.instruction_addrs))[i])

    return implicit_highs

def find_cdg_node(cdg, block_addr):
    for n in cdg.graph.nodes:
        if n.addr == block_addr:
            return n
    return None

def find_cfg_node(cfg, block_addr):
    for n in cfg.graph.nodes:
        if n.addr == block_addr:
            return n
    return None

def find_first_reg_occurences_in_cdg_node(super_dep_graph, cfg_node, reg_offset, ins_offset):
    for ins_addr in reversed(list(cfg_node.instruction_addrs)):
        if ins_offset and ins_addr > ins_offset:
            continue
        n = get_rda_reg_var(super_dep_graph, ins_addr)
        if n and n.atom.reg_offset == reg_offset:
            return n
    return None

def get_rda_reg_var(super_dep_graph, ins_addr):
    for node in super_dep_graph.graph.nodes:
        if not node.codeloc.ins_addr == ins_addr:
            continue 
        if isinstance(node.atom,angr.knowledge_plugins.key_definitions.atoms.Register) and node.atom:
            return node

def find_first_reg_occurences_from_cdg_node(cdg, super_dep_graph, cfg_node, reg_offset, stop_block_addr, ins_offset = None):
    occ = find_first_reg_occurences_in_cdg_node(super_dep_graph, cfg_node, reg_offset, ins_offset)
    if occ:
        return [occ]
    if cfg_node.addr == stop_block_addr:
        return []
    occs = []
    for n in cfg_node.predecessors:
        occ = find_first_reg_occurences_from_cdg_node(cdg, super_dep_graph, n, reg_offset, stop_block_addr, None)
        occs.extend(occ)
    return occs