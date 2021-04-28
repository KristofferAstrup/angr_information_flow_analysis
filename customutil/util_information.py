import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
from networkx.drawing.nx_pydot import graphviz_layout

#Capture all relevant functions (main and all post main in cfg)
#inclusive
def get_unique_reachable_function_addresses(cfg, start_node):
    function_addrs = []
    for n in nx.descendants(cfg.graph, start_node):
        if not n.function_address in function_addrs:
            function_addrs.append(n.function_address)
    return function_addrs

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

def get_regs(proj):
    for k in proj.arch.registers:
        offset, size = proj.arch.registers[k]
        yield {"name": k, "offset": offset, "size": size}

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

def find_cfg_nodes(cfg, block_addr):
    for n in cfg.graph.nodes:
        if n.addr == block_addr:
            yield n
    return None

def find_cfg_function_node(cfg, function_name):
    for n in cfg.graph.nodes:
        if n.name == function_name:
            return n
    return None
    
def find_addrs_of_function(kb, function_name):
    func = kb.functions.function(name=function_name)
    if not func:
        return []
    addrs = []
    for block in func.blocks:
        if hasattr(block, 'instruction_addrs'):
            addrs.extend(block.instruction_addrs)
        else:
            addrs.append(block.addr)
    for endpoint in func.endpoints:
        addrs.append(endpoint.addr)
    return addrs

def find_func_from_addrs(proj, addrs):
    for addr in addrs:
        try:
            yield proj.kb.functions.get_by_addr(addr)
        except:
            pass

def find_func_from_addr(proj, addr):
    return proj.kb.functions.get_by_addr(addr)

def find_first_reg_occurences_in_cfg_node(rda_graph, cfg_node, reg_offset, ins_offset):
    if not cfg_node.block:
        return None
    for ins in reversed(cfg_node.block.capstone.insns):
        ins_addr = ins.address
        if ins_offset and ins_addr > ins_offset:
            continue
        if len(ins.operands) < 1:
            continue
        left_operand = ins.operands[0]
        if left_operand.reg * 2 == reg_offset or left_operand.access == 2 or left_operand.access == 3:
            return ins_addr
    return None

def get_rda_reg_vars(rda_graph, ins_addr):
    for node in rda_graph.nodes:
        if not node.codeloc.ins_addr == ins_addr:
            continue 
        if isinstance(node.atom,angr.knowledge_plugins.key_definitions.atoms.Register) and node.atom:
            yield node

def find_first_reg_occurences_from_cfg_node(rda_graph, cfg_node, reg_offset, stop_block_addr, ins_offset = None):
    occ_addr = find_first_reg_occurences_in_cfg_node(rda_graph, cfg_node, reg_offset, ins_offset)
    if occ_addr:
        for reg_var in get_rda_reg_vars(rda_graph, occ_addr):
            if reg_var and reg_var.atom.reg_offset == reg_offset:
                return [reg_var]
        return []
    if cfg_node.addr == stop_block_addr:
        return []
    occs = []
    for n in cfg_node.predecessors:
        occ = find_first_reg_occurences_from_cfg_node(rda_graph, n, reg_offset, stop_block_addr, None)
        occs.extend(occ)
    return occs