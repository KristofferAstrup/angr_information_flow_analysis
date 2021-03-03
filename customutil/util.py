import angr
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx

def cfgs(proj, simgr, state):
    try:
        print("--CFG--")
        cfg = proj.analyses.CFG()
        plot_cfg(cfg, "cfg", "pdf")  
        print("Plotted to cfg.pdf")
    except Exception as e:
        print(e)
    try:
        print("--CFGEmulated--")
        cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, starts=[simgr.active[0].addr], initial_state=state, context_sensitivity_level=2, resolve_indirect_jumps=True)
        plot_cfg(cfg, "cfg_emul", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)
        print("Plotted to cfg_emul.pdf")
    except Exception as e:
        print(e)
    try:
        print("--CFGFast--")
        cfg_fast = proj.analyses.CFGFast()
        plot_cfg(cfg_fast, "cfg_fast", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  
        print("Plotted to cfg_fast.pdf")
    except Exception as e:
        print(e)

def write_stashes(simgr, filename="stash_summary.txt", args=[], input_write_stashes=[]):
    file = open(filename,"w+") 
    print('--stashes--')
    for key in simgr.stashes:
        string = str(key) + ": " + str(len(simgr.stashes[key]))
        print(string)
        writeline(file, string)
    print('writing...')
    for key in simgr.stashes:
        writeline(file, "===" + str(key) + ": " + str(len(simgr.stashes[key])) + "===")
        for c in range(len(simgr.stashes[key])):
            stash = simgr.stashes[key][c]
            writeline(file, "no: " + str(c))
            writeline(file, str(stash.addr))
            for d in range(3):
                try:
                    writeline(file, "dump["+str(d)+"]: " + str(stash.posix.dumps(d)))
                except Exception as e:
                    print("dump["+str(d)+"]: eval failure")
            for i in range(len(args)):
                writeline(file, "arg" + str(i) + " " + get_str_from_arg(stash, args[i]))
                if(key in input_write_stashes):
                    inputfile = open(key + str(c) + "_input" + str(i),"wb+")
                    inputfile.write(stash.solver.eval(args[i], cast_to=bytes))
                    inputfile.close()
            writeline(file, "-----")
    print('written to ' + filename)
    file.close()

def get_str_from_arg(state, arg):
    str = ""
    solutions = gather_evals(state, arg, 5)
    for bs in solutions:
        try:
            str += bs.decode('UTF-8') + " |\n "
        except:
            str += "no utf-8 |\n "
    return str

def gather_evals(state, arg, max):
    solutions = []
    try:
        for i in range(max):
            solutions = state.solver.eval_upto(arg, i, cast_to=bytes)
    except:
        pass
    return solutions

def writeline(file, string):
    file.write(string + "\n")

def writefile(string, filename):
    file = open(filename,"w+") 
    file.write(string)
    file.close()

def draw_ddg(ddg):
    draw_graph(ddg.graph, "ddg.pdf")
    
def draw_graph(graph, fname="graph.pdf"):
    fig = plt.figure(figsize=(200,200))
    nx.draw(graph, with_labels=True)
    fig.savefig(fname, dpi=5)

def find_explicit(proj, ddg, lowAddresses=[], lowNodes=None, highAddresses=[], regBlacklist=None):
    if regBlacklist == None:
        regBlacklist = [proj.arch.ip_offset]
    targetNodes = []

    if lowNodes:
        targetNodes = lowNodes
    else:
        for n in ddg.data_graph.nodes(data=True):
            if n[0].location.ins_addr in lowAddresses and not isinstance(n[0].variable, SimConstantVariable):
                if(n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist):
                    continue
                targetNodes.append(n[0])

    for n in ddg.data_graph.nodes(data=True):
        if n[0].location.ins_addr in highAddresses and not isinstance(n[0].variable, SimConstantVariable):
            if n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist:
                continue
            sub = ddg.data_sub_graph(n[0], simplified=False) #killing_edges=True)
            for targetNode in targetNodes:
                try:
                    yield nx.dijkstra_path(sub,n[0],targetNode)
                except:
                    pass #No path

def find_procedure_nodes(proj, ddg, sim_proc_name, regBlacklist=None):
    if regBlacklist == None:
        regBlacklist = [proj.arch.ip_offset]
    for n in ddg.data_graph.nodes(data=True):
        if not isinstance(n[0].variable, SimConstantVariable)\
        and n[0].location\
        and n[0].location.sim_procedure\
        and n[0].location.sim_procedure.display_name == sim_proc_name:
            if(n[0].variable and isinstance(n[0].variable, SimRegisterVariable) and n[0].variable.reg in regBlacklist):
                continue
            yield n[0]

def find_ddg_program_arg_nodes(proj, ddg, addr=None):
    if addr == None:
        addr = proj.entry
    arg_regs = proj.arch.argument_registers
    ent_reg_vals = proj.arch.entry_register_values
    reg_names = ['argv', 'argc']
    reg_offs = []
    for p, v in ent_reg_vals.items():
        if v in reg_names:
            off, size = proj.arch.registers[p]
            reg_offs.append(off)
    print(reg_offs)
    print('---')
    for n in ddg.data_graph.nodes(data=True):
        if n[0].location.block_addr == addr and isinstance(n[0].variable, SimRegisterVariable):
            if n[0].variable.reg in reg_offs:
                yield n[0]

def find_ddg_nodes(ddg, ins_addr):
    for n in ddg.data_graph.nodes(data=True):
        if n[0].location and n[0].location.ins_addr == ins_addr:
            yield n[0]

def hexlist(seq):
    return list(map(lambda x: hex(x), seq))

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
            isinstance(n[0].variable, SimRegisterVariable)\
            n[0].variable.reg == reg_offset:
            return n
    return None

def get_arg_regs(proj):
    for arg_reg_offset in proj.arch.argument_registers:
        for k in proj.arch.registers:
            offset, size = proj.arch.registers[k]
            if offset == arg_reg_offset:
                yield (k, offset, size)

def get_sim_proc_reg_args(proj, sim_proc_name):
    for k in proj._sim_procedures:
        if proj._sim_procedures[k].display_name == sim_proc_name:
            return proj._sim_procedures[k].cc.args

def get_sim_proc_addr(proj, sim_proc_name):
    for k in proj._sim_procedures:
        if proj._sim_procedures[k].display_name == sim_proc_name:
            return proj._sim_procedures[k].addr

def get_sim_proc_function_wrapper_addrs(proj, sim_proc_name):
    sim_addr = get_sim_proc_addr(proj, sim_proc_name)
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

#cfg_node is type CFGENode and is also used in cdg
def find_first_reg_occurences_in_cdg_node(ddg, cfg_node, reg_offset, ins_offset):
    for ins_addr in cfg_node.instruction_addrs.reverse():
        if ins_offset != None and ins_addr > ins_offset:
            continue
        n = get_ddg_reg_var(ddg, ins_addr, reg_offset)
        if n != None:
            return n
    return None

def find_first_reg_occurences_from_cdg_node(cdg, ddg, cfg_node, reg_offset, ins_offset):
    occ = find_first_reg_occurences_in_cdg_node(ddg, cfg_node, reg_offset, ins_offset)
    if occ != None:
        return [occ]
    occs = []
    for n in cfg_node.predecessors:
        occ = find_first_reg_occurences_from_cdg_node(cdg, ddg, n, reg_offset, None)
        occs.append(occ)
    return occs

def test_high_branch_context(cdg, highAddresses=[]):
    branch_ins = None
    for n in cdg.graph.nodes(data=True):
        if n[0].block_id and n[0].block_id.addr == branch_addr:
            branch_ins = n[0].instruction_addrs[len(n[0].instruction_addrs)-1]
    for path in util.find_explicit(proj, ddg, [branch_ins], highAddresses):
        return True #High context
    return False #Low context (not proven high)

def find_implicit_high_ins_addr(cdg, cdg_node, highAddresses=[]):
    targets = cdg.get_guardians(cdg_node):
    if len(targets) < 2:
        if len(targets) == 1:
            return find_branches(cdg, targets[0])
        return []
    isHigh = test_high_branch_context(cdg, highAddresses)
    return []
    #TODO: Should be recursive!!

#find branches and test if they create a high context
#return the instruction adresses of the high context