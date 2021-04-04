import angr
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angrutils import *
import matplotlib.pyplot as plt
import networkx as nx
import pydot
import random
from customutil import util_explicit
from networkx.drawing.nx_pydot import graphviz_layout

def cfgs(proj, simgr, state):
    cfg_emul = None
    try:
        print("--CFG--")
        cfg = proj.analyses.CFG()
        plot_cfg(cfg, "cfg", "pdf")  
        print("Plotted to cfg.pdf")
    except Exception as e:
        print(e)
    try:
        print("--CFGEmulated--")
        cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, starts=[simgr.active[0].addr], initial_state=state, context_sensitivity_level=5, resolve_indirect_jumps=True)
        plot_cfg(cfg, "cfg_emul", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)
        print("Plotted to cfg_emul.pdf")
        cfg_emul = cfg
    except Exception as e:
        print(e)
    try:
        print("--CFGFast--")
        cfg_fast = proj.analyses.CFGFast()
        plot_cfg(cfg_fast, "cfg_fast", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  
        print("Plotted to cfg_fast.pdf")
    except Exception as e:
        print(e)
    return cfg_emul

def draw_everything(proj, simgr, state, start_node=None):
    cfg = cfgs(proj, simgr, state)

    print("--DDG--")
    ddg = proj.analyses.DDG(cfg = cfg)
    plot_ddg_data(ddg.data_graph, "ddg", format="pdf")
    print("Plotted to ddg.pdf")

    print("--CDG--")
    cdg = proj.analyses.CDG(cfg = cfg)
    plot_cdg(cfg, cdg, "cdg", format="pdf")
    print("Plotted to cdg.pdf")

    print("--POST_DOM--")
    postdom = cdg.get_post_dominators()
    draw_tree(postdom, fname="postdom.pdf")
    print("Plotted to postdom.pdf")

    if start_node:
        print("--SUPER_DEP_GRAPH--")
        draw_super_dep_graph(proj, cfg, cdg, start_node)
        print("Plotted to super_dep_graph.pdf")

def draw_super_dep_graph(proj, cfg, cdg, start_node, fname="super_dep_graph.pdf"):
    dep_graph = util_explicit.get_super_dep_graph_with_linking(proj, cfg, cdg, start_node)
    fig = plt.figure(figsize=(100,100))
    # for n in dep_graph.graph.nodes:
    #     print(n)
    colors = [random.random() for node in dep_graph.graph.nodes()]
    nx.draw(dep_graph.graph, cmap=plt.get_cmap('viridis'), node_color=colors, with_labels=True)
    fig.savefig(fname, dpi=5)

def write_stashes(simgr, filename="stash_summary.txt", args=[], input_write_stashes=[], verbose=True):
    file = open(filename,"w+") 
    if verbose:
        print('--stashes--')
    for key in simgr.stashes:
        string = str(key) + ": " + str(len(simgr.stashes[key]))
        if verbose:
            print(string)
        writeline(file, string)
    if verbose:
        print('writing...')
    for key in simgr.stashes:
        writeline(file, "===" + str(key) + ": " + str(len(simgr.stashes[key])) + "===")
        for c in range(len(simgr.stashes[key])):
            stash = simgr.stashes[key][c]
            writeline(file, "no: " + str(c))
            writeline(file, str(hex(stash.addr)))
            for d in range(3):
                try:
                    writeline(file, "dump["+str(d)+"]: " + str(stash.posix.dumps(d)))
                except Exception as e:
                    if verbose:
                        print("dump["+str(d)+"]: eval failure")
                    pass
            for i in range(len(args)):
                writeline(file, "arg" + str(i) + " " + get_str_from_arg(stash, args[i]))
                if(key in input_write_stashes):
                    inputfile = open(key + str(c) + "_input" + str(i),"wb+")
                    sol = stash.solver.eval(args[i], cast_to=bytes)
                    inputfile.write(sol)
                    inputfile.close()
            writeline(file, "-----")
    if verbose:
        print('written to ' + filename)
    file.close()

def get_str_from_arg(state, arg, no=5, newline=True):
    str = ""
    solutions = gather_evals(state, arg, no)
    first = True
    for bs in solutions:
        try:
            decoded_sol = bs.decode('UTF-8')
            str += ("" if first else ("\n" if newline else "|")) + decoded_sol
        except:
            str +=  ("" if first else ("\n" if newline else "|")) + "no utf-8 "
        first = False
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
    fig = plt.figure(figsize=(100,100))
    nx.draw(graph, with_labels=True)
    fig.savefig(fname, dpi=5)

def draw_tree(tree, fname="tree.pdf"):
    fig = plt.figure(figsize=(100,100))
    pos = graphviz_layout(tree, prog="dot")
    nx.draw(tree, pos,with_labels=True)
    fig.savefig(fname, dpi=5)

def hexlist(seq):
    return list(map(lambda x: hex(x), seq))
