import angr
from information_flow_analysis import information, out, explicit, implicit, progress, termination, timing, rda

class InformationFlowAnalysis:
    def __init__(self, proj, high_addrs, state=None, start=None, progress_args=None, termination_args=None, timing_args=None):
        self.project = proj
        self.state = state if state else proj.factory.entry_state()
        self.simgr = proj.factory.simgr(self.state)
        self.cfg = information.cfg_emul(self.project, self.simgr, self.state)
        self.ddg = proj.analyses.DDG(cfg = self.cfg)
        self.cdg = proj.analyses.CDG(cfg = self.cfg)
        self.high_addrs = high_addrs
        self.implicit_high_blocks = []

        self.start_node = None
        if isinstance(start, int):
            self.start_node = self.cfg.model.get_any_node(addr=start)
        if isinstance(start, str):
            self.start_node = information.find_cfg_function_node(self.cfg, start)
        if not self.start_node:
            self.start_node = self.cfg.model.get_any_node(addr=self.state.addr)

        self.function_addrs = information.get_unique_reachable_function_addresses(self.cfg, self.start_node)
        self.rda_graph = rda.get_super_dep_graph_with_linking(self.project, self.cfg, self.start_node, func_addrs=self.function_addrs)
        self.post_dom_tree = self.cdg.get_post_dominators()

        self.set_termination_args(termination_args)
        self.set_progress_args(progress_args)
        self.set_timing_args(timing_args)
        
        self.simgr.explore(find=self.start_node.addr)
        if len(self.simgr.found) < 1:
            raise("No main entry block state found!")
        self.state = self.simgr.found[0]
        self.__enrich_rda__()

    def draw_everything(self):
        self.cfg_fast = self.project.analyses.CFGFast()
        self.cfg_fast = out.transform_cfg_reachable(self.cfg_fast, self.start_node.addr)
        out.draw_everything_with_data(self.project, self.cfg, self.cfg_fast, self.cdg, self.post_dom_tree, self.rda_graph)

    def set_termination_args(self, termination_args):
        self.__termination_args = termination_args if termination_args else self.__default_termination_args()

    def set_progress_args(self, progress_args):
        self.__progress_args = progress_args if progress_args else self.__default_progress_args()
        self.__subject_addrs = []
        for function in self.__progress_args.functions:
            self.__subject_addrs.extend(self.__find_subject_addrs(function.name, function.registers))

    def set_timing_args(self, timing_args):
        self.__timing_args = timing_args if timing_args else self.__default_timing_args()

    def find_explicit_flows(self, subject_addrs=None):
        subject_addrs = self.__subject_addrs if not subject_addrs else subject_addrs
        if not subject_addrs:
            print("Warning: No subject addresses found for the given ProgressFunctions")
            return
        self.__enrich_rda__()
        flows = []
        for explicit_flow in explicit.find_explicit(rda_graph=self.rda_graph, subject_addrs=subject_addrs):
            flows.append(explicit_flow)
        return flows

    def find_implicit_flows(self, subject_addrs=None):
        subject_addrs = self.__subject_addrs if not subject_addrs else subject_addrs
        if not subject_addrs:
            print("Warning: No subject addresses found for the given ProgressFunctions")
            return
        self.__enrich_rda__()
        flows = []
        for implicit_flow in implicit.find_implicit(rda_graph=self.rda_graph, subject_addrs=subject_addrs):
            flows.append(implicit_flow)
        return flows

    def find_termination_leaks(self):
        return self.find_covert_leaks(progress_args=ProgressArgs(functions=[],included=False),timing_args=TimingArgs(functions=[],included=False))

    def find_progress_leaks(self):
        return self.find_covert_leaks(termination_args=TerminationArgs(included=False),timing_args=TimingArgs(functions=[],included=False))

    def find_timing_leaks(self):
        return self.find_covert_leaks(termination_args=TerminationArgs(included=False),progress_args=ProgressArgs(functions=[],included=False))
    
    #---Precedence---
    #   Explicit (static)
    #   Implicit (static)
    #   Termination (concolic)
    #   Progress (concolic)
    #   Timing (concolic)
    #----------------
    def analyze(self, progress_args=None, termination_args=None, timing_args=None, verbose=True):
        subject_addrs = self.__subject_addrs
        if progress_args:
            subject_addrs = []
            for function in progress_args.functions:
                subject_addrs.extend(self.__find_subject_addrs(function.name, function.registers))

        if subject_addrs:
            explicit_flows = self.find_explicit_flows(subject_addrs)
            if len(list(explicit_flows)) > 0:
                if verbose:
                    print(f"Found {len(explicit_flows)} explicit flow{('s' if len(explicit_flows) > 1 else '')}:")
                    print(explicit_flows)
                return explicit_flows
            if verbose:
                print("Found no explicit flows")

            implicit_flows = self.find_implicit_flows(subject_addrs)
            if implicit_flows:
                if verbose:
                    print(f"Found {len(implicit_flows)} implicit flow{'s' if len(implicit_flows) > 1 else ''}:")
                    print(implicit_flows)
                return implicit_flows
            if verbose:
                print("Found no implicit flows")
        else:
            if verbose:
                print("No subject addresses found, skipping implicit/explicit")

        return self.find_covert_leaks(progress_args=progress_args, termination_args=termination_args, timing_args=timing_args, verbose=verbose)

    #---Precedence---
    #   Termination (concolic)
    #   Progress (concolic)
    #   Timing (concolic)
    #----------------
    def find_covert_leaks(self, progress_args=None, termination_args=None, timing_args=None, verbose=True):
        termination_args = self.__termination_args if not termination_args else termination_args
        progress_args = self.__progress_args if not progress_args else progress_args
        timing_args = self.__timing_args if not timing_args else timing_args

        start_state = self.state.copy()
        simgr = self.project.factory.simgr(start_state)
        self.__covert_simgr = simgr
        self.__branching_id_counter = 0
        self.__progress_function_names = list(map(lambda f: f.name, progress_args.functions))
        self.__progress_function_map = {f.name : f for f in progress_args.functions}
        self.__timing_function_names = list(map(lambda f: f.name, timing_args.functions))
        self.__timing_function_map = {f.name : f for f in timing_args.functions}

        start_state.inspect.b('simprocedure', when=angr.BP_BEFORE, action=self.__call_before_handler)
        start_state.inspect.b('exit', when=angr.BP_AFTER, action=self.__call_after_handler)
        #Make bp for exiting high block (from CDG) and add instruction count to current TimingInterval of TimingPlugin
        
        start_state.register_plugin(implicit.BranchRecordPlugin.NAME, implicit.BranchRecordPlugin([]))
        start_state.register_plugin(progress.ProgressRecordPlugin.NAME, progress.ProgressRecordPlugin([],None,None))
        start_state.register_plugin(timing.TimingPlugin.NAME, timing.TimingPlugin({},timing.TimingInterval(0,0)))
        
        simgr = self.project.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=termination_args.bound, limit_concrete_loops=True, bound_reached=self.__bound_reached_handler))
        simgr.use_technique(StateStepBreakpoint(action=self.__state_step_handler))

        while(True):
            if len(simgr.active) == 0:
                break
            simgr.step()

        for term_state in simgr.deadended:
            progress_plugin = term_state.plugins[progress.ProgressRecordPlugin.NAME]
            prev_progress_depth = progress_plugin.records[len(progress_plugin.records)-1].depth if len(progress_plugin.records) > 0 else -1
            self.__save_timing(term_state, termination.TERM, prev_progress_depth)

        #Termination
        if termination_args.included:
            spinning_states = simgr.spinning if hasattr(simgr, 'spinning') else []
            if verbose:
                print("Found " + str(len(spinning_states)) + " approximately non-terminating states")
            for spinning_state in spinning_states:
                leak = termination.determine_termination_leak(spinning_state, simgr.deadended)
                if leak:
                    if verbose:
                        print("Found termination leak:")
                        print(leak)
                    return [leak]
            if verbose:
                print("Found no termination leaks")
        else:
            if verbose:
                print("Skipping excluded termination leaks")
        
        states = simgr.deadended + spinning_states
        #Progress
        if progress_args.included:
            progress_leak = progress.determine_progress_leak(states)
            if progress_leak:
                if verbose:
                    print("Found progress leak:")
                    print(progress_leak)
                return [progress_leak]
            if verbose:
                print("Found no progress leaks")
        else:
            if verbose:
                print("Skipping excluded progress leaks")

        #Timing
        if timing_args.included:
            timing_procedure_call_leaks = timing.determine_timing_procedure_call_leaks(states, simgr.deadended)
            if len(timing_procedure_call_leaks) > 0:
                if verbose:
                    print("Found " + str(len(timing_procedure_call_leaks)) + " timing procedure call leaks:")
                    for leak in timing_procedure_call_leaks:
                        print(leak)
                return timing_procedure_call_leaks

            timing_procedure_leak = timing.determine_timing_procedure_leak(states, simgr.deadended)
            if timing_procedure_leak:
                if verbose:
                    print("Found timing procedure leak:")
                    print(timing_procedure_leak)
                return [timing_procedure_leak]
            if verbose:
                print("Found no timing procedure leaks")

            timing_instruction_leak = timing.determine_timing_instruction_leak(states, simgr.deadended, timing_args.epsilon)
            if timing_instruction_leak:
                if verbose:
                    print("Found timing instruction leak:")
                    print(timing_instruction_leak)
                return [timing_instruction_leak]
            if verbose:
                print("Found no timing instruction leaks")
        else:
            if verbose:
                print("Skipping excluded timing leaks")

        if verbose:
            print("No leaks found")
        return []

    def __enrich_rda__(self):
        explicit.enrich_rda_graph_explicit(self.rda_graph, self.high_addrs, self.__subject_addrs)
        enriched_blocks = implicit.enrich_rda_graph_implicit(self.rda_graph, self.cdg, self.function_addrs)
        implicit_high_blocks = list(map(lambda x: x[1], filter(lambda t: t[0] == 2, enriched_blocks)))
        self.implicit_high_blocks = list(set(self.implicit_high_blocks + implicit_high_blocks))
        self.implicit_high_block_map = {b.addr : b for b in implicit_high_blocks}

    def __bound_reached_handler(self, loopSeer, succ_state):
        print("Found approximately non-terminating state at " + str(hex(succ_state.addr)) + " by reaching bound")
        loopSeer.cut_succs.append(succ_state)

    def __state_step_handler(self, base_state, stashes):
        succs = stashes[None] #Effectively our active successor states
        if len(succs) < 2:
            return
        is_high = False
        for block in self.implicit_high_blocks:
            for succ in succs:
                if block.addr == succ.addr:
                    is_high = True
        if not is_high:
            return
        record = implicit.BranchRecord(base_state.addr, base_state.history.block_count + 1, self.__branching_id_counter)
        self.__branching_id_counter += 1
        for succ in succs:
            succ.plugins[implicit.BranchRecordPlugin.NAME].records.insert(0, record)

    def __call_before_handler(self, state):
        sim_name = state.inspect.simprocedure_name
        if sim_name in self.__progress_function_names:
            self.__progress_function_call(state, sim_name)
        if sim_name in self.__timing_function_names:
            self.__timing_function_call(state, sim_name)
            
    def __progress_function_call(self, state, name):
        plugin = state.plugins[progress.ProgressRecordPlugin.NAME]
        plugin.callfunction = self.__progress_function_map[name]
        plugin.callstate = state.copy()

    def __timing_function_call(self, state, name):
        timing_func = self.__timing_function_map[name]
        plugin = state.plugins[timing.TimingPlugin.NAME]

        high_arg_regs = []
        for arg_reg in timing_func.registers:
            offset, size = self.__unwrap_argument_register(arg_reg)
            occ_node = information.find_first_reg_occurence_from_history(self.project, self.rda_graph, state.history, offset, self.start_node.addr, reg_size=size)
            if occ_node and implicit.check_node_high(occ_node):
                high_arg_regs.append(timing.HighArgument(arg_reg, occ_node.codeloc.ins_addr))
        if len(high_arg_regs) > 0:
            call = timing.HighArgumentCall(high_arg_regs, state.addr)
            plugin.temp_interval.high_arg_calls.append(call)

        call_high = self.__is_high_procedure_call(state, name)
        if call_high:
            acc_val = timing_func.accumulate_delegate(state)
            plugin.temp_interval.acc += acc_val

    def __call_after_handler(self, state):
        plugin = state.plugins[progress.ProgressRecordPlugin.NAME]
        if not plugin.callfunction:
            return
        if state.addr in plugin.callfunction.addrs:
            return
        if not plugin.callstate:
            return
        sim_name = plugin.callstate.inspect.simprocedure_name
        prev_progress_depth = plugin.records[len(plugin.records)-1].depth if len(plugin.records) > 0 else -1
        progress_obj = plugin.callfunction.progress_delegate(plugin.callstate, state)
        call_addr = plugin.callstate.addr
        call_high = self.__is_high_procedure_call(plugin.callstate, sim_name)
        progress_index = plugin.records[-1].index + 1 if len(plugin.records) > 0 else 0
        progress_record = progress.ProgressRecord(progress_obj, state.history.block_count, call_high, call_addr, progress_index)
        plugin.callfunction = None
        plugin.callstate = None
        plugin.records.append(progress_record)
        self.__save_timing(state, len(plugin.records)-1, prev_progress_depth)
        
    def __save_timing(self, state, key, prev_progress_depth):
        timing_plugin = state.plugins[timing.TimingPlugin.NAME]
        timing_plugin.temp_interval.ins_count = timing.get_history_high_instruction_count(state, prev_progress_depth, self.implicit_high_block_map)
        timing_plugin.map[key] = timing_plugin.temp_interval
        timing_plugin.temp_interval = timing.TimingInterval(0,0)

    def __default_termination_args(self):
        return TerminationArgs()

    def __default_progress_args(self):
        return ProgressArgs(functions=[
                progress.PutsProgressFunction(self.project.kb),
                progress.PrintfProgressFunction(self.project.kb)
        ])

    def __default_timing_args(self):
        return TimingArgs(functions=[timing.SleepTimingFunction()])
    
    def __find_subject_addrs(self, procedure_name, arg_regs):
        if not arg_regs or len(arg_regs) == 0:
            cc_args = information.get_sim_proc_reg_args(self.project, procedure_name)
            arg_regs = list(map(lambda r: r.reg_name, cc_args)) if cc_args else []
        if len(arg_regs) == 0:
            print("Warning: " + procedure_name + " has no argument registers!")
            return []
        subject_addrs = []
        for wrap_addr in information.get_sim_proc_function_wrapper_addrs(self.project, procedure_name):
            for wrapper in information.find_cfg_nodes(self.cfg, wrap_addr):
                for caller in wrapper.predecessors:
                    for arg_reg in arg_regs:
                        offset, size = self.__unwrap_argument_register(arg_reg)
                        for occ_node in information.find_first_reg_occurences_from_cfg_node(self.project, self.rda_graph, caller, offset, [self.start_node.addr], reg_size=size):
                            subject_addrs.append(occ_node.codeloc.ins_addr)
        subject_addrs = list(set(subject_addrs))
        return subject_addrs

    def __is_high_procedure_call(self, state, procedure_name):
        wrap_addrs = list(information.get_sim_proc_and_wrapper_addrs(self.project, procedure_name))
        his = state.history
        while his.addr in wrap_addrs:
            his = his.parent
        is_high = his.addr in self.implicit_high_block_map
        return is_high

    def __unwrap_argument_register(self, arg_reg):
        if isinstance(arg_reg, str):
            offset, size = self.project.arch.registers[arg_reg]
        elif isinstance(arg_reg, int):
            offset = arg_reg
            size = None
        else:
            raise Exception("Argument registers must be either an integer (offset) or a string (register name)!")
        return (offset, size)

#Since a angr.BP_BEFORE breakpoint on fork doesn't work we do this manually...
class StateStepBreakpoint(angr.exploration_techniques.ExplorationTechnique):
    action = None #Should take a state and a stash dictionary

    def __init__(self, action):
        self.action = action
        if not self.action:
            raise Exception("Must set action!")

    def step_state(self, simgr, state, **kwargs):
        res = simgr.step_state(state, **kwargs)
        self.action(state, res)
        return res

class TerminationArgs():
    def __init__(self, termination_observable=True, bound=50, included=True):
        self.bound = bound
        self.included = included

class ProgressArgs():
    def __init__(self, functions, included=True):
        self.functions = functions
        self.included = included

class TimingArgs():
    def __init__(self, functions, epsilon=20, included=True):
        self.functions = functions
        self.epsilon = epsilon
        self.included = included