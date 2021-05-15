import angr
from customutil import util_information, util_out, util_explicit, util_implicit, util_progress, util_termination, util_timing, util_rda

class InformationFlowAnalysis:
    def __init__(self, proj, high_addrs, state=None, start=None, progress_args=None, termination_args=None, timing_args=None):
        self.project = proj
        self.state = state if state else proj.factory.entry_state()
        self.simgr = proj.factory.simgr(self.state)#, hierarchy=angr.state_hierarchy.StateHierarchy())
        self.cfg = util_information.cfg_emul(self.project, self.simgr, self.state)
        self.ddg = proj.analyses.DDG(cfg = self.cfg)
        self.cdg = proj.analyses.CDG(cfg = self.cfg)
        self.high_addrs = high_addrs
        self.implicit_high_blocks = []

        self.start_node = None
        if isinstance(start, int):
            self.start_node = self.cfg.model.get_any_node(addr=start)
        if isinstance(start, str):
            self.start_node = util_information.find_cfg_function_node(self.cfg, start)
        if not self.start_node:
            self.start_node = self.cfg.model.get_any_node(addr=self.state.addr)

        self.function_addrs = util_information.get_unique_reachable_function_addresses(self.cfg, self.start_node)
        self.rda_graph = util_rda.get_super_dep_graph_with_linking(self.project, self.cfg, self.start_node, func_addrs=self.function_addrs)
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
        util_out.draw_everything_with_data(self.project, self.cfg, self.cfg_fast, self.cdg, self.post_dom_tree, self.rda_graph)

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
        for explicit_flow in util_explicit.find_explicit(rda_graph=self.rda_graph, subject_addrs=subject_addrs):
            flows.append(explicit_flow)
        return flows

    def find_implicit_flows(self, subject_addrs=None):
        subject_addrs = self.__subject_addrs if not subject_addrs else subject_addrs
        if not subject_addrs:
            print("Warning: No subject addresses found for the given ProgressFunctions")
            return
        self.__enrich_rda__()
        flows = []
        for implicit_flow in util_implicit.find_implicit(rda_graph=self.rda_graph, subject_addrs=subject_addrs):
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

        return find_covert_leaks(self, progress_args, termination_args, timing_args, verbose)

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
        
        start_state.register_plugin(util_implicit.BranchRecordPlugin.NAME, util_implicit.BranchRecordPlugin([]))
        start_state.register_plugin(util_progress.ProgressRecordPlugin.NAME, util_progress.ProgressRecordPlugin([],None,None))
        start_state.register_plugin(util_timing.ProcedureRecordPlugin.NAME, util_timing.ProcedureRecordPlugin({},util_timing.TimingInterval(0,0)))
        
        simgr = self.project.factory.simgr(start_state)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=self.cfg, bound=termination_args.bound, limit_concrete_loops=True, bound_reached=self.__bound_reached_handler))
        simgr.use_technique(StateStepBreakpoint(action=self.__state_step_handler))

        while(True):
            if len(simgr.active) == 0:
                break
            simgr.step()

        #Termination
        if termination_args.included:
            spinning_states = simgr.spinning if hasattr(simgr, 'spinning') else []
            if verbose:
                print("Found " + str(len(spinning_states)) + " approximately non-terminating states")
            for spinning_state in spinning_states:
                leak = util_termination.determine_termination_leak(spinning_state, simgr.deadended)
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
            progress_leak = util_progress.determine_progress_leak(states)
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
            timing_procedure_leak = util_timing.determine_timing_procedure_leak(states)
            if timing_procedure_leak:
                if verbose:
                    print("Found timing procedure leak:")
                    print(timing_procedure_leak)
                return [timing_procedure_leak]
            if verbose:
                print("Found no timing procedure leaks")

            timing_instruction_leak = util_timing.determine_timing_instruction_leak(states, timing_args.epsilon)
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
        util_explicit.enrich_rda_graph_explicit(self.rda_graph, self.high_addrs, self.__subject_addrs)
        enriched_blocks = util_implicit.enrich_rda_graph_implicit(self.rda_graph, self.cdg, self.function_addrs)
        implicit_high_blocks = list(map(lambda x: x[1], filter(lambda t: t[0] == 2, enriched_blocks)))
        self.implicit_high_blocks = list(set(self.implicit_high_blocks + implicit_high_blocks))
        self.implicit_high_block_map = {b.addr : b for b in implicit_high_blocks}

    def __bound_reached_handler(self, loopSeer, succ_state):
        self.s = loopSeer
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
        record = util_implicit.BranchRecord(base_state.addr, base_state.history.block_count + 1, self.__branching_id_counter)
        self.__branching_id_counter += 1
        for succ in succs:
            succ.plugins[util_implicit.BranchRecordPlugin.NAME].records.insert(0, record)

    def __call_before_handler(self, state):
        sim_name = state.inspect.simprocedure_name
        if sim_name in self.__progress_function_names:
            self.__progress_function_call(state, sim_name)
        if sim_name in self.__timing_function_names:
            self.__timing_function_call(state, sim_name)
            
    def __progress_function_call(self, state, name):
        plugin = state.plugins[util_progress.ProgressRecordPlugin.NAME]
        plugin.callfunction = self.__progress_function_map[name]
        plugin.callstate = state

    def __timing_function_call(self, state, name):
        call_high = state.addr in self.implicit_high_block_map
        if not call_high:
            return
        plugin = state.plugins[util_timing.ProcedureRecordPlugin.NAME]
        acc_val = self.__timing_function_map[name].accumulate_delegate(state)
        plugin.temp_interval.acc += acc_val

    def __call_after_handler(self, state):
        plugin = state.plugins[util_progress.ProgressRecordPlugin.NAME]
        if not plugin.callfunction:
            return
        if state.addr in plugin.callfunction.addrs:
            return
        sim_name = state.inspect.simprocedure_name
        if not plugin.callstate:
            return
        prev_progress_depth = plugin.records[len(plugin.records)-1].depth if len(plugin.records) > 0 else -1
        progress_obj = plugin.callfunction.progress_delegate(plugin.callstate, state)
        call_addr = plugin.callstate.addr
        call_high = util_implicit.check_addr_high(self.rda_graph, call_addr)
        progress_index = plugin.records[-1].index + 1 if len(plugin.records) > 0 else 0
        progress_record = util_progress.ProgressRecord(progress_obj, state.history.block_count, call_high, call_addr, progress_index)
        plugin.callfunction = None
        plugin.callstate = None
        plugin.records.append(progress_record)
        timing_plugin = state.plugins[util_timing.ProcedureRecordPlugin.NAME]
        timing_plugin.temp_interval.ins_count = util_timing.get_history_high_instruction_count(state, prev_progress_depth, self.implicit_high_block_map)
        timing_plugin.map[len(plugin.records)-1] = timing_plugin.temp_interval
        timing_plugin.temp_interval = util_timing.TimingInterval(0,0)

    def __default_termination_args(self):
        return TerminationArgs()

    def __default_progress_args(self):
        return ProgressArgs(functions=[
                util_progress.PutsProgressFunction(self.project.kb),
                util_progress.PrintfProgressFunction(self.project.kb)
        ])

    def __default_timing_args(self):
        return TimingArgs(functions=[util_timing.SleepTimingFunction()])
    
    def __find_subject_addrs(self, procedure_name, arg_regs):
        subject_addrs = []
        arg_regs = util_information.get_sim_proc_reg_args(self.project, procedure_name) if not arg_regs else arg_regs
        for wrap_addr in util_information.get_sim_proc_function_wrapper_addrs(self.project, procedure_name):
            for wrapper in util_information.find_cfg_nodes(self.cfg, wrap_addr):
                for caller in wrapper.predecessors:
                    for reg in arg_regs:
                        offset, size = self.project.arch.registers[reg.reg_name]
                        for occ_node in util_information.find_first_reg_occurences_from_cfg_node(self.rda_graph, caller, offset, self.start_node.addr):
                            subject_addrs.append(occ_node.codeloc.ins_addr)
        subject_addrs = list(set(subject_addrs))
        return subject_addrs


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
    def __init__(self, bound=50, included=True):
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