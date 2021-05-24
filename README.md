# Binary Information Flow Analysis tool using Angr
Install using [`pip install information-flow-analysis`](https://pypi.org/project/information-flow-analysis/#description).

## Output relevant graphs
### Output CFGS
Use `out.cfgs()` in order to print all relevant control flow graphs in an seperate `/out` folder.

An example of this is could be:
```python
import angr
import claripy
from information_flow_analysis import out

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])

    out.cfgs()
    return 0
    
if __name__ == "__main__":
    main()
```
Generally you want to look at the `cfg_fast.pdf` as it contains relevant information about instructions. This CFG is also very relevant in order to locate which `high_addrs` you will make confidential.

### Output all relevant graphs within the `InformationFlowAnalysis` object
Use `IFA.draw_everything()` in order to print all relevant graphs contained in the `IFA`-object in an seperate `/out` folder.

An example of this is could be:
```python
import angr
import claripy
from information_flow_analysis import analysis

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])

    high_addrs = [0x4011a6, 0x4011a9]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.draw_everything()
    return 0
    
if __name__ == "__main__":
    main()
```
This is primarily used to debugging purposes or if you manually want to check for leaks. (NOTE: That you need to supply `high_addrs` in order to do this)

## Usage of `analyze` Information Flow Analysis object
```python
import angr
import claripy
from information_flow_analysis import analysis

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])

    high_addrs = [0x4011a6, 0x4011a9]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.analyze()
    return 0
    
if __name__ == "__main__":
    main()
```
## Usage of `find_explicit_leaks` Information Flow Analysis object
```python
import angr
import claripy
from information_flow_analysis import analysis

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])

    high_addrs = [0x4011a6, 0x4011a9]

    ifa = analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    ifa.find_explicit_leaks()
    return 0
    
if __name__ == "__main__":
    main()
```
