# Test file for Python getattr evasion detection
# These patterns should be detected as potential code injection

import os
import subprocess

class ModuleProxy:
    def execute_command(self, cmd):
        return os.system(cmd)

    def run_subprocess(self, cmd):
        return subprocess.run(cmd, shell=True)

# Pattern 1: getattr with user-controlled attribute name from dict
def dangerous_dispatch(user_data):
    """Attacker controls which method is called via user_data['action']"""
    proxy = ModuleProxy()
    func_name = user_data.get("action")  # User-controlled function name
    method = getattr(proxy, func_name)   # DETECT: getattr with tainted variable
    return method(user_data.get("cmd"))

# Pattern 2: getattr with attribute from request
def web_handler(request):
    """Flask/Django style - attribute from request object"""
    method_name = request.args.get('method')  # User input
    handler = getattr(os, method_name)        # DETECT: getattr with user-derived var
    return handler(request.args.get('arg'))

# Pattern 3: getattr with variable from dictionary key access
def config_executor(config):
    """Execute method based on config key"""
    action = config["execute"]              # Dictionary access
    func = getattr(subprocess, action)      # DETECT: getattr with user-derived var
    return func(config["args"])

# Pattern 4: Chained getattr - harder to detect
def indirect_getattr(user_input):
    """Attribute name comes from user input"""
    method = user_input  # Direct assignment from parameter (tainted)
    module = __import__('os')
    return getattr(module, method)()  # DETECT: getattr with tainted var

# Safe patterns (should NOT be flagged or lower confidence)
def safe_getattr():
    """Static attribute access - not user controlled"""
    return getattr(os, 'getcwd')()

def safe_dynamic_but_validated(user_input):
    """Validated against whitelist"""
    allowed = ['read', 'write', 'list']
    if user_input in allowed:
        return getattr(some_module, user_input)()
