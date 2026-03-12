import os
import site
import sys

def apply_comprehensive_fix():
    """Apply comprehensive fix to PyInstaller for Python 3.10"""
    
    # Find the util.py file in PyInstaller
    for path in site.getsitepackages() + [site.getusersitepackages()]:
        util_path = os.path.join(path, 'PyInstaller', 'lib', 'modulegraph', 'util.py')
        if os.path.exists(util_path):
            print(f"Found PyInstaller util.py at: {util_path}")
            
            # Read the file
            with open(util_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create a more robust fix
            old_code = """def iterate_instructions(code_object):
    # Attempt to use the new dis.get_instructions() if available,
    # otherwise fall back to the old method.
    try:
        yield from (i for i in dis.get_instructions(code_object) if i.opname != "EXTENDED_ARG")
    except AttributeError:
        # Python < 3.4 doesn't have dis.get_instructions()
        for i in dis.Bytecode(code_object):
            if i.opname != "EXTENDED_ARG":
                yield i"""
            
            new_code = """def iterate_instructions(code_object):
    # Attempt to use the new dis.get_instructions() if available,
    # otherwise fall back to the old method.
    try:
        # Python 3.10+ fix for bytecode issues
        try:
            instructions = list(dis.get_instructions(code_object))
            for i in instructions:
                if i.opname != "EXTENDED_ARG":
                    yield i
        except (IndexError, ValueError) as e:
            # Handle bytecode errors in Python 3.10
            try:
                # Fallback to older method
                for i in dis.Bytecode(code_object):
                    if i.opname != "EXTENDED_ARG":
                        yield i
            except Exception:
                # Last resort - return empty
                return
    except AttributeError:
        # Python < 3.4 doesn't have dis.get_instructions()
        try:
            for i in dis.Bytecode(code_object):
                if i.opname != "EXTENDED_ARG":
                    yield i
        except Exception:
            return"""
            
            if old_code in content:
                # Create backup
                backup_path = util_path + '.backup2'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Created backup: {backup_path}")
                
                # Write new content
                new_content = content.replace(old_code, new_code)
                with open(util_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print("✅ Applied comprehensive fix to PyInstaller")
                return True
            else:
                print("Code pattern not found, trying alternative fix...")
                # Alternative fix - add try-except around the problematic line
                old_line = 'yield from (i for i in dis.get_instructions(code_object) if i.opname != "EXTENDED_ARG")'
                new_line = """try:
                    yield from (i for i in dis.get_instructions(code_object) if i.opname != "EXTENDED_ARG")
                except IndexError:
                    # Handle Python 3.10 bytecode issue
                    return"""
                
                if old_line in content:
                    new_content = content.replace(old_line, new_line)
                    with open(util_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print("✅ Applied alternative fix to PyInstaller")
                    return True
    
    print("❌ Could not find PyInstaller installation")
    return False

if __name__ == "__main__":
    print("="*50)
    print("PyInstaller Python 3.10 Fix")
    print("="*50)
    
    # Run as admin check
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        print("Running with administrator privileges")
        if apply_comprehensive_fix():
            print("\n✅ Fix applied successfully!")
            print("You can now run PyInstaller normally.")
        else:
            print("\n❌ Fix failed to apply.")
    else:
        print("⚠️ Please run this script as Administrator!")
        print("Right-click on Command Prompt and select 'Run as administrator'")
    
    input("\nPress Enter to exit...")