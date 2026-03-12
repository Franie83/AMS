import os
import site

def fix_indentation():
    """Fix indentation in PyInstaller util.py"""
    
    # Find the util.py file
    for path in site.getsitepackages() + [site.getusersitepackages()]:
        util_path = os.path.join(path, 'PyInstaller', 'lib', 'modulegraph', 'util.py')
        if os.path.exists(util_path):
            print(f"Found util.py at: {util_path}")
            
            # Read the file
            with open(util_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Find the iterate_instructions function and fix its indentation
            fixed_lines = []
            i = 0
            in_function = False
            function_indent = 0
            
            while i < len(lines):
                line = lines[i]
                
                # Check if we're entering the iterate_instructions function
                if 'def iterate_instructions' in line and not in_function:
                    in_function = True
                    function_indent = len(line) - len(line.lstrip())
                    fixed_lines.append(line)
                    i += 1
                    continue
                
                if in_function:
                    # Check if we're leaving the function
                    if i < len(lines) and lines[i].strip() and len(lines[i]) - len(lines[i].lstrip()) <= function_indent:
                        in_function = False
                        fixed_lines.append(line)
                        i += 1
                        continue
                    
                    # Fix the try-except block
                    if 'try:' in line:
                        fixed_lines.append(' ' * (function_indent + 4) + 'try:\n')
                        i += 1
                        # Handle the next lines inside try
                        while i < len(lines) and 'except' not in lines[i]:
                            if lines[i].strip():
                                fixed_lines.append(' ' * (function_indent + 8) + lines[i].lstrip())
                            else:
                                fixed_lines.append(lines[i])
                            i += 1
                        continue
                    
                    if 'except IndexError:' in line:
                        fixed_lines.append(' ' * (function_indent + 4) + 'except IndexError:\n')
                        i += 1
                        # Handle the next lines inside except
                        while i < len(lines) and lines[i].strip() and (len(lines[i]) - len(lines[i].lstrip())) > function_indent + 4:
                            if lines[i].strip():
                                fixed_lines.append(' ' * (function_indent + 8) + lines[i].lstrip())
                            else:
                                fixed_lines.append(lines[i])
                            i += 1
                        continue
                    
                    # Fix any other lines with wrong indentation
                    if line.strip():
                        current_indent = len(line) - len(line.lstrip())
                        if current_indent < function_indent + 4:
                            # This line has wrong indentation, fix it
                            fixed_lines.append(' ' * (function_indent + 4) + line.lstrip())
                        else:
                            fixed_lines.append(line)
                        i += 1
                    else:
                        fixed_lines.append(line)
                        i += 1
                else:
                    fixed_lines.append(line)
                    i += 1
            
            # Write the fixed file
            backup_path = util_path + '.indent_backup'
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"Created backup: {backup_path}")
            
            with open(util_path, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)
            print("✅ Fixed indentation in util.py")
            return True
    
    print("❌ Could not find util.py")
    return False

if __name__ == "__main__":
    print("="*50)
    print("Fixing PyInstaller Indentation")
    print("="*50)
    
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        if fix_indentation():
            print("\n✅ Indentation fixed successfully!")
            print("You can now run PyInstaller.")
        else:
            print("\n❌ Failed to fix indentation.")
    else:
        print("⚠️ Please run as Administrator!")
    
    input("\nPress Enter to exit...")