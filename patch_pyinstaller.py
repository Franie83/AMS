import os
import site
import sys

def patch_pyinstaller():
    # Find PyInstaller installation
    for path in site.getsitepackages():
        hook_path = os.path.join(path, 'PyInstaller', 'lib', 'modulegraph', 'util.py')
        if os.path.exists(hook_path):
            print(f"Found PyInstaller at: {hook_path}")
            
            # Read the file
            with open(hook_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Add try-except around the get_instructions call
            patched_content = content.replace(
                'yield from (i for i in get_instructions(code_object) if i.opname != "EXTENDED_ARG")',
                'try:\n            yield from (i for i in get_instructions(code_object) if i.opname != "EXTENDED_ARG")\n        except IndexError:\n            pass'
            )
            
            if content != patched_content:
                # Backup original
                backup_path = hook_path + '.backup'
                os.rename(hook_path, backup_path)
                print(f"Created backup: {backup_path}")
                
                # Write patched version
                with open(hook_path, 'w', encoding='utf-8') as f:
                    f.write(patched_content)
                print("✅ PyInstaller patched successfully!")
                return True
    
    print("❌ Could not find PyInstaller installation")
    return False

if __name__ == "__main__":
    patch_pyinstaller()